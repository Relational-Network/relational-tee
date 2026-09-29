// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential revocations: an append-only log, plus an index.
//!
//! - Blob `revocations/{pool_pda}/{yyyy}/{mm}.jsonl`: encrypted revocation
//!   events, each tagged with HMAC-SHA256 under the audit key. The log is
//!   authoritative: its container has a time-based WORM policy with
//!   protected appends, so a revocation can't be silently undone.
//! - Table `revocations`: `{pool_pda}` / `{credential_id}`, one row per
//!   revoked credential, for listing and counting.
//!
//! A revocation appends to the log first, then inserts the index row. A
//! crash between the two leaves a log line without an index row, which a
//! re-index from the log repairs; a retry appends a duplicate line, which
//! collapses on read.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::store::{
    Container, Continuation, InsertOutcome, Page, Prop, RkRange, StoreError, Table,
};
use super::Storage;

const PAYLOAD_VERSION: u32 = 1;

/// One revocation, as logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEvent {
    pub event_id: String,
    pub pool_pda: String,
    pub credential_id: String,
    pub revoked_by: String,
    pub revoked_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// HMAC-SHA256 over the canonical JSON with `hmac` unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

impl RevocationEvent {
    fn canonical(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.hmac = None;
        serde_json::to_vec(&unsigned).expect("revocation events serialize")
    }
}

/// The payload of an index row.
#[derive(Serialize, Deserialize)]
struct RevocationRow {
    revoked_by: String,
    revoked_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Where the authoritative log line is.
    event_id: String,
    log_path: String,
}

/// A revoked credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub credential_id: String,
    pub revoked_by: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: Option<String>,
}

/// Revocation storage.
pub struct Revocations<'a> {
    s: &'a Storage,
}

fn log_path(pool_pda: &str, at: DateTime<Utc>) -> String {
    format!("{pool_pda}/{}.jsonl", at.format("%Y/%m"))
}

impl<'a> Revocations<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// Revoke a credential. Returns `false` if it was already revoked.
    pub async fn revoke(
        &self,
        pool_pda: &str,
        credential_id: &str,
        revoked_by: &str,
        reason: Option<&str>,
    ) -> Result<bool, StoreError> {
        if self
            .s
            .index()
            .get(Table::Revocations, pool_pda, credential_id)
            .await?
            .is_some()
        {
            return Ok(false);
        }

        let mut event = RevocationEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            pool_pda: pool_pda.to_string(),
            credential_id: credential_id.to_string(),
            revoked_by: revoked_by.to_string(),
            revoked_at: Utc::now(),
            reason: reason.map(String::from),
            hmac: None,
        };
        event.hmac = Some(self.s.keys().audit_tag(&event.canonical()));
        let path = log_path(pool_pda, event.revoked_at);
        let signed = zeroize::Zeroizing::new(
            serde_json::to_vec(&event).map_err(|e| StoreError::Invalid(e.to_string()))?,
        );
        let line =
            self.s
                .keys()
                .seal_log_line(Container::Revocations, &path, &event.event_id, &signed);
        self.s
            .objects()
            .append(Container::Revocations, &path, Bytes::from(line))
            .await?;

        let row = RevocationRow {
            revoked_by: event.revoked_by.clone(),
            revoked_at: event.revoked_at,
            reason: event.reason.clone(),
            event_id: event.event_id.clone(),
            log_path: path,
        };
        let entity = self
            .s
            .sealed_row(
                Table::Revocations,
                pool_pda,
                credential_id,
                PAYLOAD_VERSION,
                &row,
            )?
            .with("revoked_at", Prop::Str(event.revoked_at.to_rfc3339()));
        // A concurrent revocation of the same credential won; its line and
        // ours collapse on read.
        Ok(self.s.index().insert(Table::Revocations, entity).await? != InsertOutcome::Conflict)
    }

    /// One page of the pool's revocations, in credential ID order.
    pub async fn list(
        &self,
        pool_pda: &str,
        limit: usize,
        page: Option<Continuation>,
    ) -> Result<Page<Revocation>, StoreError> {
        let rows = self
            .s
            .query_rows(
                Table::Revocations,
                pool_pda,
                RkRange::all(),
                None,
                limit,
                page,
            )
            .await?;
        let mut items = Vec::with_capacity(rows.items.len());
        for entity in &rows.items {
            let row: RevocationRow =
                self.s
                    .open_row(Table::Revocations, PAYLOAD_VERSION, entity)?;
            items.push(Revocation {
                credential_id: entity.rk.clone(),
                revoked_by: row.revoked_by,
                revoked_at: row.revoked_at,
                reason: row.reason,
            });
        }
        Ok(Page {
            items,
            next: rows.next,
        })
    }

    /// How many credentials of the pool are revoked.
    pub async fn count(&self, pool_pda: &str) -> Result<u64, StoreError> {
        Ok(self
            .s
            .query_all(Table::Revocations, pool_pda, RkRange::all(), None)
            .await?
            .len() as u64)
    }

    /// The log for one month, verified, with duplicate lines collapsed.
    #[cfg(test)]
    pub async fn read_log(
        &self,
        pool_pda: &str,
        month: DateTime<Utc>,
    ) -> Result<Vec<(RevocationEvent, bool)>, StoreError> {
        let path = log_path(pool_pda, month);
        let Some(blob) = self.s.objects().get(Container::Revocations, &path).await? else {
            return Ok(Vec::new());
        };
        let text = String::from_utf8_lossy(&blob.body).into_owned();
        let mut events: Vec<(RevocationEvent, bool)> = Vec::new();
        for line in text.lines() {
            let (_, plain) = self
                .s
                .keys()
                .open_log_line(Container::Revocations, &path, line)?;
            let event: RevocationEvent =
                serde_json::from_slice(&plain).map_err(|e| StoreError::Integrity(e.to_string()))?;
            let valid = event
                .hmac
                .as_deref()
                .is_some_and(|tag| self.s.keys().audit_tag_valid(&event.canonical(), tag));
            if !events.iter().any(|(e, _)| e.event_id == event.event_id) {
                events.push((event, valid));
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::tests::two_workers;

    #[tokio::test]
    async fn revocations_log_then_index_and_count_once() {
        let (a, b) = two_workers();
        assert!(a
            .revocations()
            .revoke("P1", "r1", "alice", Some("typo"))
            .await
            .unwrap());
        assert!(!b
            .revocations()
            .revoke("P1", "r1", "bob", None)
            .await
            .unwrap());
        assert!(b
            .revocations()
            .revoke("P1", "r2", "bob", None)
            .await
            .unwrap());
        assert_eq!(b.revocations().count("P1").await.unwrap(), 2);
        assert_eq!(b.revocations().count("P2").await.unwrap(), 0);

        let page = a.revocations().list("P1", 1, None).await.unwrap();
        assert_eq!(page.items[0].credential_id, "r1");
        assert_eq!(page.items[0].reason.as_deref(), Some("typo"));
        let rest = a.revocations().list("P1", 1, page.next).await.unwrap();
        assert_eq!(rest.items[0].credential_id, "r2");

        let log = a
            .revocations()
            .read_log("P1", chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|(_, valid)| *valid));
    }
}
