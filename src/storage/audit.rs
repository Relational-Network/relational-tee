// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The audit log.
//!
//! Each event carries an HMAC-SHA256 tag over its canonical JSON (the event
//! with `hmac` unset, fields in declaration order), under a key derived from
//! `storage-root`, so every worker can verify every event.
//!
//! - **Write:** append the encrypted line to this worker's hourly append blob
//!   `audit/{yyyy}/{mm}/{dd}/{hh}/{worker_id}.jsonl`, then insert the index
//!   rows in Table `audit`: `{pool_pda}` (or `global`) and `date:{yyyy-mm-dd}`,
//!   both with row key `{inverted_ts}:{event_id}`. An existing row means a
//!   duplicate, which is ignored.
//! - **Read:** queries use the index, and every returned event is verified.
//!   An event that fails comes back with `hmac_valid: false` and raises an
//!   alert; it is never silently dropped.

use bytes::Bytes;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::store::{
    Container, Continuation, Entity, Filter, InsertOutcome, Page, Prop, RkRange, StoreError, Table,
};
use super::{inverted_millis, Storage};

const PAYLOAD_VERSION: u32 = 1;
const GLOBAL_PK: &str = "global";

/// Categories of auditable events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    WalletCreated,
    WalletDeleted,
    WalletAccessed,
    TransactionSigned,
    TransactionBroadcast,
    PermissionDenied,
    AdminAccess,
    // ── Credential issuance events ───────────────────────────────
    PoolCreated,
    PoolClosed,
    DatasetInitialized,
    CredentialIssued,
    CredentialIssuanceFailed,
    CredentialRevoked,
    RoleAssigned,
    SchemaUploaded,
    // ── DRT grant lifecycle (new contract) ───────────────────────
    RightGranted,
    RightRevoked,
    // ── DRT execution (analyst runs a script in the enclave) ─────
    DrtExecuted,
}

impl AuditEventType {
    /// The snake_case name, as serialized.
    pub fn as_str(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    }
}

/// A single audit event.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub success: bool,
    /// HMAC-SHA256 integrity tag over the canonical JSON of this event
    /// (computed with `hmac` field absent). `None` only transiently before
    /// the tag is attached during write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
    /// The `X-Request-Id` of the request that caused the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Pool PDA for pool-scoped events (previously buried in `details` JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_pda: Option<String>,
}

impl AuditEvent {
    /// Start building an event with the given type (defaults to `success: true`).
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            user_id: None,
            resource_type: None,
            resource_id: None,
            details: None,
            success: true,
            hmac: None,
            correlation_id: None,
            pool_pda: None,
        }
    }

    /// Attach user identity.
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Attach resource type and id.
    pub fn with_resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Attach structured details (forensic metadata for audit queries).
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Attach a pool PDA for pool-scoped events.
    pub fn with_pool_pda(mut self, pda: impl Into<String>) -> Self {
        self.pool_pda = Some(pda.into());
        self
    }

    /// The JSON the tag covers: the event with `hmac` unset.
    fn canonical(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.hmac = None;
        serde_json::to_vec(&unsigned).expect("audit events serialize")
    }
}

/// An event as read back, with the result of its integrity check.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AuditEventView {
    #[serde(flatten)]
    pub event: AuditEvent,
    /// `false` if the event's tag or its row failed verification.
    pub hmac_valid: bool,
}

/// Filters for a pool's events. Empty fields match everything.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Any of these event types (snake_case).
    pub event_types: Vec<String>,
    /// Events by this user.
    pub actor: Option<String>,
    pub success: Option<bool>,
    /// Inclusive time bounds.
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

/// The audit log.
pub struct AuditLog<'a> {
    s: &'a Storage,
}

fn blob_path(at: DateTime<Utc>, worker_id: &str) -> String {
    format!("{}/{worker_id}.jsonl", at.format("%Y/%m/%d/%H"))
}

fn date_pk(date: NaiveDate) -> String {
    format!("date:{}", date.format("%Y-%m-%d"))
}

impl<'a> AuditLog<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    fn actor_hash(&self, user_id: &str) -> String {
        self.s.keys().index_hash(user_id)
    }

    /// Record an event. Failures are logged and never returned: auditing
    /// must not block the request that caused the event.
    pub async fn log(&self, event: AuditEvent) {
        let event_id = event.event_id.clone();
        if let Err(e) = self.try_log(event).await {
            error!(event_id = %event_id, error = %e, "Audit event not stored");
        }
    }

    async fn try_log(&self, mut event: AuditEvent) -> Result<(), StoreError> {
        if event.correlation_id.is_none() {
            event.correlation_id = crate::request_id::current();
        }
        event.hmac = Some(self.s.keys().audit_tag(&event.canonical()));
        let signed = zeroize::Zeroizing::new(
            serde_json::to_vec(&event).map_err(|e| StoreError::Invalid(e.to_string()))?,
        );

        let path = blob_path(event.timestamp, self.s.worker_id());
        let line = self
            .s
            .keys()
            .seal_log_line(Container::Audit, &path, &event.event_id, &signed);
        self.s
            .objects()
            .append(Container::Audit, &path, Bytes::from(line))
            .await?;

        let rk = format!("{}:{}", inverted_millis(event.timestamp), event.event_id);
        let partition = event.pool_pda.clone().unwrap_or_else(|| GLOBAL_PK.into());
        for pk in [partition, date_pk(event.timestamp.date_naive())] {
            let mut row = self
                .s
                .sealed_row(Table::Audit, &pk, &rk, PAYLOAD_VERSION, &event)?
                .with("event_type", Prop::Str(event.event_type.as_str()))
                .with("success", Prop::Bool(event.success));
            if let Some(user) = &event.user_id {
                row = row.with("actor_h", Prop::Str(self.actor_hash(user)));
            }
            if self.s.index().insert(Table::Audit, row).await? == InsertOutcome::Conflict {
                warn!(event_id = %event.event_id, pk = %pk, "Duplicate audit index row ignored");
            }
        }
        Ok(())
    }

    /// One page of a pool's events, newest first.
    pub async fn pool_events(
        &self,
        pool_pda: &str,
        filter: &AuditFilter,
        limit: usize,
        page: Option<Continuation>,
    ) -> Result<Page<AuditEventView>, StoreError> {
        let mut clauses = Vec::new();
        if !filter.event_types.is_empty() {
            clauses.push(Filter::Or(
                filter
                    .event_types
                    .iter()
                    .map(|t| Filter::eq("event_type", Prop::Str(t.clone())))
                    .collect(),
            ));
        }
        if let Some(actor) = &filter.actor {
            clauses.push(Filter::eq("actor_h", Prop::Str(self.actor_hash(actor))));
        }
        if let Some(success) = filter.success {
            clauses.push(Filter::eq("success", Prop::Bool(success)));
        }
        // Row keys sort newest first: `to` bounds the start, `from` the end.
        let range = RkRange::between(
            filter.to.map(inverted_millis),
            filter
                .from
                .map(|from| format!("{};", inverted_millis(from))),
        );
        let filter = (!clauses.is_empty()).then_some(Filter::And(clauses));
        self.events(pool_pda, range, filter, limit, page).await
    }

    /// One page of a day's events across all pools, newest first.
    pub async fn day_events(
        &self,
        date: NaiveDate,
        limit: usize,
        page: Option<Continuation>,
    ) -> Result<Page<AuditEventView>, StoreError> {
        self.events(&date_pk(date), RkRange::all(), None, limit, page)
            .await
    }

    async fn events(
        &self,
        pk: &str,
        range: RkRange,
        filter: Option<Filter>,
        limit: usize,
        page: Option<Continuation>,
    ) -> Result<Page<AuditEventView>, StoreError> {
        let rows = self
            .s
            .query_rows(Table::Audit, pk, range, filter, limit, page)
            .await?;
        Ok(Page {
            items: rows
                .items
                .iter()
                .filter_map(|row| self.verify(row))
                .collect(),
            next: rows.next,
        })
    }

    /// Decrypt a row and check the event's tag, and that the row's keys and
    /// plaintext properties agree with the event.
    fn verify(&self, row: &Entity) -> Option<AuditEventView> {
        match self
            .s
            .open_row::<AuditEvent>(Table::Audit, PAYLOAD_VERSION, row)
        {
            Ok(event) => {
                let tag_valid = event
                    .hmac
                    .as_deref()
                    .is_some_and(|tag| self.s.keys().audit_tag_valid(&event.canonical(), tag));
                let row_matches = row.rk.ends_with(&format!(":{}", event.event_id))
                    && row.str("event_type") == Some(event.event_type.as_str().as_str())
                    && row.bool("success") == Some(event.success)
                    && row.str("actor_h").map(String::from)
                        == event.user_id.as_deref().map(|u| self.actor_hash(u));
                let hmac_valid = tag_valid && row_matches;
                if !hmac_valid {
                    error!(alert = "audit_integrity", event_id = %event.event_id, pk = %row.pk,
                        tag_valid, row_matches, "Audit event failed its integrity check");
                }
                Some(AuditEventView { event, hmac_valid })
            }
            Err(e) => {
                error!(alert = "audit_integrity", pk = %row.pk, rk = %row.rk, error = %e,
                    "Audit row failed its integrity check");
                self.stub(row, &e)
            }
        }
    }

    /// What the plaintext row still tells us about an event whose payload
    /// doesn't decrypt.
    fn stub(&self, row: &Entity, e: &StoreError) -> Option<AuditEventView> {
        let (inverted, event_id) = row.rk.split_once(':')?;
        let millis = u64::MAX - u64::from_str_radix(inverted, 16).ok()?;
        let event_type = serde_json::from_value(serde_json::Value::String(
            row.str("event_type")?.to_string(),
        ))
        .ok()?;
        let mut event = AuditEvent::new(event_type);
        event.event_id = event_id.to_string();
        event.timestamp = DateTime::from_timestamp_millis(millis as i64)?;
        event.success = row.bool("success").unwrap_or(false);
        event.details = Some(serde_json::json!({ "integrity_error": e.to_string() }));
        Some(AuditEventView {
            event,
            hmac_valid: false,
        })
    }
}

/// Record an audit event from a handler. Never fails the request.
///
/// ```rust,ignore
/// audit_log!(state, AuditEventType::WalletCreated, &user_id, "wallet", &wallet_id);
/// ```
#[macro_export]
macro_rules! audit_log {
    ($state:expr, $event_type:expr, $user_id:expr, $resource_type:expr, $resource_id:expr) => {{
        $state
            .storage
            .audit()
            .log(
                $crate::storage::audit::AuditEvent::new($event_type)
                    .with_user($user_id)
                    .with_resource($resource_type, $resource_id),
            )
            .await;
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::MemoryStore;
    use crate::storage::StorageKeys;
    use crate::tee::tests::fixed_key;
    use std::sync::Arc;

    fn storage() -> (Storage, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::new());
        let s = Storage::new(
            store.clone(),
            store.clone(),
            StorageKeys::derive(&fixed_key(1)),
            "worker-a".into(),
        );
        (s, store)
    }

    fn pool_event(kind: AuditEventType, user: &str, at_millis: i64) -> AuditEvent {
        let mut event = AuditEvent::new(kind)
            .with_user(user)
            .with_resource("drt_pool", "Pool1")
            .with_pool_pda("Pool1");
        event.timestamp = DateTime::from_timestamp_millis(at_millis).unwrap();
        event
    }

    #[tokio::test]
    async fn events_are_logged_encrypted_indexed_and_verified() {
        let (s, store) = storage();
        let audit = s.audit();
        audit
            .log(pool_event(AuditEventType::PoolCreated, "alice", 1_000))
            .await;
        audit
            .log(pool_event(AuditEventType::CredentialIssued, "bob", 2_000))
            .await;
        audit
            .log(AuditEvent::new(AuditEventType::AdminAccess).with_user("alice"))
            .await;

        let all = audit
            .pool_events("Pool1", &AuditFilter::default(), 10, None)
            .await
            .unwrap();
        let kinds: Vec<_> = all
            .items
            .iter()
            .map(|v| v.event.event_type.clone())
            .collect();
        assert_eq!(
            kinds,
            [
                AuditEventType::CredentialIssued,
                AuditEventType::PoolCreated
            ]
        );
        assert!(all.items.iter().all(|v| v.hmac_valid));

        let by_bob = AuditFilter {
            actor: Some("bob".into()),
            ..Default::default()
        };
        let got = audit.pool_events("Pool1", &by_bob, 10, None).await.unwrap();
        assert_eq!(got.items.len(), 1);
        let issued_only = AuditFilter {
            event_types: vec!["pool_created".into()],
            to: DateTime::from_timestamp_millis(1_500),
            ..Default::default()
        };
        let got = audit
            .pool_events("Pool1", &issued_only, 10, None)
            .await
            .unwrap();
        assert_eq!(got.items.len(), 1);

        let day = audit
            .day_events(NaiveDate::from_ymd_opt(1970, 1, 1).unwrap(), 10, None)
            .await
            .unwrap();
        assert_eq!(day.items.len(), 2);

        // The blob holds one encrypted line per event, which opens and verifies.
        let path = blob_path(DateTime::from_timestamp_millis(1_000).unwrap(), "worker-a");
        let blob = s
            .objects()
            .get(Container::Audit, &path)
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8(blob.body.to_vec()).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(!text.contains("alice"));
        for line in text.lines() {
            let (_, plain) = s
                .keys()
                .open_log_line(Container::Audit, &path, line)
                .unwrap();
            let event: AuditEvent = serde_json::from_slice(&plain).unwrap();
            assert!(s
                .keys()
                .audit_tag_valid(&event.canonical(), event.hmac.as_deref().unwrap()));
        }
        drop(store);
    }

    #[tokio::test]
    async fn tampered_rows_come_back_flagged_not_dropped() {
        let (s, store) = storage();
        let audit = s.audit();
        audit
            .log(pool_event(AuditEventType::PoolCreated, "alice", 1_000))
            .await;
        audit
            .log(pool_event(AuditEventType::CredentialIssued, "alice", 2_000))
            .await;
        let rows = s
            .query_all(Table::Audit, "Pool1", RkRange::all(), None)
            .await
            .unwrap();

        // Flip a plaintext filter property.
        store.tamper_row(Table::Audit, "Pool1", &rows[0].rk, |props| {
            props.insert("success".into(), Prop::Bool(false));
        });
        // Corrupt the other row's payload.
        store.tamper_row(Table::Audit, "Pool1", &rows[1].rk, |props| {
            if let Some(Prop::Bin(payload)) = props.get_mut("payload") {
                payload[20] ^= 1;
            }
        });

        let got = audit
            .pool_events("Pool1", &AuditFilter::default(), 10, None)
            .await
            .unwrap();
        assert_eq!(got.items.len(), 2);
        assert!(got.items.iter().all(|v| !v.hmac_valid));
        assert_eq!(got.items[1].event.event_type, AuditEventType::PoolCreated);
    }

    #[tokio::test]
    async fn a_tampered_log_line_fails_to_open() {
        let (s, store) = storage();
        s.audit()
            .log(pool_event(AuditEventType::PoolCreated, "alice", 1_000))
            .await;
        let path = blob_path(DateTime::from_timestamp_millis(1_000).unwrap(), "worker-a");
        store.tamper_blob(Container::Audit, &path, |bytes| {
            let i = bytes.len() - 10;
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        });
        let blob = s
            .objects()
            .get(Container::Audit, &path)
            .await
            .unwrap()
            .unwrap();
        let line = String::from_utf8(blob.body.to_vec()).unwrap();
        assert!(s
            .keys()
            .open_log_line(Container::Audit, &path, line.trim_end())
            .is_err());
    }
}
