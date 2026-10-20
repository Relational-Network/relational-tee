// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The analysis log: one sealed, create-only record per analysis request,
//! `audit/analyses/{pool_pda}/{date}/{event_id}.json`, and two per export:
//! one when it's asked for, before any work, and one when it ends, which
//! for a file is stored before any of it is sent. The operator events
//! leave the TEE through the host's logs, so they carry no filter values;
//! this record holds what was asked, of which rows, and what went back.
//!
//! The worker names each record with an event ID of its own: a caller
//! chooses its request ID, so a name taken from that could be reused to
//! keep a later request out of the log.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{id, Storage, StoreError};
use crate::analysis::export::Format;
use crate::store::Created;

/// One analysis request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AnalysisRecord {
    /// The worker's ID for this record, new for every request. Records
    /// from before it existed have none.
    #[serde(default)]
    pub event_id: String,
    /// The request's correlation ID: the caller's `X-Request-Id` if it sent
    /// a UUID, otherwise one the worker chose. Requests may share it.
    pub request_id: String,
    pub at: DateTime<Utc>,
    /// The caller's `user_id`.
    pub user_id: String,
    /// The grant the caller ran it through; none for an admin, who needs none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// The chain reading the grant was checked against: its slot, and when
    /// the worker read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_slot: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_verified_at: Option<DateTime<Utc>>,
    pub pool_pda: String,
    pub analysis_id: String,
    pub definition_sha256: String,
    /// `open`, `query`, `options`, `search` or `export`.
    pub action: String,
    /// What was asked: a query's filters, and the sort and page it ran
    /// with; a search's filter, prefix and limit; an export's format,
    /// filters and sort, and the sort it ran with.
    #[schema(value_type = Object)]
    pub request: Value,
    /// The rows a query returned or an export holds, or the values an
    /// options or search request returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returned: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_matched: Option<u64>,
    /// `success`, or the error's code; for an export, `requested` before
    /// it runs, and `cancelled` for one whose client went away.
    pub outcome: String,
    /// An export's two records share it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<ExportEvent>,
}

/// One of an export's two records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExportEvent {
    /// Both records' ID, also returned with the file in `X-Export-Id`.
    pub export_id: String,
    /// `requested`, written before any work, or `finished`.
    pub stage: String,
    /// The format asked for, if the request named one the worker makes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<Format>,
    /// The pool's name when it was asked for.
    pub pool_name: String,
    /// When it was asked for; both records are filed under its date.
    pub requested_at: DateTime<Utc>,
    /// Once finished: `success` (the file was made whole and approved to
    /// be sent), `refused` (a 4xx), `failed` (a 5xx), `timeout` or
    /// `cancelled` (its client went away first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// The file's size, once made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// How long it took from being asked for, once finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Analysis log storage.
pub struct AnalysisLog<'a> {
    s: &'a Storage,
}

fn dir(pool_pda: &str, date: &str) -> String {
    format!("audit/analyses/{pool_pda}/{date}/")
}

impl<'a> AnalysisLog<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// Store `record` under its event ID, on the day of its `at`, or for an
    /// export's, the day it was asked for, so that its two records are
    /// filed together. Storing it again is harmless, but another record
    /// under that ID is an error, never a success.
    pub async fn record(&self, record: &AnalysisRecord) -> Result<(), StoreError> {
        let (Some(pool), Some(event)) = (id(&record.pool_pda), id(&record.event_id)) else {
            return Err(StoreError::Invalid(
                "an analysis record needs a pool and event ID that can name it".into(),
            ));
        };
        let day = record.export.as_ref().map_or(record.at, |e| e.requested_at);
        let date = day.format("%Y-%m-%d").to_string();
        let path = format!("{}{event}.json", dir(pool, &date));
        let plain = serde_json::to_vec(record)
            .map_err(|e| StoreError::Invalid(format!("serializing an analysis record: {e}")))?;
        let state = self.s.state();
        if let Created::AlreadyExists = state.create_uncached(&path, &plain).await? {
            let stored = state.read_uncached(&path).await?;
            if stored.as_deref().map(Vec::as_slice) != Some(plain.as_slice()) {
                return Err(StoreError::Integrity(format!(
                    "{path} already holds another analysis record"
                )));
            }
        }
        Ok(())
    }

    /// The records of `pool_pda`'s requests on `date` (`YYYY-MM-DD`, UTC),
    /// oldest first.
    pub async fn on(&self, pool_pda: &str, date: &str) -> Result<Vec<AnalysisRecord>, StoreError> {
        let (Some(pool), Some(date)) = (id(pool_pda), id(date)) else {
            return Ok(Vec::new());
        };
        let mut records: Vec<AnalysisRecord> = self
            .s
            .state()
            .list_json(&dir(pool, date), |p| p.ends_with(".json"))
            .await?;
        records.sort_by(|a, b| (a.at, &a.event_id).cmp(&(b.at, &b.event_id)));
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::files_storage;

    #[tokio::test]
    async fn each_event_is_recorded_once_under_its_pool_and_day() {
        let storage = files_storage();
        let record = AnalysisRecord {
            event_id: "9b2c1f4e-0d3a-4c5b-8e6f-7a8b9c0d1e2f".into(),
            request_id: "0f8fad5b-d9cb-469f-a165-70867728950e".into(),
            at: "2026-10-05T09:30:00Z".parse().unwrap(),
            user_id: "u-1".into(),
            grant_id: Some("g-1".into()),
            chain_slot: Some(1),
            chain_verified_at: Some("2026-10-05T09:29:00Z".parse().unwrap()),
            pool_pda: "P1".into(),
            analysis_id: "awards-report-v1".into(),
            definition_sha256: "ab".repeat(32),
            action: "query".into(),
            request: serde_json::json!({ "filters": {} }),
            returned: Some(3),
            total_matched: Some(3),
            outcome: "success".into(),
            export: None,
        };
        let log = storage.analysis_log();
        log.record(&record).await.unwrap();
        // The same record again, as a retried write would store it.
        log.record(&record).await.unwrap();
        // Another record under the same event ID is refused, never
        // counted as stored.
        let mut altered = record.clone();
        altered.returned = Some(99);
        assert!(matches!(
            log.record(&altered).await,
            Err(StoreError::Integrity(_))
        ));
        // Another event with the same request ID is a record of its own.
        let mut second = record.clone();
        second.event_id = "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9".into();
        second.returned = Some(1);
        log.record(&second).await.unwrap();
        let stored = log.on("P1", "2026-10-05").await.unwrap();
        assert_eq!(stored, [second.clone(), record.clone()]);
        assert!(log.on("P1", "2026-10-06").await.unwrap().is_empty());

        let mut stray = record.clone();
        stray.pool_pda = "../wallets".into();
        assert!(log.record(&stray).await.is_err());
        let mut unnamed = record;
        unnamed.event_id = String::new();
        assert!(log.record(&unnamed).await.is_err());
    }

    #[tokio::test]
    async fn an_exports_two_records_are_filed_on_the_day_it_was_asked_for() {
        let storage = files_storage();
        let log = storage.analysis_log();
        let requested_at = "2026-10-05T23:59:59Z".parse().unwrap();
        let event = ExportEvent {
            export_id: "5d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
            stage: "requested".into(),
            format: Some(Format::Xlsx),
            pool_name: "Pool A".into(),
            requested_at,
            result: None,
            bytes: None,
            duration_ms: None,
        };
        let requested = AnalysisRecord {
            event_id: "9b2c1f4e-0d3a-4c5b-8e6f-7a8b9c0d1e2f".into(),
            request_id: "0f8fad5b-d9cb-469f-a165-70867728950e".into(),
            at: requested_at,
            user_id: "u-1".into(),
            grant_id: None,
            chain_slot: None,
            chain_verified_at: None,
            pool_pda: "P1".into(),
            analysis_id: "awards-report-v1".into(),
            definition_sha256: "ab".repeat(32),
            action: "export".into(),
            request: serde_json::json!({ "format": "xlsx" }),
            returned: None,
            total_matched: None,
            outcome: "requested".into(),
            export: Some(event.clone()),
        };
        let finished = AnalysisRecord {
            event_id: "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9".into(),
            at: "2026-10-06T00:00:02Z".parse().unwrap(),
            returned: Some(7),
            total_matched: Some(7),
            outcome: "success".into(),
            export: Some(ExportEvent {
                stage: "finished".into(),
                result: Some("success".into()),
                bytes: Some(4096),
                duration_ms: Some(3000),
                ..event
            }),
            ..requested.clone()
        };
        log.record(&requested).await.unwrap();
        log.record(&finished).await.unwrap();
        assert_eq!(
            log.on("P1", "2026-10-05").await.unwrap(),
            [requested, finished]
        );
        assert!(log.on("P1", "2026-10-06").await.unwrap().is_empty());

        // A record from before exports reads as one without an export.
        let older: AnalysisRecord = serde_json::from_value(serde_json::json!({
            "request_id": "r", "at": "2026-10-05T09:30:00Z", "user_id": "u-1",
            "pool_pda": "P1", "analysis_id": "awards-report-v1",
            "definition_sha256": "ab", "action": "query", "request": {},
            "outcome": "success",
        }))
        .unwrap();
        assert!(older.export.is_none());
        assert!(serde_json::to_value(&older)
            .unwrap()
            .get("export")
            .is_none());
    }
}
