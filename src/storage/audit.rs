// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Audit event logging (daily JSONL append) with HMAC integrity.
//!
//! Each day's events are written to `/data/audit/{YYYY-MM-DD}.jsonl`.
//! Events are **appended** (never overwritten) for tamper-evident logging.
//! An HMAC-SHA256 tag is computed over each event's canonical JSON so that
//! any post-hoc modification of the log file is detectable.

use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::AsyncWriteExt;
use tracing::warn;

use super::encrypted_fs::EncryptedStorage;

/// Categories of auditable events.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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
    // ── DRT marketplace events ───────────────────────────────────
    DrtPurchased,
    DrtRedeemed,
    SchemaUploaded,
    // ── DRT grant lifecycle (new contract) ───────────────────────
    RightGranted,
    RightRevoked,
    // ── DRT execution (analyst runs a script in the enclave) ─────
    DrtExecuted,
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
    /// Correlation ID linking related operations (e.g. redeem + issue).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Pool PDA for pool-scoped events (previously buried in `details` JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_pda: Option<String>,
}

type HmacSha256 = Hmac<Sha256>;

/// Stable 32-byte HMAC key, persisted at `/data/audit/.hmac-key`.
///
/// On first call the key is loaded from disk (or generated and saved if the
/// file does not yet exist).  The result is cached for the lifetime of the
/// process so the file is read at most once.
static AUDIT_HMAC_KEY: OnceLock<[u8; 32]> = OnceLock::new();

fn audit_hmac_key() -> [u8; 32] {
    *AUDIT_HMAC_KEY.get_or_init(|| {
        let key_path = std::path::Path::new(crate::config::DATA_DIR)
            .join("audit")
            .join(".hmac-key");

        // Try to read an existing key.
        if let Ok(bytes) = std::fs::read(&key_path) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return key;
            }
            warn!("Corrupt audit HMAC key file ({} bytes) — regenerating", bytes.len());
        }

        // Generate a fresh key and persist it.
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&key_path, key) {
            tracing::error!(error = %e, "Failed to persist audit HMAC key — events will not survive restart");
        }
        key
    })
}

/// Compute HMAC-SHA256 of a canonical JSON blob.
fn compute_hmac(json_bytes: &[u8]) -> String {
    let key = audit_hmac_key();
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(json_bytes);
    hex::encode(mac.finalize().into_bytes())
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
}

use super::tx_database::TxDatabase;

/// Writes [`AuditEvent`]s to daily JSONL files and optionally to redb.
pub struct AuditRepository<'a> {
    storage: &'a EncryptedStorage,
    tx_db: Option<&'a TxDatabase>,
}

impl<'a> AuditRepository<'a> {
    pub fn new(storage: &'a EncryptedStorage) -> Self {
        Self {
            storage,
            tx_db: None,
        }
    }

    /// Attach a `TxDatabase` reference for dual-write to redb audit tables.
    pub fn with_tx_db(mut self, tx_db: &'a TxDatabase) -> Self {
        self.tx_db = Some(tx_db);
        self
    }

    /// Append an event to today's audit log.
    ///
    /// The HMAC tag is computed over the canonical JSON (with the `hmac` field
    /// absent), then the full event including `hmac` is serialised and appended.
    ///
    /// Errors are logged but **not** propagated — audit logging must never
    /// block business logic.
    pub async fn log(&self, event: &AuditEvent) {
        let date = event.timestamp.format("%Y-%m-%d").to_string();
        let path = self.storage.paths().audit_events_file(&date);

        // Ensure audit directory exists.
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        // Compute the HMAC tag once over the canonical (hmac-less) JSON,
        // then write the **signed** event to both stores so the redb copy
        // also carries the tag — list_audit_by_resource returns whatever
        // bytes redb holds.
        let mut canonical = event.clone();
        canonical.hmac = None;
        let signed = match serde_json::to_string(&canonical) {
            Ok(canonical_json) => {
                let mut signed = event.clone();
                signed.hmac = Some(compute_hmac(canonical_json.as_bytes()));
                signed
            }
            Err(e) => {
                warn!(error = %e, "Failed to serialize audit event for HMAC");
                return;
            }
        };

        match serde_json::to_string(&signed) {
            Ok(mut line) => {
                line.push('\n');
                match tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .await
                {
                    Ok(mut f) => {
                        if let Err(e) = f.write_all(line.as_bytes()).await {
                            warn!(error = %e, path = %path.display(), "Failed to write audit event");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, path = %path.display(), "Failed to open audit log file");
                    }
                }
            }
            Err(e) => warn!(error = %e, "Failed to serialize signed audit event"),
        }

        // Dual-write: persist the signed event to redb audit tables.
        if let Some(tx_db) = self.tx_db {
            if let Err(e) = tx_db.log_audit_event(&signed) {
                warn!(error = %e, event_id = %event.event_id, "Failed to write audit event to redb");
            }
        }
    }

    /// Read only events with a valid HMAC for the given date.
    ///
    /// Events missing an HMAC or whose tag does not verify are excluded.
    #[allow(dead_code)] //TODO
    pub fn read_verified_events(&self, date: &str) -> Vec<AuditEvent> {
        let path = self.storage.paths().audit_events_file(date);
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        data.lines()
            .filter_map(|line| {
                let event: AuditEvent = serde_json::from_str(line).ok()?;
                let tag = event.hmac.as_ref()?;
                let mut canonical = event.clone();
                canonical.hmac = None;
                let canonical_json = serde_json::to_string(&canonical).ok()?;
                let expected = compute_hmac(canonical_json.as_bytes());
                if tag == &expected {
                    Some(event)
                } else {
                    warn!(
                        event_id = %event.event_id,
                        "Audit event HMAC mismatch — excluding"
                    );
                    None
                }
            })
            .collect()
    }
}

/// Convenience macro for fire-and-forget audit logging.
///
/// Must be called from inside an async context (handler). The `.await` is
/// non-blocking because it uses `tokio::fs` internally.
///
/// ```rust,ignore
/// audit_log!(storage, tx_db, AuditEventType::WalletCreated, "user_123", "wallet", "wallet_456");
/// ```
#[macro_export]
macro_rules! audit_log {
    ($storage:expr, $tx_db:expr, $event_type:expr, $user_id:expr, $resource_type:expr, $resource_id:expr) => {{
        let repo = $crate::storage::audit::AuditRepository::new($storage).with_tx_db($tx_db);
        repo.log(
            &$crate::storage::audit::AuditEvent::new($event_type)
                .with_user($user_id)
                .with_resource($resource_type, $resource_id),
        )
        .await;
    }};
}
