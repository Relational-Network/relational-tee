// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Health, readiness and drain.
//!
//! - `GET /health/live`: 200 while the process runs; no dependencies.
//! - `GET /health/ready`: 200 only when the worker holds its keys, has a
//!   valid certificate (or serves plain HTTP in a dev build), its storage
//!   canary succeeded within the last 60 seconds, and it isn't draining. It
//!   reads cached state only, so probes are cheap. It never depends on
//!   Solana RPC or the token-signing key cache, so their outages can't pull
//!   every worker out of rotation.
//! - `GET /health`: details for operators, without secrets.
//!
//! On SIGTERM the worker drains: readiness fails at once, the worker keeps
//! serving for two probe intervals so the load balancer notices, then stops
//! accepting connections and gives in-flight requests up to 40 seconds.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::time::Instant;
use tracing::{info, warn};
use utoipa::ToSchema;

use crate::blockchain::SolanaClient;
use crate::state::AppState;
use crate::storage::Storage;
use crate::tee::WorkerKeys;

/// How often the storage canary runs.
pub const CANARY_INTERVAL: Duration = Duration::from_secs(20);
/// Readiness needs a canary success at most this old.
pub const CANARY_MAX_AGE: Duration = Duration::from_secs(60);
/// How often `/health`'s Solana RPC status is refreshed.
pub const RPC_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// After SIGTERM, keep serving this long (two load balancer probe
/// intervals) before refusing new connections.
pub const DRAIN_PROBE_WAIT: Duration = Duration::from_secs(10);
/// Then give in-flight requests this long to finish.
pub const DRAIN_GRACE: Duration = Duration::from_secs(40);

/// The certificate the worker serves.
#[derive(Debug, Clone)]
pub enum Certificate {
    /// A PEM certificate chain read at startup.
    File { not_after: Option<DateTime<Utc>> },
    /// No certificate: plain HTTP. Dev builds only.
    #[cfg(feature = "dev")]
    PlainHttp,
}

#[derive(Default)]
struct Canary {
    last_ok: Option<Instant>,
    last_error: Option<String>,
}

struct Rpc {
    status: String,
    checked_at: Instant,
}

/// The state readiness and `/health` report, kept current in the
/// background.
pub struct Health {
    started: Instant,
    keys_held: Vec<String>,
    certificate: Certificate,
    canary: Mutex<Canary>,
    rpc: Mutex<Option<Rpc>>,
    draining: AtomicBool,
}

impl Health {
    pub fn new(keys: &WorkerKeys, certificate: Certificate) -> Self {
        Self {
            started: Instant::now(),
            keys_held: keys.names().map(|k| k.as_str().to_string()).collect(),
            certificate,
            canary: Mutex::new(Canary::default()),
            rpc: Mutex::new(None),
            draining: AtomicBool::new(false),
        }
    }

    /// Fail readiness from now on.
    pub fn start_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    fn draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    fn keys_ok(&self) -> bool {
        self.keys_held.len() == crate::tee::KeyName::ALL.len()
    }

    fn certificate_ok(&self) -> bool {
        match &self.certificate {
            Certificate::File { not_after } => not_after.is_none_or(|t| t > Utc::now()),
            #[cfg(feature = "dev")]
            Certificate::PlainHttp => true,
        }
    }

    fn canary_age(&self) -> Option<Duration> {
        self.canary.lock().ok()?.last_ok.map(|at| at.elapsed())
    }

    fn canary_ok(&self) -> bool {
        self.canary_age().is_some_and(|age| age <= CANARY_MAX_AGE)
    }

    pub(crate) fn record_canary(&self, result: Result<(), String>) {
        if let Ok(mut canary) = self.canary.lock() {
            match result {
                Ok(()) => {
                    canary.last_ok = Some(Instant::now());
                    canary.last_error = None;
                }
                Err(e) => canary.last_error = Some(e),
            }
        }
    }

    fn readiness(&self) -> ReadinessResponse {
        let (keys, certificate, storage_canary, draining) = (
            self.keys_ok(),
            self.certificate_ok(),
            self.canary_ok(),
            self.draining(),
        );
        let ready = keys && certificate && storage_canary && !draining;
        ReadinessResponse {
            status: if ready { "ready" } else { "not_ready" }.to_string(),
            keys,
            certificate,
            storage_canary,
            draining,
        }
    }

    /// Run the storage canary now and then every [`CANARY_INTERVAL`].
    pub fn spawn_canary(self: &Arc<Self>, storage: Arc<Storage>) {
        let health = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let result = storage.canary().await.map_err(|e| e.to_string());
                if let Err(e) = &result {
                    warn!(error = %e, "Storage canary failed");
                }
                health.record_canary(result);
                tokio::time::sleep(CANARY_INTERVAL).await;
            }
        });
    }

    /// Check Solana RPC every [`RPC_CHECK_INTERVAL`], for `/health` only.
    pub fn spawn_rpc_check(self: &Arc<Self>, solana: Arc<SolanaClient>) {
        let health = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let status = match solana.rpc().get_health().await {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("error: {e}"),
                };
                if let Ok(mut rpc) = health.rpc.lock() {
                    *rpc = Some(Rpc {
                        status,
                        checked_at: Instant::now(),
                    });
                }
                tokio::time::sleep(RPC_CHECK_INTERVAL).await;
            }
        });
    }
}

/// Liveness: the process is running.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
}

/// Readiness, computed from cached state.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReadinessResponse {
    /// `ready` or `not_ready`.
    pub status: String,
    /// All four keys are held.
    pub keys: bool,
    /// A valid certificate is loaded (always true for plain HTTP in dev builds).
    pub certificate: bool,
    /// The storage canary succeeded within the last 60 seconds.
    pub storage_canary: bool,
    /// The worker is shutting down.
    pub draining: bool,
}

/// The served certificate.
#[derive(Debug, Serialize, ToSchema)]
pub struct CertificateDetails {
    /// `file`, or `none` for plain HTTP in dev builds.
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// The storage canary: a read and a conditional write of this worker's blob.
#[derive(Debug, Serialize, ToSchema)]
pub struct CanaryDetails {
    pub ok: bool,
    /// Seconds since the last success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<u64>,
    /// The last failure, if the last run failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Solana RPC, as last checked.
#[derive(Debug, Serialize, ToSchema)]
pub struct RpcDetails {
    /// `ok`, `error: …`, or `unknown` before the first check.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_age_seconds: Option<u64>,
}

/// Details for operators. No secrets.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthDetails {
    /// `ready`, `not_ready` or `draining`.
    pub status: String,
    pub version: String,
    pub worker_id: String,
    pub uptime_seconds: u64,
    pub keys_held: Vec<String>,
    pub certificate: CertificateDetails,
    pub storage_canary: CanaryDetails,
    /// Seconds since the token-signing keys were fetched, if they have been.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_cache_age_seconds: Option<u64>,
    pub solana_rpc: RpcDetails,
    /// The SHA-256 of the running CCE policy, from the attestation token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_expires_at: Option<String>,
}

/// Operator details.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    summary = "Health details",
    description = "Details for operators: keys held, certificate expiry, storage canary age, key cache age, Solana RPC status, version and host data. Always 200; use /health/ready for routing.",
    responses(
        (status = 200, description = "Details", body = HealthDetails),
    )
)]
pub async fn health(State(state): State<AppState>) -> Json<HealthDetails> {
    let h = &state.health;
    let readiness = h.readiness();
    let status = if readiness.draining {
        "draining"
    } else {
        &readiness.status
    };
    let (canary_age, canary_error) = h
        .canary
        .lock()
        .map(|c| {
            (
                c.last_ok.map(|at| at.elapsed().as_secs()),
                c.last_error.clone(),
            )
        })
        .unwrap_or_default();
    let rpc = h
        .rpc
        .lock()
        .ok()
        .and_then(|rpc| {
            rpc.as_ref().map(|r| RpcDetails {
                status: r.status.clone(),
                checked_age_seconds: Some(r.checked_at.elapsed().as_secs()),
            })
        })
        .unwrap_or(RpcDetails {
            status: "unknown".into(),
            checked_age_seconds: None,
        });
    let jwks_cache_age_seconds = state.auth.keys_age().await.map(|age| age.as_secs());
    let token = state.attestation.token();
    let certificate = match &h.certificate {
        Certificate::File { not_after } => CertificateDetails {
            source: "file".into(),
            not_after: not_after.map(|t| t.to_rfc3339()),
        },
        #[cfg(feature = "dev")]
        Certificate::PlainHttp => CertificateDetails {
            source: "none".into(),
            not_after: None,
        },
    };

    Json(HealthDetails {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        worker_id: state.storage.worker_id().to_string(),
        uptime_seconds: h.started.elapsed().as_secs(),
        keys_held: h.keys_held.clone(),
        certificate,
        storage_canary: CanaryDetails {
            ok: readiness.storage_canary,
            age_seconds: canary_age,
            error: canary_error,
        },
        jwks_cache_age_seconds,
        solana_rpc: rpc,
        host_data: token.as_ref().and_then(|t| t.host_data.clone()),
        attestation_expires_at: token
            .and_then(|t| DateTime::from_timestamp(t.expires_at, 0))
            .map(|t| t.to_rfc3339()),
    })
}

/// Liveness probe handler.
///
/// Always returns 200 if the process is running.
#[utoipa::path(
    get,
    path = "/health/live",
    tag = "Health",
    summary = "Liveness probe",
    description = "Always returns 200 while the service is running. It checks no dependencies.",
    responses(
        (status = 200, description = "Service is alive", body = HealthResponse)
    )
)]
pub async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Readiness probe handler.
#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    summary = "Readiness probe",
    description = "200 only when the worker holds its keys, has a valid certificate, its storage canary succeeded within 60 seconds, and it isn't draining. Computed from cached state; independent of Solana RPC.",
    responses(
        (status = 200, description = "Ready", body = ReadinessResponse),
        (status = 503, description = "Not ready", body = ReadinessResponse)
    )
)]
pub async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let response = state.health.readiness();
    let status = if response.status == "ready" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(response))
}

/// Drain on the first shutdown signal, then shut down. SIGTERM waits
/// [`DRAIN_PROBE_WAIT`] before refusing new connections; an interactive
/// Ctrl-C doesn't, and a second Ctrl-C exits at once.
pub fn spawn_drain<A>(health: Arc<Health>, handle: axum_server::Handle<A>)
where
    A: axum_server::Address + Send + 'static,
{
    tokio::spawn(async move {
        let terminated = shutdown_signal().await;
        health.start_draining();
        if terminated {
            info!(
                wait_secs = DRAIN_PROBE_WAIT.as_secs(),
                "SIGTERM: draining, readiness now fails"
            );
            tokio::time::sleep(DRAIN_PROBE_WAIT).await;
        } else {
            info!("Interrupted: draining");
        }
        info!(
            grace_secs = DRAIN_GRACE.as_secs(),
            "No longer accepting connections; finishing in-flight requests"
        );
        handle.graceful_shutdown(Some(DRAIN_GRACE));
        if tokio::signal::ctrl_c().await.is_ok() {
            warn!("Interrupted again: exiting now");
            std::process::exit(130);
        }
    });
}

/// Wait for SIGINT (Ctrl-C) or SIGTERM. Returns whether it was SIGTERM.
async fn shutdown_signal() -> bool {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => false,
        _ = terminate => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(certificate: Certificate) -> Health {
        Health::new(&crate::tee::tests::test_keys(), certificate)
    }

    #[tokio::test(start_paused = true)]
    async fn ready_only_with_a_fresh_canary_a_valid_certificate_and_no_drain() {
        let valid = Certificate::File {
            not_after: Some(Utc::now() + chrono::Duration::days(30)),
        };
        let h = health(valid);
        assert_eq!(h.readiness().status, "not_ready", "no canary yet");

        h.record_canary(Ok(()));
        let r = h.readiness();
        assert!(r.keys && r.certificate && r.storage_canary && !r.draining);
        assert_eq!(r.status, "ready");

        // A failure doesn't undo a recent success, but age does.
        h.record_canary(Err("timeout".into()));
        assert_eq!(h.readiness().status, "ready");
        tokio::time::advance(CANARY_MAX_AGE + Duration::from_secs(1)).await;
        assert_eq!(h.readiness().status, "not_ready");

        h.record_canary(Ok(()));
        h.start_draining();
        let r = h.readiness();
        assert!(r.draining);
        assert_eq!(r.status, "not_ready");
    }

    #[test]
    fn an_expired_certificate_is_not_ready() {
        let h = health(Certificate::File {
            not_after: Some(Utc::now() - chrono::Duration::minutes(1)),
        });
        h.record_canary(Ok(()));
        assert!(!h.readiness().certificate);
        assert_eq!(h.readiness().status, "not_ready");
    }
}
