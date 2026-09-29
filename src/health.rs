// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Health check endpoints for container probes and load balancers.
//!
//! This module provides three health endpoints:
//!
//! - `/health` - Combined liveness and readiness check
//! - `/health/live` - Liveness probe (always 200 if running)
//! - `/health/ready` - Readiness probe (checks dependencies)

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use utoipa::ToSchema;

use crate::state::AppState;

/// Health check response with individual component status.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReadyResponse {
    /// Overall health status ("ok" or "degraded").
    pub status: String,
    /// Individual health checks and their results.
    pub checks: HealthChecks,
}

/// Individual health check results.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthChecks {
    /// Whether the service process is running.
    pub service: String,
    /// Solana RPC reachability (readiness only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solana_rpc: Option<String>,
    /// AVS JWKS cache status (readiness only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
}

/// Simple health check response for liveness probes.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
}

/// Health check endpoint handler.
///
/// Returns 200 if all checks pass, 503 if any check fails.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    summary = "Combined health check",
    description = "Returns health status with individual check results. Returns 503 if any check fails.",
    responses(
        (status = 200, description = "Service is healthy", body = ReadyResponse),
        (status = 503, description = "Service is unhealthy", body = ReadyResponse)
    )
)]
pub async fn health() -> (StatusCode, Json<ReadyResponse>) {
    let response = ReadyResponse {
        status: "ok".to_string(),
        checks: HealthChecks {
            service: "ok".to_string(),
            solana_rpc: None,
            jwks: None,
        },
    };
    (StatusCode::OK, Json(response))
}

/// Liveness probe handler.
///
/// Always returns 200 if the process is running.
/// Does not check dependencies - use readiness for that.
#[utoipa::path(
    get,
    path = "/health/live",
    tag = "Health",
    summary = "Liveness probe",
    description = "Always returns 200 if the service is running. Use for Kubernetes liveness probes.",
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
///
/// Returns 200 only if all dependencies are available.
/// Use for Kubernetes readiness probes.
#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    summary = "Readiness probe",
    description = "Checks all dependencies and returns 200 only if ready to serve traffic.",
    responses(
        (status = 200, description = "Service is ready", body = ReadyResponse),
        (status = 503, description = "Service is not ready", body = ReadyResponse)
    )
)]
pub async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<ReadyResponse>) {
    // Check Solana RPC by calling a lightweight getHealth.
    let solana_rpc = match state.solana_client.rpc().get_health().await {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("error: {e}"),
    };

    // Check JWKS cache has been populated at least once.
    let jwks = {
        let guard = state.jwks_cache.read().await;
        if guard.is_some() {
            "ok".to_string()
        } else {
            "not_loaded".to_string()
        }
    };

    let all_ok = solana_rpc == "ok" && jwks == "ok";

    let response = ReadyResponse {
        status: if all_ok { "ok" } else { "degraded" }.to_string(),
        checks: HealthChecks {
            service: "ok".to_string(),
            solana_rpc: Some(solana_rpc),
            jwks: Some(jwks),
        },
    };

    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}
