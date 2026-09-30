// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! HTTP request handlers for the enclave API.
//!
//! This module contains handlers for:
//! - Public key endpoint (for browser encryption)
//! - Admin endpoints (require admin role)
//! - Opening and validating the sealed CSV uploads of the pool endpoints

use axum::{
    extract::{Multipart, State},
    Json,
};
use serde::Serialize;
use tracing::{debug, info};
use utoipa::ToSchema;

use crate::auth::Caller;
use crate::crypto::{jwk_for_public_key, Jwk};
use crate::data_validation::{validate_csv_bytes, FieldSchema, ValidationMode, ValidationSummary};
use crate::error::ApiError;
use crate::idempotency::Idempotent;
use crate::seal::{self, SealedUpload};
use crate::state::AppState;
use crate::tee::{KeyName, ReleasedKey};

// ============================================================================
// Public Key Endpoint
// ============================================================================

/// Get the transport public key that uploads are sealed to.
///
/// Every worker holds the same transport key, released at startup, so an
/// upload sealed on one worker's answer opens on any worker.
#[utoipa::path(
    get,
    path = "/v1/attestation/public-key",
    tag = "Attestation",
    summary = "Get the transport public key",
    description = "Returns the current P-256 transport public key in JWK format for browser encryption.",
    responses(
        (status = 200, description = "Public key returned", body = Jwk)
    )
)]
pub async fn get_public_key(State(state): State<AppState>) -> Json<Jwk> {
    debug!("Serving the transport public key");
    let transport = state.keys.get(KeyName::Transport);
    Json(jwk_for_public_key(&transport.current.public_key()))
}

// ============================================================================
// Admin Endpoints
// ============================================================================

/// Response for admin status endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminStatusResponse {
    pub status: String,
    pub admin_user: String,
    pub uptime_seconds: u64,
}

/// Admin-only status endpoint.
///
/// Returns enclave operational status. Requires admin role.
#[utoipa::path(
    get,
    path = "/v1/admin/status",
    tag = "Admin",
    summary = "Admin status",
    description = "Returns enclave status. Requires admin role.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Status returned", body = AdminStatusResponse),
        (status = 401, description = "Unauthorized - missing or invalid token"),
        (status = 403, description = "Forbidden - admin role required")
    )
)]
pub async fn admin_status(caller: Caller) -> Result<Json<AdminStatusResponse>, ApiError> {
    caller.require_admin()?;
    info!(admin_user = %caller.user_id, "Admin status requested");
    let uptime_seconds = crate::STARTED_AT
        .get()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    Ok(Json(AdminStatusResponse {
        status: "operational".to_string(),
        admin_user: caller.user_id,
        uptime_seconds,
    }))
}

// ============================================================================
// Sealed uploads
// ============================================================================

/// Read and open the sealed CSV of `caller`'s upload `request`.
pub(crate) async fn open_sealed_csv(
    transport: &ReleasedKey,
    caller: &Caller,
    request: &Idempotent,
    multipart: Multipart,
) -> Result<Vec<u8>, ApiError> {
    let upload = SealedUpload::read(multipart).await?;
    let aad = seal::request_aad(
        request.method().as_str(),
        request.path(),
        &request.key,
        &upload.kid,
        &caller.user_id,
    );
    Ok(seal::open_upload(transport, &upload, &aad)?)
}

/// Validate a CSV payload against the pool's schema.
///
/// `mode == None` skips the schema entirely. Other modes need one.
pub(crate) fn validate_payload(
    schema: &[FieldSchema],
    pool_pda: &str,
    csv_bytes: &[u8],
    mode: ValidationMode,
) -> Result<ValidationSummary, ApiError> {
    if matches!(mode, ValidationMode::None) {
        return Ok(validate_csv_bytes(csv_bytes, &[], mode));
    }
    if schema.is_empty() {
        return Err(ApiError::bad_request(format!(
            "pool {pool_pda} has no schema — upload one first",
        )));
    }
    Ok(validate_csv_bytes(csv_bytes, schema, mode))
}
