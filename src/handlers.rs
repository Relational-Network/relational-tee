// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! HTTP request handlers for the enclave API.
//!
//! This module contains handlers for:
//! - Admin endpoints (require admin role)
//! - Opening and validating the sealed CSV uploads of the pool endpoints

use axum::{extract::Multipart, Json};
use serde::Serialize;
use tracing::info;
use utoipa::ToSchema;

use crate::auth::Caller;
use crate::data_validation::{validate_csv_bytes, FieldSchema, ValidationSummary};
use crate::error::ApiError;
use crate::idempotency::Idempotent;
use crate::seal::{self, SealedUpload, TransportKeys};

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
    transport: &TransportKeys,
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
pub(crate) fn validate_payload(
    schema: &[FieldSchema],
    pool_pda: &str,
    csv_bytes: &[u8],
) -> Result<ValidationSummary, ApiError> {
    if schema.is_empty() {
        return Err(ApiError::bad_request(format!(
            "pool {pool_pda} has no schema, so it takes no uploads"
        )));
    }
    Ok(validate_csv_bytes(csv_bytes, schema))
}
