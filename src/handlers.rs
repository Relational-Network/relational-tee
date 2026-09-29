// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! HTTP request handlers for the enclave API.
//!
//! This module contains handlers for:
//! - Public key endpoint (for browser encryption)
//! - Protected endpoints (require authentication)
//! - Admin endpoints (require admin role)
//! - Sealed CSV upload parsing and validation shared by the pool endpoints

use axum::{
    extract::{Multipart, State},
    Json,
};
use serde::Serialize;
use tracing::{debug, info};
use utoipa::ToSchema;

use crate::auth::AdminToken;
use crate::config::MAX_BODY_SIZE;
use crate::crypto::{jwk_for_public_key, Jwk};
use crate::data_validation::{
    load_pool_schema, validate_csv_bytes, ValidationMode, ValidationSummary,
};
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::paths::StoragePaths;
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
pub async fn admin_status(AdminToken(token): AdminToken) -> Json<AdminStatusResponse> {
    info!(admin_user = %token.sub, "Admin status requested");
    let uptime_seconds = crate::STARTED_AT
        .get()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    Json(AdminStatusResponse {
        status: "operational".to_string(),
        admin_user: token.sub,
        uptime_seconds,
    })
}

// ============================================================================
// Data Endpoints
// ============================================================================

#[derive(Debug, Default)]
pub(crate) struct MultipartCsvInput {
    pub encrypted_data: Option<String>,
    pub ephemeral_public_key: Option<String>,
    pub nonce: Option<String>,
}

pub(crate) struct ParsedCsvPayload {
    pub csv_bytes: Vec<u8>,
}

/// Validate a CSV payload against the pool's stored schema.
///
/// `mode == None` skips the schema lookup entirely. Other modes require the
/// schema to have been uploaded via `POST /v1/drt/pools/{pda}/schema`.
pub(crate) fn validate_payload(
    paths: &StoragePaths,
    pool_pda: &str,
    csv_bytes: &[u8],
    mode: ValidationMode,
) -> Result<ValidationSummary, ApiError> {
    if matches!(mode, ValidationMode::None) {
        return Ok(validate_csv_bytes(csv_bytes, &[], mode));
    }

    let schema = load_pool_schema(paths, pool_pda).ok_or_else(|| {
        ApiError::bad_request(format!(
            "schema for pool {pool_pda} not found — upload one to the enclave first",
        ))
    })?;

    Ok(validate_csv_bytes(csv_bytes, &schema, mode))
}

pub(crate) async fn parse_csv_payload(
    transport: &ReleasedKey,
    multipart: Multipart,
) -> Result<ParsedCsvPayload, ApiError> {
    let input = parse_multipart_fields(multipart).await?;
    let (encrypted_data, ephemeral_key, nonce) = input.encrypted_parts()?;

    let csv_bytes =
        crate::crypto::decrypt_ecdh_payload(transport, &encrypted_data, &ephemeral_key, &nonce)
            .map_err(ApiError::bad_request)?;

    ensure_size_limit(&csv_bytes)?;

    Ok(ParsedCsvPayload { csv_bytes })
}

impl MultipartCsvInput {
    fn encrypted_parts(self) -> Result<(String, String, String), ApiError> {
        let encrypted_data = self
            .encrypted_data
            .ok_or_else(|| ApiError::bad_request("missing encrypted_data field"))?;

        let ephemeral_key = self.ephemeral_public_key.ok_or_else(|| {
            ApiError::bad_request("ephemeral_public_key is required for encrypted uploads")
        })?;
        let nonce = self
            .nonce
            .ok_or_else(|| ApiError::bad_request("nonce is required for encrypted uploads"))?;

        Ok((encrypted_data, ephemeral_key, nonce))
    }
}

fn validate_csv_multipart_field_name(name: &str) -> Result<(), ApiError> {
    match name {
        "encrypted_data" | "ephemeral_public_key" | "nonce" => Ok(()),
        "file" => Err(ApiError::bad_request(
            "plaintext file uploads are not accepted — use encrypted_data with ephemeral_public_key and nonce",
        )),
        other => Err(ApiError::bad_request(format!(
            "unsupported multipart field: {other}"
        ))),
    }
}

pub(crate) async fn parse_multipart_fields(
    mut multipart: Multipart,
) -> Result<MultipartCsvInput, ApiError> {
    let mut input = MultipartCsvInput::default();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("invalid multipart payload"))?
    {
        let Some(name) = field.name().map(str::to_owned) else {
            continue;
        };
        validate_csv_multipart_field_name(&name)?;

        match name.as_str() {
            "encrypted_data" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid encrypted_data field"))?;
                if !value.trim().is_empty() {
                    input.encrypted_data = Some(value.trim().to_string());
                }
            }
            "ephemeral_public_key" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid ephemeral_public_key field"))?;
                if !value.trim().is_empty() {
                    input.ephemeral_public_key = Some(value.trim().to_string());
                }
            }
            "nonce" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid nonce field"))?;
                if !value.trim().is_empty() {
                    input.nonce = Some(value.trim().to_string());
                }
            }
            _ => unreachable!("validated unsupported multipart field"),
        }
    }
    Ok(input)
}

pub(crate) fn ensure_size_limit(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.len() > MAX_BODY_SIZE {
        return Err(ApiError::bad_request(format!(
            "payload exceeds maximum size of {} bytes",
            MAX_BODY_SIZE
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_upload_parts_do_not_require_schema_id() {
        let input = MultipartCsvInput {
            encrypted_data: Some("ciphertext".to_string()),
            ephemeral_public_key: Some("ephemeral-key".to_string()),
            nonce: Some("nonce".to_string()),
        };

        let parts = input.encrypted_parts();
        assert!(parts.is_ok());
    }

    #[test]
    fn encrypted_upload_parts_require_encrypted_fields() {
        let input = MultipartCsvInput {
            encrypted_data: Some("ciphertext".to_string()),
            ephemeral_public_key: None,
            nonce: Some("nonce".to_string()),
        };

        assert!(input.encrypted_parts().is_err());
    }

    #[test]
    fn credential_upload_rejects_schema_id_field() {
        assert!(validate_csv_multipart_field_name("schema_id").is_err());
    }

    #[test]
    fn credential_upload_rejects_plaintext_file_field() {
        assert!(validate_csv_multipart_field_name("file").is_err());
    }

    #[test]
    fn credential_upload_accepts_encrypted_fields() {
        assert!(validate_csv_multipart_field_name("encrypted_data").is_ok());
        assert!(validate_csv_multipart_field_name("ephemeral_public_key").is_ok());
        assert!(validate_csv_multipart_field_name("nonce").is_ok());
    }
}
