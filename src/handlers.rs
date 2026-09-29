// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! HTTP request handlers for the enclave API.
//!
//! This module contains handlers for:
//! - Public key endpoint (for browser encryption)
//! - Protected endpoints (require authentication)
//! - Admin endpoints (require admin role)
//! - Data endpoints (require appropriate roles)

use axum::{
    extract::{Multipart, State},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use utoipa::ToSchema;

use crate::auth::{AdminToken, AnalystToken};
use crate::config::MAX_BODY_SIZE;
use crate::crypto::{enclave_key, Jwk};
use crate::data_validation::{
    load_pool_schema, validate_csv_bytes, ValidationMode, ValidationSummary,
};
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::paths::StoragePaths;

// ============================================================================
// Public Key Endpoint
// ============================================================================

/// Get the enclave's public key for encrypting data.
///
/// Browsers use this key to encrypt payloads that only the enclave can decrypt.
/// The key is ephemeral and generated at enclave startup.
///
/// **Note:** In production, verify this key via AVS attestation tokens instead
/// of fetching directly.
#[utoipa::path(
    get,
    path = "/v1/attestation/public-key",
    tag = "Attestation",
    summary = "Get enclave public key",
    description = "Returns the enclave's P-256 public key in JWK format for browser encryption.",
    responses(
        (status = 200, description = "Public key returned", body = Jwk)
    )
)]
pub async fn get_public_key() -> Json<Jwk> {
    debug!("Serving enclave public key");
    let key = enclave_key();
    Json(key.public_jwk().clone())
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

/// Request body for `/v1/data/query`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DataQueryRequest {
    /// Pool PDA (base58) the DRT script reads from.
    pub pool_pda: String,
    /// Name of the DRT to invoke — must be present in the pool's `drts` map.
    pub drt_name: String,
    /// Free-form arguments forwarded to the DRT as the `args` JSON field.
    #[serde(default)]
    pub args: serde_json::Value,
}

/// Response for `/v1/data/query`.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataQueryResponse {
    /// Pool PDA the script ran against.
    pub pool_pda: String,
    /// DRT name that was invoked.
    pub drt_name: String,
    /// SHA-256 of the script that ran (matches on-chain `code_hash`).
    pub code_hash_hex: String,
    /// `run()` exit code from the WASM module. 0 = success.
    pub exit_code: i32,
    /// Script-emitted result as JSON.
    pub result: serde_json::Value,
}

/// Execute a DRT script against a pool inside the enclave.
///
/// Pipeline:
///
/// 1. Look up the pool and DRT metadata.
/// 2. Re-verify the script against the on-chain (mirrored) `code_hash`,
///    fetching from GitHub if not cached. Any mismatch fails the call.
/// 3. Read the pool's CSV datasets and concatenate them.
/// 4. Apply the row-level employer-group filter derived from the caller's
///    Entra claim. (Placeholder today — Entra plumb-through is Phase 2.5
///    backlog; for now the filter is a no-op and a TODO is emitted in logs.)
/// 5. Hand `{ csv, args }` to the wasmi sandbox; cap fuel + wall-clock + memory.
/// 6. Return whatever the script wrote — typically a small JSON blob.
///
/// Authorization: requires the analyst role. The `analyst_id` recorded in
/// the on-chain grant must match `token.sub` (verified by `commitment_hex`)
/// — TODO once the grant scan helper is wired (D3 backend).
#[utoipa::path(
    post,
    path = "/v1/data/query",
    tag = "Data",
    summary = "Run a DRT script against a pool",
    description = "Analyst-only. Fetches and verifies the DRT script, loads pool data, executes \
                   the script inside the WASM sandbox, and returns the result.",
    security(("bearer_auth" = [])),
    request_body = DataQueryRequest,
    responses(
        (status = 200, description = "Query result", body = DataQueryResponse),
        (status = 400, description = "Bad request / hash mismatch / script trap"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - analyst role required"),
        (status = 404, description = "Pool or DRT not found"),
    )
)]
pub async fn data_query(
    AnalystToken(token): AnalystToken,
    State(state): State<AppState>,
    Json(payload): Json<DataQueryRequest>,
) -> Result<Json<DataQueryResponse>, ApiError> {
    info!(
        sub = %token.sub,
        role = %token.role,
        pool = %payload.pool_pda,
        drt = %payload.drt_name,
        "Data query requested"
    );

    let result = data_query_inner(&state, &token, &payload).await;
    record_drt_execution_audit(&state, &token, &payload, &result).await;
    result.map(Json)
}

async fn data_query_inner(
    state: &AppState,
    token: &crate::auth::TokenData,
    payload: &DataQueryRequest,
) -> Result<DataQueryResponse, ApiError> {
    if payload.drt_name.is_empty() {
        return Err(ApiError::bad_request("drt_name cannot be empty"));
    }

    // 1. Pool + DRT lookup.
    let meta_path = state.storage.paths().pool_meta(&payload.pool_pda);
    let meta = state
        .storage
        .read_json::<crate::storage::pool_metadata::PoolMetadata>(&meta_path)
        .map_err(|_| ApiError::not_found(format!("pool {} not found", payload.pool_pda)))?;

    let drt = meta
        .drts
        .get(&payload.drt_name)
        .ok_or_else(|| ApiError::not_found(format!("DRT '{}' not in pool", payload.drt_name)))?;

    if drt.code_repo_url.is_empty() {
        return Err(ApiError::bad_request(format!(
            "DRT '{}' has no executable script (append-only)",
            payload.drt_name
        )));
    }

    // Enforce: the caller must hold an active grant for this DRT on this pool.
    // Grants are mirrored locally from `grant_right` / `revoke_grant` so this
    // is a single redb lookup — no chain round-trip on the hot query path.
    if !state
        .tx_db
        .is_grant_active(&token.sub, &payload.pool_pda, &payload.drt_name)
        .map_err(|e| ApiError::internal(format!("grant lookup: {e}")))?
    {
        return Err(ApiError::forbidden(format!(
            "no active grant for DRT '{}' in pool {}",
            payload.drt_name, payload.pool_pda
        )));
    }

    // 2. Fetch + SHA-256 verify against on-chain hash (cached + re-checked).
    let wasm_bytes = crate::drt::verified_fetch::fetch_and_verify(
        &drt.code_repo_url,
        &drt.code_hash_hex,
        &state.storage,
    )
    .await?;

    // 3. Load pool CSVs. For the pilot we concatenate every `*.csv` in the
    // pool's dataset dir; the schema is identical across files (initial.csv +
    // append snapshots), so a single CSV header followed by all body rows is
    // safe.
    let dataset_dir = state.storage.paths().pool_dataset_dir(&payload.pool_pda);
    let csv = load_and_concat_pool_csvs(&dataset_dir)?;

    // 4. TODO(phase-2.5): apply row-level employer_group filter from
    // `token.employer_group` once the AVS embeds the Entra group claim.
    if csv.is_empty() {
        return Err(ApiError::bad_request("pool has no data uploaded yet"));
    }

    // 5. Sandboxed execution. Prime the AOT cache so subsequent calls skip
    // Cranelift entirely (best-effort — falls through to JIT on failure).
    let scripts_dir = state.storage.paths().root().join("drt-scripts");
    let cache_path = match crate::drt::runtime::ensure_precompiled(
        &scripts_dir,
        &drt.code_hash_hex,
        &wasm_bytes,
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "AOT precompile skipped; falling back to JIT");
            crate::drt::runtime::precompile_cache_path(&scripts_dir, &drt.code_hash_hex)
        }
    };
    let runtime_input = crate::drt::runtime::RuntimeInput {
        csv: &csv,
        args: &payload.args,
    };
    let output = crate::drt::runtime::execute_cached(cache_path, wasm_bytes, runtime_input).await?;

    // 6. Try to parse the body as JSON; fall back to a string blob otherwise.
    let result_json: serde_json::Value =
        serde_json::from_slice(&output.body).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&output.body).into())
        });

    Ok(DataQueryResponse {
        pool_pda: payload.pool_pda.clone(),
        drt_name: payload.drt_name.clone(),
        code_hash_hex: drt.code_hash_hex.clone(),
        exit_code: output.exit_code,
        result: result_json,
    })
}

async fn record_drt_execution_audit(
    state: &AppState,
    token: &crate::auth::TokenData,
    payload: &DataQueryRequest,
    result: &Result<DataQueryResponse, ApiError>,
) {
    use crate::storage::audit::{AuditEvent, AuditEventType, AuditRepository};

    let mut details = serde_json::Map::new();
    details.insert(
        "pool_pda".to_string(),
        serde_json::Value::String(payload.pool_pda.clone()),
    );
    details.insert(
        "drt_name".to_string(),
        serde_json::Value::String(payload.drt_name.clone()),
    );
    details.insert("args".to_string(), payload.args.clone());

    let success = match result {
        Ok(resp) => {
            details.insert(
                "code_hash_hex".to_string(),
                serde_json::Value::String(resp.code_hash_hex.clone()),
            );
            details.insert(
                "exit_code".to_string(),
                serde_json::Value::Number(resp.exit_code.into()),
            );
            resp.exit_code == 0
        }
        Err(e) => {
            details.insert(
                "error".to_string(),
                serde_json::Value::String(e.to_string()),
            );
            false
        }
    };

    let mut evt = AuditEvent::new(AuditEventType::DrtExecuted)
        .with_user(&token.sub)
        .with_resource("drt_pool", &payload.pool_pda)
        .with_pool_pda(&payload.pool_pda)
        .with_details(serde_json::Value::Object(details));
    evt.success = success;

    AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&evt)
        .await;
}

fn load_and_concat_pool_csvs(dataset_dir: &std::path::Path) -> Result<String, ApiError> {
    use std::io::Read;
    let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(dataset_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("csv"))
            .collect(),
        Err(_) => return Ok(String::new()),
    };
    entries.sort();

    let mut out = String::new();
    let mut header_emitted = false;
    for path in entries {
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut buf = String::new();
        if file.read_to_string(&mut buf).is_err() {
            continue;
        }
        let mut lines = buf.lines();
        let Some(header) = lines.next() else { continue };
        if !header_emitted {
            out.push_str(header);
            out.push('\n');
            header_emitted = true;
        }
        for line in lines {
            if line.is_empty() {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out)
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

pub(crate) async fn parse_csv_payload(multipart: Multipart) -> Result<ParsedCsvPayload, ApiError> {
    let input = parse_multipart_fields(multipart).await?;
    let (encrypted_data, ephemeral_key, nonce) = input.encrypted_parts()?;

    let csv_bytes = crate::crypto::decrypt_ecdh_payload(&encrypted_data, &ephemeral_key, &nonce)
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
