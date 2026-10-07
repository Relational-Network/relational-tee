// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Opening and validating the sealed CSV uploads of the pool endpoints.

use axum::extract::Multipart;

use crate::auth::Caller;
use crate::data_validation::{validate_csv_bytes, FieldSchema, ValidationSummary};
use crate::error::ApiError;
use crate::idempotency::Idempotent;
use crate::seal::{self, SealedUpload, TransportKeys};

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
