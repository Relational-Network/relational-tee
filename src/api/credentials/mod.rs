// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential issuance, revocation, and pool discovery endpoints.
//!
//! Everything here reads or changes the pool document (see
//! [`crate::storage::pools`]).

pub mod initialize;
pub mod issue;
pub mod reads;
pub mod revoke;
pub mod schema;

use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use std::str::FromStr;

use crate::error::ApiError;

// ============================================================================
// Helpers
// ============================================================================

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Decode a 32-char hex string into 16 raw bytes. Used for right_id and pool_uuid.
pub(crate) fn decode_right_id(hex: &str) -> Result<[u8; 16], ApiError> {
    if hex.len() != 32 {
        return Err(ApiError::internal("expected 32-char hex (16 bytes)"));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ApiError::internal("invalid hex in 16-byte id"))?;
    }
    Ok(out)
}

/// Count CSV rows (excluding header).
fn count_csv_rows(csv_bytes: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(csv_bytes);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() > 1 {
        (lines.len() - 1) as u64 // subtract header
    } else {
        0
    }
}

fn validation_failed(errors: usize) -> ApiError {
    ApiError::bad_request(format!("CSV validation failed: {errors} error(s)"))
        .with_code("validation_failed")
}

fn pool_not_found(pool_pda: &str) -> ApiError {
    ApiError::not_found(format!("pool metadata not found for {pool_pda}"))
}

fn parse_pda(pool_pda: &str) -> Result<Pubkey, ApiError> {
    Pubkey::from_str(pool_pda).map_err(|_| ApiError::bad_request("invalid pool PDA address"))
}
