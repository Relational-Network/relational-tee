// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Client-side validation for DRT requests.
//!
//! The on-chain contract is permissive on names — any non-empty string up to
//! `MAX_DRT_NAME_LEN` works. The off-chain rules we enforce here:
//!
//! - The `append` DRT is special: no `code_repo_url`, zeroed `code_hash`.
//!   It is the admin-only upload receipt for MALTA pools.
//! - Every other DRT must carry a non-empty URL and a non-zero 32-byte hash so
//!   the enclave can verify the script at grant time.
//! - Supplies must be `1..=MAX_SUPPLY`. Names cannot duplicate inside a pool.

use super::types::*;
use crate::error::ApiError;

/// A `DrtRequest` after validation: every field is normalised and the hash
/// is parsed into raw bytes ready for the instruction builder.
#[derive(Debug, Clone)]
pub struct ResolvedDrt {
    pub name: String,
    pub supply: u64,
    pub code_repo_url: String,
    pub code_hash: [u8; 32],
}

/// Validate an off-chain pool name.
pub fn validate_pool_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::bad_request("pool name cannot be empty"));
    }
    if name != name.trim() {
        return Err(ApiError::bad_request(
            "pool name cannot have leading/trailing whitespace",
        ));
    }
    if name.len() > MAX_POOL_NAME_LEN {
        return Err(ApiError::bad_request(format!(
            "pool name exceeds maximum {MAX_POOL_NAME_LEN} bytes"
        )));
    }
    Ok(())
}

/// Validate the logical DRT name supplied in a request.
pub fn validate_drt_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::bad_request("DRT name cannot be empty"));
    }
    if name != name.trim() {
        return Err(ApiError::bad_request(
            "DRT name cannot have leading/trailing whitespace",
        ));
    }
    if name.len() > MAX_DRT_NAME_LEN {
        return Err(ApiError::bad_request(format!(
            "DRT name exceeds maximum {MAX_DRT_NAME_LEN} bytes"
        )));
    }
    Ok(())
}

/// Parse a 64-char hex string into `[u8; 32]`. Empty → all zeros.
pub fn parse_code_hash(hex: &str) -> Result<[u8; 32], ApiError> {
    if hex.is_empty() {
        return Ok([0u8; 32]);
    }
    let clean = hex.strip_prefix("0x").unwrap_or(hex);
    if clean.len() != 64 {
        return Err(ApiError::bad_request(
            "code_hash must be exactly 64 hex characters",
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| ApiError::bad_request("code_hash contains invalid hex"))?;
    }
    Ok(out)
}

/// Validate + resolve a list of DRT requests. `allow_append=false` rejects
/// `append` outright (IOB ERP pools).
pub fn validate_drt_requests(
    drts: &[DrtRequest],
    allow_append: bool,
) -> Result<Vec<ResolvedDrt>, ApiError> {
    if drts.is_empty() {
        return Err(ApiError::bad_request("at least one DRT is required"));
    }
    if drts.len() > MAX_DRTS_PER_POOL {
        return Err(ApiError::bad_request(format!(
            "too many DRTs (max {MAX_DRTS_PER_POOL})"
        )));
    }

    let mut seen = std::collections::HashSet::new();
    let mut resolved = Vec::with_capacity(drts.len());

    for d in drts {
        validate_drt_name(&d.name)?;
        if !seen.insert(d.name.clone()) {
            return Err(ApiError::bad_request(format!("duplicate DRT '{}'", d.name)));
        }
        if !allow_append && d.name == APPEND_DRT_NAME {
            return Err(ApiError::bad_request(
                "the 'append' DRT is not allowed on IOB ERP pools",
            ));
        }
        if d.supply == 0 {
            return Err(ApiError::bad_request(format!(
                "DRT '{}' supply must be greater than 0",
                d.name
            )));
        }
        if d.supply > MAX_SUPPLY {
            return Err(ApiError::bad_request(format!(
                "DRT '{}' supply exceeds maximum ({MAX_SUPPLY})",
                d.name
            )));
        }

        let url = d.code_repo_url.clone().unwrap_or_default();
        let hash_hex = d.code_hash_hex.clone().unwrap_or_default();
        let is_append = d.name == APPEND_DRT_NAME;

        let (final_url, final_hash) = if is_append {
            if !url.is_empty() {
                return Err(ApiError::bad_request(
                    "append DRT must not include code_repo_url",
                ));
            }
            let parsed = parse_code_hash(&hash_hex)?;
            if parsed != [0u8; 32] {
                return Err(ApiError::bad_request(
                    "append DRT must use a zeroed code_hash",
                ));
            }
            (String::new(), [0u8; 32])
        } else {
            if url.is_empty() {
                return Err(ApiError::bad_request(format!(
                    "DRT '{}' requires a code_repo_url",
                    d.name
                )));
            }
            let trimmed_url = url.trim();
            if trimmed_url.len() != url.len() {
                return Err(ApiError::bad_request(format!(
                    "DRT '{}' code_repo_url has leading/trailing whitespace",
                    d.name
                )));
            }
            if url.len() > MAX_CODE_REPO_URL_LEN {
                return Err(ApiError::bad_request(format!(
                    "DRT '{}' code_repo_url exceeds maximum {MAX_CODE_REPO_URL_LEN} bytes",
                    d.name
                )));
            }
            let parsed = parse_code_hash(&hash_hex)?;
            if parsed == [0u8; 32] {
                return Err(ApiError::bad_request(format!(
                    "DRT '{}' requires a non-zero code_hash",
                    d.name
                )));
            }
            (url, parsed)
        };

        resolved.push(ResolvedDrt {
            name: d.name.clone(),
            supply: d.supply,
            code_repo_url: final_url,
            code_hash: final_hash,
        });
    }

    Ok(resolved)
}
