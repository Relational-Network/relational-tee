// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! On-chain account deserialisation for the `digital_rights_tokens` program.

use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;

use super::types::{
    DrtConfig, Grant, Pool, DISC_DRT_CONFIG_ACCOUNT, DISC_GRANT_ACCOUNT, DISC_POOL_ACCOUNT,
};
use crate::blockchain::rpc::JsonRpcClient;
use crate::error::ApiError;

/// Account size caps to prevent unbounded Borsh allocations from untrusted RPC.
const MAX_POOL_DATA: usize = 1024;
const MAX_DRT_CONFIG_DATA: usize = 4 * 1024;
const MAX_GRANT_DATA: usize = 256;

fn strip_discriminator<'a>(
    data: &'a [u8],
    expected: &[u8; 8],
    max: usize,
    label: &str,
) -> Result<&'a [u8], ApiError> {
    if data.len() < 8 {
        return Err(ApiError::internal(format!("{label} account too short")));
    }
    let disc: [u8; 8] = data[..8].try_into().unwrap();
    if &disc != expected {
        return Err(ApiError::internal(format!("invalid {label} discriminator")));
    }
    let payload = &data[8..];
    if payload.len() > max {
        return Err(ApiError::internal(format!(
            "{label} account too large ({} bytes, max {max})",
            payload.len()
        )));
    }
    Ok(payload)
}

/// Fetch and deserialise a Pool account from chain.
pub async fn fetch_pool(rpc: &JsonRpcClient, pool_pda: &Pubkey) -> Result<Pool, ApiError> {
    let data = rpc
        .get_account_data(pool_pda)
        .await
        .map_err(|e| ApiError::not_found(format!("pool account {pool_pda} not found: {e}")))?
        .ok_or_else(|| ApiError::not_found(format!("pool account {pool_pda} not found")))?;
    let payload = strip_discriminator(&data, &DISC_POOL_ACCOUNT, MAX_POOL_DATA, "pool")?;
    Pool::try_from_slice(payload)
        .map_err(|e| ApiError::internal(format!("failed to deserialise pool: {e}")))
}

/// Fetch and deserialise a DrtConfig account.
pub async fn fetch_drt_config(
    rpc: &JsonRpcClient,
    drt_config_pda: &Pubkey,
) -> Result<DrtConfig, ApiError> {
    let data = rpc
        .get_account_data(drt_config_pda)
        .await
        .map_err(|e| ApiError::not_found(format!("drt_config {drt_config_pda} not found: {e}")))?
        .ok_or_else(|| ApiError::not_found(format!("drt_config {drt_config_pda} not found")))?;
    let payload = strip_discriminator(
        &data,
        &DISC_DRT_CONFIG_ACCOUNT,
        MAX_DRT_CONFIG_DATA,
        "drt_config",
    )?;
    DrtConfig::try_from_slice(payload)
        .map_err(|e| ApiError::internal(format!("failed to deserialise drt_config: {e}")))
}

/// Fetch and deserialise a Grant account.
pub async fn fetch_grant(rpc: &JsonRpcClient, grant_pda: &Pubkey) -> Result<Grant, ApiError> {
    let data = rpc
        .get_account_data(grant_pda)
        .await
        .map_err(|e| ApiError::not_found(format!("grant {grant_pda} not found: {e}")))?
        .ok_or_else(|| ApiError::not_found(format!("grant {grant_pda} not found")))?;
    let payload = strip_discriminator(&data, &DISC_GRANT_ACCOUNT, MAX_GRANT_DATA, "grant")?;
    Grant::try_from_slice(payload)
        .map_err(|e| ApiError::internal(format!("failed to deserialise grant: {e}")))
}
