// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! On-chain account deserialisation for the `digital_rights_tokens` program.

use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;

use super::types::{DrtConfig, Pool, DISC_DRT_CONFIG_ACCOUNT, DISC_POOL_ACCOUNT};
use crate::blockchain::rpc::JsonRpcClient;
use crate::error::ApiError;

/// Account size caps to prevent unbounded Borsh allocations from untrusted RPC.
const MAX_POOL_DATA: usize = 1024;
const MAX_DRT_CONFIG_DATA: usize = 4 * 1024;

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

/// Fetch and deserialise a Pool account from chain. A missing account is
/// `404`; an RPC failure is `503 rpc_unavailable`, which a client retries.
pub async fn fetch_pool(rpc: &JsonRpcClient, pool_pda: &Pubkey) -> Result<Pool, ApiError> {
    let data = rpc
        .get_account_data(pool_pda)
        .await
        .map_err(|e| ApiError::rpc_unavailable(format!("reading pool account {pool_pda}: {e}")))?
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
        .map_err(|e| {
            ApiError::rpc_unavailable(format!("reading drt_config {drt_config_pda}: {e}"))
        })?
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::fake::{self, FakeChain};
    use std::sync::Arc;

    #[tokio::test]
    async fn a_missing_pool_is_not_found_and_an_rpc_failure_is_retryable() {
        let solana = fake::start(Arc::new(FakeChain::default()));
        let err = fetch_pool(solana.rpc(), &Pubkey::new_unique())
            .await
            .unwrap_err();
        assert_eq!(err.code, "not_found");

        let unreachable = "http://127.0.0.1:9";
        let solana = crate::blockchain::SolanaClient::new(
            unreachable,
            crate::blockchain::types::devnet_config(unreachable),
        );
        let err = fetch_pool(solana.rpc(), &Pubkey::new_unique())
            .await
            .unwrap_err();
        assert_eq!((err.status.as_u16(), err.code), (503, "rpc_unavailable"));
    }
}
