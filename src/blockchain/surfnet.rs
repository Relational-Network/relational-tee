// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Tests against a surfnet: a local Solana network that runs the real
//! programs and clones what it lacks from devnet on first use, the DRT
//! program among them. `just chain-test` starts one and runs the tests
//! named `surfnet_`, which the fake chain can't stand in for: whether the
//! real System, SPL Token, token account and Memo programs do what the
//! worker's transactions rely on.

use serde_json::json;
use solana_pubkey::Pubkey;

use super::types::devnet_config;
use super::SolanaClient;
use crate::http_client::HttpClient;

/// The surfnet `just chain-test` started.
pub fn url() -> String {
    std::env::var("SURFNET_URL").expect("SURFNET_URL names a surfnet: run `just chain-test`")
}

/// A client of the surfnet at `SURFNET_URL`, configured as for devnet.
pub fn client() -> SolanaClient {
    SolanaClient::new(&url(), devnet_config(&url()))
}

/// Give `address` `lamports`, by Surfpool's `surfnet_setAccount`.
pub async fn fund(address: &Pubkey, lamports: u64) {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "surfnet_setAccount",
        "params": [address.to_string(), { "lamports": lamports }],
    });
    let response = HttpClient::new().post_json(&url(), &body).await.unwrap();
    assert!(
        response.is_success(),
        "surfnet_setAccount: {}",
        response.status()
    );
}
