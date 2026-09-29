// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Lightweight Solana JSON-RPC client.
//!
//! Replaces `solana-client` with direct HTTP calls over our in-house
//! `http_client` (hyper + hyper-rustls), eliminating ~300 transitive
//! dependencies (quinn, ring, etc.) plus the `url`/`idna`/`icu_*`
//! chain that `reqwest` would have pulled in.

use crate::http_client::HttpClient;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Error
// ============================================================================

/// Minimal RPC error type.
#[derive(Debug)]
pub struct RpcError {
    pub message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

// ============================================================================
// Response envelope
// ============================================================================

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcErrorObject>,
    #[allow(dead_code)]
    id: Option<Value>,
}

#[derive(Deserialize)]
struct RpcErrorObject {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct RpcContext<T> {
    #[allow(dead_code)]
    context: Option<Value>,
    value: T,
}

// ============================================================================
// Client
// ============================================================================

/// Asynchronous Solana JSON-RPC client.
///
/// Default commitment: `confirmed` (single validator, ~400ms).
pub struct JsonRpcClient {
    client: HttpClient,
    url: String,
    commitment: String,
    next_id: AtomicU64,
}

impl JsonRpcClient {
    /// Create a new client for the given RPC URL.
    pub fn new(url: &str, commitment: &str) -> Self {
        Self {
            client: HttpClient::new(),
            url: url.to_string(),
            commitment: commitment.to_string(),
            next_id: AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Execute a JSON-RPC call and return the raw `result` field.
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.next_id(),
            "method": method,
            "params": params,
        });

        let resp = self
            .client
            .post_json(&self.url, &body)
            .await
            .map_err(|e| RpcError::new(format!("HTTP error: {e}")))?;

        let status = resp.status();
        let text = resp
            .into_text()
            .map_err(|e| RpcError::new(format!("response read error: {e}")))?;

        if !status.is_success() {
            return Err(RpcError::new(format!("HTTP {status}: {text}")));
        }

        let rpc_resp: RpcResponse<Value> =
            serde_json::from_str(&text).map_err(|e| RpcError::new(format!("JSON parse: {e}")))?;

        if let Some(err) = rpc_resp.error {
            return Err(RpcError::new(format!(
                "RPC error {}: {}",
                err.code, err.message
            )));
        }

        rpc_resp
            .result
            .ok_or_else(|| RpcError::new("missing result in response"))
    }

    /// Execute a JSON-RPC call and deserialize `result` into `T`.
    async fn call_typed<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, RpcError> {
        let value = self.call(method, params).await?;
        serde_json::from_value(value).map_err(|e| RpcError::new(format!("deserialize: {e}")))
    }

    // ========================================================================
    // RPC methods
    // ========================================================================

    /// `getLatestBlockhash` → (Hash, lastValidBlockHeight).
    pub async fn get_latest_blockhash(&self) -> Result<Hash, RpcError> {
        #[derive(Deserialize)]
        struct Inner {
            blockhash: String,
            #[allow(dead_code)]
            #[serde(rename = "lastValidBlockHeight")]
            last_valid_block_height: u64,
        }
        let ctx: RpcContext<Inner> = self
            .call_typed(
                "getLatestBlockhash",
                json!([{"commitment": self.commitment}]),
            )
            .await?;
        ctx.value
            .blockhash
            .parse()
            .map_err(|_| RpcError::new("invalid blockhash"))
    }

    /// `sendTransaction` — serialize, base64 encode, send.
    pub async fn send_transaction(
        &self,
        tx: &solana_transaction::Transaction,
    ) -> Result<Signature, RpcError> {
        let bytes =
            bincode::serialize(tx).map_err(|e| RpcError::new(format!("serialize tx: {e}")))?;
        let encoded = BASE64.encode(&bytes);
        let sig_str: String = self
            .call_typed(
                "sendTransaction",
                json!([
                    encoded,
                    {
                        "encoding": "base64",
                        "skipPreflight": false,
                        "preflightCommitment": self.commitment,
                    }
                ]),
            )
            .await?;
        Signature::from_str(&sig_str).map_err(|_| RpcError::new("invalid signature in response"))
    }

    /// `getSignatureStatuses` — check confirmation status for one or more signatures.
    pub async fn get_signature_statuses(
        &self,
        signatures: &[&Signature],
    ) -> Result<Vec<Option<SignatureStatus>>, RpcError> {
        let sigs: Vec<String> = signatures.iter().map(|s| s.to_string()).collect();
        let ctx: RpcContext<Vec<Option<SignatureStatus>>> = self
            .call_typed(
                "getSignatureStatuses",
                json!([sigs, {"searchTransactionHistory": false}]),
            )
            .await?;
        Ok(ctx.value)
    }

    /// `getBalance` → lamports.
    pub async fn get_balance(&self, pubkey: &Pubkey) -> Result<u64, RpcError> {
        let ctx: RpcContext<u64> = self
            .call_typed(
                "getBalance",
                json!([pubkey.to_string(), {"commitment": self.commitment}]),
            )
            .await?;
        Ok(ctx.value)
    }

    /// `getAccountInfo` → raw account bytes (or `None` if not found).
    pub async fn get_account_data(&self, pubkey: &Pubkey) -> Result<Option<Vec<u8>>, RpcError> {
        let ctx: RpcContext<Value> = self
            .call_typed(
                "getAccountInfo",
                json!([
                    pubkey.to_string(),
                    {"encoding": "base64", "commitment": self.commitment}
                ]),
            )
            .await?;

        if ctx.value.is_null() {
            return Ok(None);
        }

        let data_arr = ctx.value["data"]
            .as_array()
            .ok_or_else(|| RpcError::new("missing data field"))?;
        let b64 = data_arr[0]
            .as_str()
            .ok_or_else(|| RpcError::new("data[0] not a string"))?;
        let bytes = BASE64
            .decode(b64)
            .map_err(|e| RpcError::new(format!("base64 decode: {e}")))?;
        Ok(Some(bytes))
    }

    /// `getFeeForMessage` → fee in lamports.
    pub async fn get_fee_for_message(
        &self,
        message: &solana_message::Message,
    ) -> Result<u64, RpcError> {
        let msg_bytes =
            bincode::serialize(message).map_err(|e| RpcError::new(format!("serialize: {e}")))?;
        let encoded = BASE64.encode(&msg_bytes);
        let ctx: RpcContext<Option<u64>> = self
            .call_typed(
                "getFeeForMessage",
                json!([encoded, {"commitment": self.commitment}]),
            )
            .await?;
        ctx.value.ok_or_else(|| RpcError::new("null fee response"))
    }

    /// `getHealth` → Ok(()) if healthy.
    pub async fn get_health(&self) -> Result<(), RpcError> {
        let result: String = self.call_typed("getHealth", json!([])).await?;
        if result == "ok" {
            Ok(())
        } else {
            Err(RpcError::new(format!("unhealthy: {result}")))
        }
    }

    /// `getTokenAccountBalance` → token amount info.
    pub async fn get_token_account_balance(
        &self,
        pubkey: &Pubkey,
    ) -> Result<TokenAmountInfo, RpcError> {
        let ctx: RpcContext<TokenAmountInfo> = self
            .call_typed(
                "getTokenAccountBalance",
                json!([pubkey.to_string(), {"commitment": self.commitment}]),
            )
            .await?;
        Ok(ctx.value)
    }

    /// `getTokenSupply` → current circulating SPL supply for a mint.
    ///
    /// Returns the live, on-chain remaining supply (minted minus burned).
    pub async fn get_token_supply(&self, mint: &Pubkey) -> Result<TokenAmountInfo, RpcError> {
        let ctx: RpcContext<TokenAmountInfo> = self
            .call_typed(
                "getTokenSupply",
                json!([mint.to_string(), {"commitment": self.commitment}]),
            )
            .await?;
        Ok(ctx.value)
    }

    /// `getTransaction` → transaction details with meta (logs, fee, etc.).
    pub async fn get_transaction(
        &self,
        signature: &str,
        commitment: &str,
    ) -> Result<TransactionDetail, RpcError> {
        let result: Value = self
            .call(
                "getTransaction",
                json!([
                    signature,
                    {
                        "encoding": "jsonParsed",
                        "commitment": commitment,
                        "maxSupportedTransactionVersion": 0,
                    }
                ]),
            )
            .await?;

        if result.is_null() {
            return Err(RpcError::new(format!("transaction {signature} not found")));
        }

        Ok(TransactionDetail {
            slot: result["slot"].as_u64().unwrap_or(0),
            meta: parse_tx_meta(&result["meta"]),
            transaction: parse_tx_envelope(&result["transaction"]),
        })
    }

    /// `getSignaturesForAddress` → recent signatures.
    pub async fn get_signatures_for_address(
        &self,
        address: &Pubkey,
        before: Option<&str>,
        until: Option<&str>,
        limit: Option<usize>,
        commitment: &str,
    ) -> Result<Vec<SignatureInfo>, RpcError> {
        let mut config = json!({"commitment": commitment});
        if let Some(b) = before {
            config["before"] = json!(b);
        }
        if let Some(u) = until {
            config["until"] = json!(u);
        }
        if let Some(l) = limit {
            config["limit"] = json!(l);
        }
        self.call_typed(
            "getSignaturesForAddress",
            json!([address.to_string(), config]),
        )
        .await
    }
}

// ============================================================================
// Response types (lightweight — no solana-transaction-status dependency)
// ============================================================================

/// Signature confirmation status from `getSignatureStatuses`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SignatureStatus {
    pub slot: u64,
    pub confirmations: Option<u64>,
    pub err: Option<Value>,
    #[serde(rename = "confirmationStatus")]
    pub confirmation_status: Option<String>,
}

/// Token account balance info from `getTokenAccountBalance`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenAmountInfo {
    pub amount: String,
    pub decimals: u8,
    #[serde(rename = "uiAmountString")]
    pub ui_amount_string: Option<String>,
}

/// Parsed transaction detail from `getTransaction`.
#[derive(Debug)]
pub struct TransactionDetail {
    pub slot: u64,
    pub meta: Option<TransactionMeta>,
    pub transaction: TransactionEnvelope,
}

/// Transaction metadata (fee, logs, balances, etc.).
#[derive(Debug)]
#[allow(dead_code)]
pub struct TransactionMeta {
    pub fee: u64,
    pub log_messages: Vec<String>,
    pub err: Option<Value>,
    /// Pre-transaction balances (in lamports) for each account in account_keys order.
    pub pre_balances: Vec<u64>,
    /// Post-transaction balances (in lamports) for each account in account_keys order.
    pub post_balances: Vec<u64>,
}

/// Parsed transaction envelope (account keys for fee-payer extraction).
#[derive(Debug)]
pub struct TransactionEnvelope {
    pub account_keys: Vec<String>,
}

/// Signature info from `getSignaturesForAddress`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: Option<u64>,
    pub err: Option<Value>,
    #[serde(rename = "blockTime")]
    pub block_time: Option<i64>,
    #[serde(rename = "confirmationStatus")]
    pub confirmation_status: Option<String>,
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_tx_meta(v: &Value) -> Option<TransactionMeta> {
    if v.is_null() {
        return None;
    }
    Some(TransactionMeta {
        fee: v["fee"].as_u64().unwrap_or(0),
        log_messages: v["logMessages"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        err: if v["err"].is_null() {
            None
        } else {
            Some(v["err"].clone())
        },
        pre_balances: v["preBalances"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|x| x.as_u64()).collect())
            .unwrap_or_default(),
        post_balances: v["postBalances"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|x| x.as_u64()).collect())
            .unwrap_or_default(),
    })
}

fn parse_tx_envelope(v: &Value) -> TransactionEnvelope {
    // jsonParsed format: { message: { accountKeys: [ { pubkey: "..." }, ... ] } }
    let keys = v["message"]["accountKeys"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    // Could be string or object with "pubkey" field
                    item.as_str()
                        .map(String::from)
                        .or_else(|| item["pubkey"].as_str().map(String::from))
                })
                .collect()
        })
        .unwrap_or_default();
    TransactionEnvelope { account_keys: keys }
}
