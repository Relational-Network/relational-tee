// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A fake Solana JSON-RPC server for tests: accounts, landed transactions,
//! a block height, fresh blockhashes, and a record of what was sent.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use super::types::devnet_config;
use super::SolanaClient;

/// How many blocks a blockhash stays valid for.
pub const VALID_FOR: u64 = 150;

#[derive(Default)]
pub struct FakeChain {
    pub accounts: Mutex<Vec<Pubkey>>,
    /// Accounts with data, which `getAccountInfo` returns.
    pub data: Mutex<Vec<(Pubkey, Vec<u8>)>>,
    /// Mints' supplies, which `getTokenSupply` returns; for any other mint
    /// it answers with an error.
    pub supplies: Mutex<Vec<(Pubkey, u64)>>,
    /// Finalized transactions, and whether each succeeded.
    pub landed: Mutex<Vec<(String, bool)>>,
    /// `getSignaturesForAddress`'s answer, newest first.
    pub history: Mutex<Vec<Value>>,
    pub block_height: AtomicU64,
    /// Every transaction sent, as sent.
    pub sent: Mutex<Vec<String>>,
    /// Whether a sent transaction lands, successfully, at once.
    pub lands: AtomicBool,
    /// The error a send's preflight simulation fails with, if any.
    pub preflight: Mutex<Option<Value>>,
    blockhashes: AtomicU8,
}

impl FakeChain {
    pub fn land(&self, signature: &str, succeeded: bool) {
        self.landed
            .lock()
            .unwrap()
            .push((signature.into(), succeeded));
    }

    pub fn sent(&self) -> Vec<String> {
        self.sent.lock().unwrap().clone()
    }

    /// The call's result, or its JSON-RPC error.
    fn answer(&self, method: &str, params: &Value) -> Result<Value, Value> {
        let context = |value: Value| json!({ "context": { "slot": 1 }, "value": value });
        Ok(match method {
            "getAccountInfo" => {
                let address = params[0].as_str().unwrap();
                let data = self
                    .data
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(a, _)| a.to_string() == address)
                    .map(|(_, data)| data.clone());
                let exists = data.is_some()
                    || self
                        .accounts
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|a| a.to_string() == address);
                context(if exists {
                    let data = BASE64.encode(data.unwrap_or_default());
                    json!({ "lamports": 1, "data": [data, "base64"] })
                } else {
                    Value::Null
                })
            }
            "getSignatureStatuses" => {
                let signature = params[0][0].as_str().unwrap();
                let status = self
                    .landed
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(s, _)| s == signature)
                    .map(|(_, ok)| {
                        let err = if *ok { Value::Null } else { json!("Failed") };
                        json!({ "slot": 1, "confirmations": null, "err": err,
                            "confirmationStatus": "finalized" })
                    });
                context(json!([status]))
            }
            "getTokenSupply" => {
                let mint = params[0].as_str().unwrap();
                let supply = self
                    .supplies
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(m, _)| m.to_string() == mint)
                    .map(|(_, supply)| *supply);
                let Some(supply) = supply else {
                    return Err(json!({
                        "code": -32602,
                        "message": "Invalid param: could not find account",
                    }));
                };
                context(json!({
                    "amount": supply.to_string(),
                    "decimals": 0,
                    "uiAmountString": supply.to_string(),
                }))
            }
            "getSignaturesForAddress" => Value::Array(self.history.lock().unwrap().clone()),
            "getBlockHeight" => json!(self.block_height.load(Ordering::SeqCst)),
            "getLatestBlockhash" => {
                let n = self.blockhashes.fetch_add(1, Ordering::SeqCst) + 1;
                let height = self.block_height.load(Ordering::SeqCst);
                context(json!({
                    "blockhash": Hash::new_from_array([n; 32]).to_string(),
                    "lastValidBlockHeight": height + VALID_FOR,
                }))
            }
            "sendTransaction" => {
                let encoded = params[0].as_str().unwrap();
                self.sent.lock().unwrap().push(encoded.into());
                if let Some(err) = self.preflight.lock().unwrap().clone() {
                    return Err(json!({
                        "code": -32002,
                        "message": format!("Transaction simulation failed: {err}"),
                        "data": { "err": err, "logs": [] },
                    }));
                }
                let bytes = BASE64.decode(encoded).unwrap();
                let tx: Transaction = bincode::deserialize(&bytes).unwrap();
                let signature = tx.signatures[0].to_string();
                if self.lands.load(Ordering::SeqCst) {
                    self.land(&signature, true);
                }
                json!(signature)
            }
            other => panic!("unexpected RPC call {other}"),
        })
    }
}

async fn rpc(State(chain): State<Arc<FakeChain>>, Json(req): Json<Value>) -> Json<Value> {
    Json(
        match chain.answer(req["method"].as_str().unwrap(), &req["params"]) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }),
            Err(error) => json!({ "jsonrpc": "2.0", "id": req["id"], "error": error }),
        },
    )
}

/// Serve `chain` on an ephemeral port, and a client for it.
pub fn start(chain: Arc<FakeChain>) -> SolanaClient {
    let app = Router::new().route("/", post(rpc)).with_state(chain);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = axum_server::from_tcp(listener).expect("server");
    tokio::spawn(server.serve(app.into_make_service()));
    SolanaClient::new(&url, devnet_config(&url))
}
