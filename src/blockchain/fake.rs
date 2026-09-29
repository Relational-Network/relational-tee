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
    /// Finalized transactions, and whether each succeeded.
    pub landed: Mutex<Vec<(String, bool)>>,
    /// `getSignaturesForAddress`'s answer, newest first.
    pub history: Mutex<Vec<Value>>,
    pub block_height: AtomicU64,
    /// Every transaction sent, as sent.
    pub sent: Mutex<Vec<String>>,
    /// Whether a sent transaction lands, successfully, at once.
    pub lands: AtomicBool,
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

    fn answer(&self, method: &str, params: &Value) -> Value {
        let context = |value: Value| json!({ "context": { "slot": 1 }, "value": value });
        match method {
            "getAccountInfo" => {
                let exists = self
                    .accounts
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|a| a.to_string() == params[0].as_str().unwrap());
                context(if exists {
                    json!({ "lamports": 1, "data": ["", "base64"] })
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
                let bytes = BASE64.decode(encoded).unwrap();
                let tx: Transaction = bincode::deserialize(&bytes).unwrap();
                let signature = tx.signatures[0].to_string();
                if self.lands.load(Ordering::SeqCst) {
                    self.land(&signature, true);
                }
                json!(signature)
            }
            other => panic!("unexpected RPC call {other}"),
        }
    }
}

async fn rpc(State(chain): State<Arc<FakeChain>>, Json(req): Json<Value>) -> Json<Value> {
    let result = chain.answer(req["method"].as_str().unwrap(), &req["params"]);
    Json(json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }))
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
