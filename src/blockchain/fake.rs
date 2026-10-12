// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A fake Solana JSON-RPC server for tests: accounts, landed transactions,
//! a block height, fresh blockhashes, and a record of what was sent.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use super::drt::idl_generated::DISC_GRANT_ACCOUNT;
use super::drt::types::{
    GrantAccount, Pool, DISC_GRANT_RIGHT, DISC_POOL_ACCOUNT, DISC_REVOKE_GRANT,
};
use super::types::devnet_config;
use super::SolanaClient;
use crate::config::drt_program_id;

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// How many blocks a blockhash stays valid for.
pub const VALID_FOR: u64 = 150;

/// The rent-exempt minimum of an account with no data, as on devnet.
pub const RECEIPT_DEPOSIT: u64 = 890_880;

/// The System program's `CreateAccountWithSeed` and `TransferWithSeed`.
const CREATE_ACCOUNT_WITH_SEED: [u8; 4] = 3u32.to_le_bytes();
const TRANSFER_WITH_SEED: [u8; 4] = 11u32.to_le_bytes();

#[derive(Default)]
pub struct FakeChain {
    /// Accounts that hold only lamports, owned by the System program, as
    /// sending SOL to an address makes them.
    pub accounts: Mutex<Vec<Pubkey>>,
    /// Accounts with data, owned by the DRT program, which `getAccountInfo`
    /// and `getMultipleAccounts` return.
    pub data: Mutex<Vec<(Pubkey, Vec<u8>)>>,
    /// While set, account reads answer with this HTTP status, as a node
    /// that is down (503) or rate-limiting (429) does.
    pub refuse_reads: Mutex<Option<u16>>,
    /// Every method called, in order.
    pub calls: Mutex<Vec<String>>,
    /// Mints' supplies, which `getTokenSupply` returns; for any other mint
    /// it answers with an error.
    pub supplies: Mutex<Vec<(Pubkey, u64)>>,
    /// Finalized transactions, and whether each succeeded.
    pub landed: Mutex<Vec<(String, bool)>>,
    /// `getSignaturesForAddress`'s answer, newest first.
    pub history: Mutex<Vec<Value>>,
    pub block_height: AtomicU64,
    /// What `getBalance` answers for every address.
    pub balance: AtomicU64,
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

    /// The program's Grant at `pda`, for a burn of `drt_config`'s DRT.
    pub fn grant(&self, pda: Pubkey, drt_config: Pubkey) {
        let account = GrantAccount {
            drt_config,
            granted_at: 1,
            bump: 255,
        };
        let data = [&DISC_GRANT_ACCOUNT[..], &borsh::to_vec(&account).unwrap()].concat();
        self.close(&pda);
        self.data.lock().unwrap().push((pda, data));
    }

    /// The program's Pool at `pda`, owned by `owner`.
    pub fn pool(&self, pda: Pubkey, owner: Pubkey) {
        let account = Pool {
            uuid: [7; 16],
            owner,
            created_at: 0,
            sealed: true,
            bump: 255,
        };
        let data = [&DISC_POOL_ACCOUNT[..], &borsh::to_vec(&account).unwrap()].concat();
        self.close(&pda);
        self.data.lock().unwrap().push((pda, data));
    }

    /// Remove whatever account is at `pda`, as closing it does.
    pub fn close(&self, pda: &Pubkey) {
        self.data.lock().unwrap().retain(|(a, _)| a != pda);
        self.accounts.lock().unwrap().retain(|a| a != pda);
    }

    /// How many times `method` was called.
    pub fn called(&self, method: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|m| *m == method)
            .count()
    }

    /// Whether an account, with data or only lamports, is at `address`.
    pub fn exists(&self, address: &Pubkey) -> bool {
        self.data.lock().unwrap().iter().any(|(a, _)| a == address)
            || self.accounts.lock().unwrap().contains(address)
    }

    /// What a landed transaction does, as the programs do it, and whether it
    /// succeeded: `grant_right` opens a Grant and `revoke_grant` closes one;
    /// `CreateAccountWithSeed` makes an account, and fails the whole
    /// transaction where one exists; `TransferWithSeed` empties one.
    fn apply(&self, tx: &Transaction) -> bool {
        let keys = &tx.message.account_keys;
        let system = |program: u8, data: &[u8], op: [u8; 4]| {
            keys[program as usize].to_string() == SYSTEM_PROGRAM && data.starts_with(&op)
        };
        let taken = tx.message.instructions.iter().any(|ix| {
            system(ix.program_id_index, &ix.data, CREATE_ACCOUNT_WITH_SEED)
                && self.exists(&keys[ix.accounts[1] as usize])
        });
        if taken {
            return false;
        }
        for ix in &tx.message.instructions {
            let account = |i: usize| keys[ix.accounts[i] as usize];
            if system(ix.program_id_index, &ix.data, CREATE_ACCOUNT_WITH_SEED) {
                self.accounts.lock().unwrap().push(account(1));
            } else if system(ix.program_id_index, &ix.data, TRANSFER_WITH_SEED) {
                self.close(&account(0));
            }
            if keys[ix.program_id_index as usize] != drt_program_id() || ix.data.len() < 8 {
                continue;
            }
            if ix.data[..8] == DISC_GRANT_RIGHT {
                self.grant(account(5), account(1));
            } else if ix.data[..8] == DISC_REVOKE_GRANT {
                self.close(&account(3));
            }
        }
        true
    }

    /// The account at `address` as `getAccountInfo` returns it, or null.
    fn account(&self, address: &str) -> Value {
        let data = self
            .data
            .lock()
            .unwrap()
            .iter()
            .find(|(a, _)| a.to_string() == address)
            .map(|(_, data)| data.clone());
        if let Some(data) = data {
            return json!({ "lamports": 1, "owner": drt_program_id().to_string(),
                "data": [BASE64.encode(data), "base64"] });
        }
        let lamports_only = self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .any(|a| a.to_string() == address);
        if lamports_only {
            json!({ "lamports": 1, "owner": SYSTEM_PROGRAM, "data": ["", "base64"] })
        } else {
            Value::Null
        }
    }

    /// The call's result, or its JSON-RPC error.
    fn answer(&self, method: &str, params: &Value) -> Result<Value, Value> {
        let context = |value: Value| json!({ "context": { "slot": 1 }, "value": value });
        Ok(match method {
            "getAccountInfo" => context(self.account(params[0].as_str().unwrap())),
            "getMultipleAccounts" => context(Value::Array(
                params[0]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| self.account(a.as_str().unwrap()))
                    .collect(),
            )),
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
            "getMinimumBalanceForRentExemption" => json!(RECEIPT_DEPOSIT),
            "getBalance" => context(json!(self.balance.load(Ordering::SeqCst))),
            "getFeeForMessage" => context(json!(5000)),
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
                let processed = self
                    .landed
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(s, _)| *s == signature);
                if self.lands.load(Ordering::SeqCst) && !processed {
                    let succeeded = self.apply(&tx);
                    self.land(&signature, succeeded);
                }
                json!(signature)
            }
            other => panic!("unexpected RPC call {other}"),
        })
    }
}

async fn rpc(State(chain): State<Arc<FakeChain>>, Json(req): Json<Value>) -> Response {
    let method = req["method"].as_str().unwrap();
    chain.calls.lock().unwrap().push(method.into());
    let reads = matches!(method, "getAccountInfo" | "getMultipleAccounts");
    if let Some(status) = chain.refuse_reads.lock().unwrap().filter(|_| reads) {
        return StatusCode::from_u16(status).unwrap().into_response();
    }
    Json(match chain.answer(method, &req["params"]) {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }),
        Err(error) => json!({ "jsonrpc": "2.0", "id": req["id"], "error": error }),
    })
    .into_response()
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
