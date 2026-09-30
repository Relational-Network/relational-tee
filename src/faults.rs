// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The idempotency fault-injection suite (dev builds only):
//! `relational-tee faults`, which `just faults` runs against the local stack
//! of three workers behind its round-robin proxy.
//!
//! It calls the API as dev-token users, seals uploads to the stack's
//! transport key, and crashes workers mid-request with `X-Fault-Exit` (see
//! [`crate::fault`]); the stack restarts them, as ACI restarts a container,
//! and the suite retries through the proxy with the same `Idempotency-Key`.
//! Every check reads effects back through the API or Solana: append DRTs
//! burned, issuance entries, pool documents, wallets, transfers and
//! revocations. Chain steps run on devnet, so the suite user's wallet needs
//! devnet SOL; the suite stops at once, naming the address, if it has too
//! little.

use std::time::{Duration, Instant};

use axum::http::{header, Method, Request};
use bytes::Bytes;
use http_body_util::Full;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use solana_pubkey::Pubkey;

use crate::blockchain::SolanaClient;
use crate::http_client::HttpClient;
use crate::seal;
use crate::tee::dev_rsa::RsaSigner;

const USAGE: &str = "usage: relational-tee faults [--runs N]

Runs the idempotency fault-injection suite against FAULTS_API (default
http://127.0.0.1:8443), the local stack started with FAULT_INJECTION=on
(`just faults` starts it). --runs sets the randomised runs (default 20; the
acceptance run is 100). Tokens are signed with the dev token signing key.";

/// The suite user's wallet must hold at least this much devnet SOL.
const MIN_LAMPORTS: u64 = 200_000_000;
/// Each randomised send moves this much to a fresh address, enough for the
/// address to exist.
const SEND_LAMPORTS: u64 = 1_000_000;
const BOUNDARY: &str = "fault-suite-boundary";

/// The saga steps a pool creation or an issuance can crash after.
const SAGA_POINTS: [&str; 5] = ["staged", "tx_stored", "tx_sent", "tx_confirmed", "recorded"];

/// What came back: a response, or a dropped connection, as when the worker
/// handling the request exits.
enum Outcome {
    Reply(Reply),
    Dropped(String),
}

#[derive(Debug, Clone, PartialEq)]
struct Reply {
    status: u16,
    replayed: bool,
    body: Value,
}

impl Reply {
    fn expect(self, status: u16) -> Result<Self, String> {
        if self.status == status {
            Ok(self)
        } else {
            Err(format!(
                "expected {status}, got {} {}",
                self.status, self.body
            ))
        }
    }

    fn str(&self, field: &str) -> Result<String, String> {
        self.body[field]
            .as_str()
            .map(String::from)
            .ok_or_else(|| format!("the response has no {field}: {}", self.body))
    }
}

#[derive(Clone)]
enum Body {
    Empty,
    Json(Value),
    Form(Vec<u8>),
}

/// One request, sent as often as a scenario needs.
#[derive(Clone)]
struct Call {
    method: Method,
    path: String,
    token: String,
    key: Option<String>,
    body: Body,
}

struct Api {
    http: HttpClient,
    base: String,
}

impl Api {
    async fn send(&self, call: &Call, fault: Option<&str>) -> Outcome {
        let mut request = Request::builder()
            .method(call.method.clone())
            .uri(format!("{}{}", self.base, call.path))
            .header(header::AUTHORIZATION, format!("Bearer {}", call.token));
        if let Some(key) = &call.key {
            request = request.header("idempotency-key", key.as_str());
        }
        if let Some(point) = fault {
            request = request.header(crate::fault::HEADER, point);
        }
        let bytes = match &call.body {
            Body::Empty => Bytes::new(),
            Body::Json(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Bytes::from(value.to_string())
            }
            Body::Form(form) => {
                request = request.header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                );
                Bytes::from(form.clone())
            }
        };
        let request = match request.body(Full::new(bytes)) {
            Ok(request) => request,
            Err(e) => return Outcome::Dropped(e.to_string()),
        };
        match self.http.send(request).await {
            Ok(response) => Outcome::Reply(Reply {
                status: response.status().as_u16(),
                replayed: response.header("idempotent-replayed") == Some("true"),
                body: serde_json::from_slice(response.body()).unwrap_or(Value::Null),
            }),
            Err(e) => Outcome::Dropped(e.to_string()),
        }
    }

    /// Send until a worker gives a final answer, as a client retries: after
    /// a dropped connection, a 502 or 503, or a lost compare-and-swap. The
    /// wait grows, because devnet's public RPC rate-limits bursts.
    async fn settle(&self, call: &Call) -> Result<Reply, String> {
        let mut last = String::new();
        let mut wait = Duration::from_millis(1500);
        for _ in 0..40 {
            match self.send(call, None).await {
                Outcome::Reply(r) if !retryable(&r) => return Ok(r),
                Outcome::Reply(r) => last = format!("{} {}", r.status, r.body),
                Outcome::Dropped(e) => last = e,
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 3 / 2).min(Duration::from_secs(10));
        }
        Err(format!(
            "{} {} never settled: {last}",
            call.method, call.path
        ))
    }

    /// Send with `X-Fault-Exit: point`, which must crash the worker.
    async fn crash(&self, call: &Call, point: &str) -> Result<(), String> {
        match self.send(call, Some(point)).await {
            Outcome::Dropped(_) => Ok(()),
            Outcome::Reply(r) if r.status == 502 || r.status == 503 => Ok(()),
            Outcome::Reply(r) => Err(format!(
                "the worker didn't exit at {point}: {} {}",
                r.status, r.body
            )),
        }
    }

    async fn get(&self, path: &str, token: &str) -> Result<Value, String> {
        let call = Call {
            method: Method::GET,
            path: path.into(),
            token: token.into(),
            key: None,
            body: Body::Empty,
        };
        Ok(self.settle(&call).await?.expect(200)?.body)
    }
}

fn retryable(reply: &Reply) -> bool {
    matches!(reply.status, 502 | 503) || (reply.status == 409 && reply.body["code"] == "conflict")
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn random(below: u32) -> u32 {
    OsRng.next_u32() % below
}

struct User {
    token: String,
    user_id: String,
}

/// The suite user's wallet and pool, and the stack's transport key.
struct Suite {
    api: Api,
    solana: SolanaClient,
    signer: RsaSigner,
    entra: crate::config::EntraConfig,
    owner: User,
    wallet_id: String,
    kid: String,
    transport: p256::PublicKey,
}

impl Suite {
    async fn user(&self, oid: &str) -> Result<User, String> {
        let mut spec = crate::auth::entra::mint::Spec::valid(&self.entra);
        spec.oid = oid.into();
        spec.roles = vec!["Admin".into()];
        spec.email = Some(format!("{oid}@faults.invalid"));
        spec.name = Some("Fault suite".into());
        let token = spec.sign(&self.signer)?;
        let me = self.api.get("/v1/users/me", &token).await?;
        let user_id = me["user_id"]
            .as_str()
            .ok_or("/v1/users/me has no user_id")?
            .to_string();
        Ok(User { token, user_id })
    }

    fn call(&self, user: &User, method: Method, path: String, body: Body) -> Call {
        Call {
            method,
            path,
            token: user.token.clone(),
            key: Some(uuid()),
            body,
        }
    }

    /// A pool creation for the owner's wallet.
    fn pool_call(&self, name: &str, supply: u64) -> Call {
        let body = json!({
            "wallet_id": self.wallet_id,
            "pool_name": name,
            "drts": [{ "name": "append", "supply": supply }],
            "schema": { "fields": [
                { "name": "name", "field_type": { "varchar": 64 }, "nullable": false },
                { "name": "score", "field_type": "integer", "nullable": false },
            ]},
        });
        self.call(
            &self.owner,
            Method::POST,
            "/v1/drt/pools/malta".into(),
            Body::Json(body),
        )
    }

    /// An upload of `csv` to `route` of `pool`, sealed as the dashboard seals.
    fn upload_call(&self, pool: &str, route: &str, csv: &str) -> Call {
        let mut call = self.call(
            &self.owner,
            Method::POST,
            format!("/v1/drt/pools/{pool}/{route}"),
            Body::Empty,
        );
        let key = call.key.clone().unwrap_or_default();
        let aad = seal::request_aad("POST", &call.path, &key, &self.kid, &self.owner.user_id);
        let (enc, ct) = seal::seal_to(&self.transport, &aad, csv.as_bytes())
            .expect("the transport key is a P-256 key");
        call.body = Body::Form(seal::form(
            BOUNDARY,
            &[
                ("v", &b"1"[..]),
                ("kid", self.kid.as_bytes()),
                ("enc", enc.as_bytes()),
                ("ct", &ct),
            ],
        ));
        call
    }

    fn record_id(&self, pool: &str, call: &Call) -> String {
        crate::ids::upload_id(
            &self.owner.user_id,
            pool,
            call.key.as_deref().unwrap_or_default(),
        )
    }

    async fn remaining(&self, pool: &str) -> Result<u64, String> {
        let summary = self
            .api
            .get(&format!("/v1/drt/pools/{pool}/summary"), &self.owner.token)
            .await?;
        summary["drts"]
            .as_array()
            .and_then(|drts| drts.iter().find(|d| d["drt_type"] == "append"))
            .and_then(|d| d["remaining_supply"].as_u64())
            .ok_or_else(|| format!("the summary has no append supply: {summary}"))
    }

    /// How many times `record_id` is in the pool's issuance log.
    async fn logged(&self, pool: &str, record_id: &str) -> Result<usize, String> {
        let log = self
            .api
            .get(
                &format!("/v1/drt/pools/{pool}/issuance-log?limit=200"),
                &self.owner.token,
            )
            .await?;
        Ok(log["records"].as_array().map_or(0, |r| {
            r.iter().filter(|r| r["record_id"] == record_id).count()
        }))
    }

    /// How many pool documents name `pool`.
    async fn pools_named(&self, pool: &str) -> Result<usize, String> {
        let (mut count, mut cursor) = (0, String::new());
        loop {
            let page = self
                .api
                .get(
                    &format!("/v1/drt/pools/list?limit=100&cursor={cursor}"),
                    &self.owner.token,
                )
                .await?;
            count += page["pools"]
                .as_array()
                .map_or(0, |p| p.iter().filter(|p| p["pool_pda"] == pool).count());
            match page["next_cursor"].as_str() {
                Some(next) => cursor = next.to_string(),
                None => return Ok(count),
            }
        }
    }

    async fn initialized_pool(&self, name: &str, supply: u64) -> Result<String, String> {
        let pool = self
            .api
            .settle(&self.pool_call(name, supply))
            .await?
            .expect(201)?
            .str("pool_pda")?;
        let init = self.upload_call(&pool, "initialize", "name,score\nseed,0\n");
        self.api.settle(&init).await?.expect(200)?;
        Ok(pool)
    }
}

/// Criteria 1 and 3: a replay returns the stored response and creates
/// nothing; the same key with another body is refused.
async fn replays(s: &Suite) -> Result<String, String> {
    let call = s.pool_call(&format!("faults-{}", random(1_000_000)), 60);
    let first = s.api.settle(&call).await?.expect(201)?;
    let again = s.api.settle(&call).await?.expect(201)?;
    if !again.replayed || again.body != first.body {
        return Err(format!("the replay differs: {again:?}"));
    }
    let pool = first.str("pool_pda")?;
    let mut other = call.clone();
    if let Body::Json(body) = &mut other.body {
        body["pool_name"] = json!("another name");
    }
    let refused = s.api.settle(&other).await?.expect(422)?;
    if refused.body["code"] != "idempotency_mismatch" {
        return Err(format!("expected idempotency_mismatch: {}", refused.body));
    }
    if s.pools_named(&pool).await? != 1 {
        return Err(format!("pool {pool} doesn't have exactly one document"));
    }

    let init = s.upload_call(&pool, "initialize", "name,score\nseed,0\n");
    let first = s.api.settle(&init).await?.expect(200)?;
    let again = s.api.settle(&init).await?.expect(200)?;
    if !again.replayed || again.body != first.body {
        return Err("the initialisation's replay differs".into());
    }
    Ok(pool)
}

/// Checks that one issuance of `call` happened: one DRT burned since
/// `before`, and one issuance entry.
async fn issued_once(s: &Suite, pool: &str, call: &Call, before: u64) -> Result<(), String> {
    let after = s.remaining(pool).await?;
    if after + 1 != before {
        return Err(format!("{} append DRTs burned, not 1", before - after));
    }
    match s.logged(pool, &s.record_id(pool, call)).await? {
        1 => Ok(()),
        n => Err(format!("{n} issuance entries, not 1")),
    }
}

/// Criterion 2: two concurrent attempts with one key have one effect and
/// one response.
async fn concurrent(s: &Suite, pool: &str) -> Result<(), String> {
    let before = s.remaining(pool).await?;
    let call = s.upload_call(pool, "issue", "name,score\nconcurrent,1\n");
    let (a, b) = tokio::join!(s.api.settle(&call), s.api.settle(&call));
    let (a, b) = (a?.expect(200)?, b?.expect(200)?);
    if a.body != b.body {
        return Err(format!("the responses differ: {} and {}", a.body, b.body));
    }
    issued_once(s, pool, &call, before).await
}

/// Criterion 4: a worker killed after each saga step of an issuance, and
/// the request retried on another, burns one DRT and adds one entry.
async fn kills_during_issuance(s: &Suite, pool: &str) -> Result<(), String> {
    for point in SAGA_POINTS {
        let before = s.remaining(pool).await?;
        let call = s.upload_call(pool, "issue", &format!("name,score\n{point},2\n"));
        s.api.crash(&call, point).await?;
        s.api.settle(&call).await?.expect(200)?;
        issued_once(s, pool, &call, before)
            .await
            .map_err(|e| format!("after {point}: {e}"))?;
        println!("    killed after {point}: one burn, one entry");
    }
    Ok(())
}

/// Criterion 8: a pool creation retried after a crash leaves one pool
/// document.
async fn kills_during_pool_creation(s: &Suite) -> Result<(), String> {
    for point in SAGA_POINTS {
        let call = s.pool_call(&format!("faults-{point}-{}", random(1_000_000)), 1);
        s.api.crash(&call, point).await?;
        let reply = s.api.settle(&call).await?.expect(201)?;
        let pool = reply.str("pool_pda")?;
        match s.pools_named(&pool).await? {
            1 => println!("    killed after {point}: one pool document"),
            n => return Err(format!("after {point}: {n} documents for {pool}")),
        }
    }
    Ok(())
}

/// Criterion 5: after a crash between the burn and the pool document, with
/// no retry, the reconciler adds the entry.
async fn reconciler(s: &Suite, pool: &str) -> Result<(), String> {
    let before = s.remaining(pool).await?;
    let call = s.upload_call(pool, "issue", "name,score\nabandoned,3\n");
    s.api.crash(&call, "tx_confirmed").await?;
    let started = Instant::now();
    let record_id = s.record_id(pool, &call);
    while s.logged(pool, &record_id).await? == 0 {
        if started.elapsed() > Duration::from_secs(15 * 60) {
            return Err("the reconciler didn't add the entry within 15 minutes".into());
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    println!(
        "    the reconciler added the entry after {} s",
        started.elapsed().as_secs()
    );
    issued_once(s, pool, &call, before).await
}

/// Criterion 7: two users with one key get different IDs.
async fn two_users_one_key(s: &Suite) -> Result<(), String> {
    let key = uuid();
    let mut wallets = Vec::new();
    for _ in 0..2 {
        let user = s.user(&uuid()).await?;
        let mut call = s.call(
            &user,
            Method::POST,
            "/v1/wallets".into(),
            Body::Json(json!({})),
        );
        call.key = Some(key.clone());
        let reply = s.api.settle(&call).await?.expect(201)?;
        wallets.push(reply.body["wallet"]["wallet_id"].clone());
    }
    if wallets[0] == wallets[1] {
        return Err(format!("both users got wallet {}", wallets[0]));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Once,
    Twice,
    Together,
    Crash(&'static str),
}

/// Run `call` in `mode` and return its final response.
async fn exercise(api: &Api, call: &Call, mode: Mode) -> Result<Reply, String> {
    match mode {
        Mode::Once => api.settle(call).await,
        Mode::Twice => {
            let first = api.settle(call).await?;
            let again = api.settle(call).await?;
            if again.body != first.body || (first.status < 300 && !again.replayed) {
                return Err(format!(
                    "the repeat differs: {} then {}",
                    first.body, again.body
                ));
            }
            Ok(first)
        }
        Mode::Together => {
            let (a, b) = tokio::join!(api.settle(call), api.settle(call));
            let (a, b) = (a?, b?);
            if a.body != b.body {
                return Err(format!(
                    "concurrent attempts differ: {} and {}",
                    a.body, b.body
                ));
            }
            Ok(a)
        }
        Mode::Crash(point) => {
            api.crash(call, point).await?;
            api.settle(call).await
        }
    }
}

fn mode_for(points: &[&'static str]) -> Mode {
    match random(4) {
        0 => Mode::Once,
        1 => Mode::Twice,
        2 => Mode::Together,
        _ => Mode::Crash(points[random(points.len() as u32) as usize]),
    }
}

/// Criterion 6: randomised runs across issue, pool creation, wallet
/// creation, send and revoke, with duplicates, concurrent attempts and
/// crashes, checking after each that there's no double burn, double
/// transfer, lost update or second wallet.
async fn randomised(s: &Suite, pool: &str, runs: u32) -> Result<(), String> {
    for run in 1..=runs {
        let op = random(10);
        let (name, mode) = match op {
            0..=2 => {
                let mode = mode_for(&SAGA_POINTS);
                let before = s.remaining(pool).await?;
                let call = s.upload_call(pool, "issue", &format!("name,score\nrun{run},{run}\n"));
                exercise(&s.api, &call, mode).await?.expect(200)?;
                issued_once(s, pool, &call, before).await?;
                ("issue", mode)
            }
            3 => {
                let mode = mode_for(&SAGA_POINTS);
                let call = s.pool_call(&format!("faults-run-{run}-{}", random(1_000_000)), 1);
                let pda = exercise(&s.api, &call, mode)
                    .await?
                    .expect(201)?
                    .str("pool_pda")?;
                if s.pools_named(&pda).await? != 1 {
                    return Err(format!("run {run}: pool {pda} doesn't have one document"));
                }
                ("pool creation", mode)
            }
            4 | 5 => {
                let mode = mode_for(&["recorded"]);
                let user = s.user(&uuid()).await?;
                let call = s.call(
                    &user,
                    Method::POST,
                    "/v1/wallets".into(),
                    Body::Json(json!({})),
                );
                exercise(&s.api, &call, mode).await?.expect(201)?;
                let wallets = s.api.get("/v1/wallets", &user.token).await?;
                if wallets["wallets"].as_array().map_or(0, Vec::len) != 1 {
                    return Err(format!("run {run}: the user has {wallets}"));
                }
                ("wallet creation", mode)
            }
            6 | 7 => {
                let mode = mode_for(&["tx_stored", "tx_sent", "tx_confirmed", "recorded"]);
                let mut bytes = [0u8; 32];
                OsRng.fill_bytes(&mut bytes);
                let recipient = Pubkey::new_from_array(bytes);
                let call = s.call(
                    &s.owner,
                    Method::POST,
                    format!("/v1/wallets/{}/send", s.wallet_id),
                    Body::Json(
                        json!({ "recipient": recipient.to_string(), "amount": SEND_LAMPORTS }),
                    ),
                );
                exercise(&s.api, &call, mode).await?.expect(200)?;
                let mut received = 0;
                for _ in 0..20 {
                    received = s.solana.rpc().get_balance(&recipient).await.unwrap_or(0);
                    if received > 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                if received != SEND_LAMPORTS {
                    return Err(format!("run {run}: the recipient got {received} lamports"));
                }
                ("send", mode)
            }
            _ => {
                let mode = mode_for(&["recorded"]);
                let log = s
                    .api
                    .get(
                        &format!("/v1/drt/pools/{pool}/issuance-log?limit=200"),
                        &s.owner.token,
                    )
                    .await?;
                let ids: Vec<String> = log["records"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r["record_id"].as_str().map(String::from))
                    .collect();
                let Some(id) = ids.get(random(ids.len().max(1) as u32) as usize) else {
                    return Err(format!("run {run}: the pool has no uploads to revoke"));
                };
                let chosen = vec![id.clone()];
                let call = s.call(
                    &s.owner,
                    Method::POST,
                    format!("/v1/drt/pools/{pool}/revoke"),
                    Body::Json(json!({ "wallet_id": s.wallet_id, "credential_ids": chosen, "reason": "fault suite" })),
                );
                exercise(&s.api, &call, mode).await?.expect(200)?;
                let revocations = s
                    .api
                    .get(
                        &format!("/v1/drt/pools/{pool}/revocations?limit=200"),
                        &s.owner.token,
                    )
                    .await?;
                let listed = revocations["revocations"].as_array().map_or(0, |r| {
                    r.iter().filter(|r| r["credential_id"] == chosen[0]).count()
                });
                if listed != 1 {
                    return Err(format!(
                        "run {run}: {} is revoked {listed} times",
                        chosen[0]
                    ));
                }
                ("revoke", mode)
            }
        };
        println!("    run {run}/{runs}: {name}, {mode:?}");
    }
    Ok(())
}

async fn setup(base: String) -> Result<Suite, String> {
    let lookup = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
    let api = Api {
        http: HttpClient::new().with_timeout(Duration::from_secs(180)),
        base,
    };
    let network = crate::blockchain::types::network_config_from_env();
    let attestation = api.get("/v1/attestation", "").await?;
    let jwk = &attestation["transport_jwk"];
    let coordinate = |name: &str| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk[name].as_str().unwrap_or_default())
            .map_err(|_| format!("the transport key has no {name}"))
    };
    let point = [vec![4], coordinate("x")?, coordinate("y")?].concat();
    let transport =
        p256::PublicKey::from_sec1_bytes(&point).map_err(|_| "the transport key isn't P-256")?;
    let signer = RsaSigner::load(&crate::config::dev_token_key_from_lookup(&lookup))?;
    let mut suite = Suite {
        solana: SolanaClient::new(&network.rpc_url.clone(), network),
        api,
        signer,
        entra: crate::config::entra_from_lookup(&lookup)?,
        owner: User {
            token: String::new(),
            user_id: String::new(),
        },
        wallet_id: String::new(),
        kid: attestation["kid"].as_str().unwrap_or_default().to_string(),
        transport,
    };
    suite.owner = suite.user("d0000000-0000-4000-8000-00000000fa17").await?;

    let wallets = suite.api.get("/v1/wallets", &suite.owner.token).await?;
    let wallet = match wallets["wallets"].as_array().and_then(|w| w.first()) {
        Some(wallet) => wallet.clone(),
        None => {
            let call = suite.call(
                &suite.owner,
                Method::POST,
                "/v1/wallets".into(),
                Body::Json(json!({ "label": "fault suite" })),
            );
            suite.api.settle(&call).await?.expect(201)?.body["wallet"].clone()
        }
    };
    suite.wallet_id = wallet["wallet_id"].as_str().unwrap_or_default().to_string();
    let address = wallet["public_address"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let balance = suite
        .api
        .get(
            &format!("/v1/wallets/{}/balance", suite.wallet_id),
            &suite.owner.token,
        )
        .await?;
    let lamports = balance["balances"]
        .as_array()
        .and_then(|b| b.iter().find(|b| b["token"] == "SOL"))
        .and_then(|b| b["raw_amount"].as_str()?.parse::<u64>().ok())
        .unwrap_or(0);
    if lamports < MIN_LAMPORTS {
        return Err(format!(
            "the suite's wallet {address} holds {lamports} lamports; send it at least {MIN_LAMPORTS} devnet lamports, then run it again"
        ));
    }
    println!(
        "fault suite: wallet {address} holds {} SOL",
        lamports as f64 / 1e9
    );
    Ok(suite)
}

async fn run_inner(args: &[String]) -> Result<(), String> {
    let mut runs = std::env::var("FAULTS_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--runs" => {
                runs = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("--runs needs a number\n\n{USAGE}"))?
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
        }
    }
    let base = std::env::var("FAULTS_API").unwrap_or_else(|_| "http://127.0.0.1:8443".into());
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let s = setup(base).await?;

    let started = Instant::now();
    let mut failures: Vec<String> = Vec::new();
    macro_rules! scenario {
        ($name:expr, $run:expr) => {{
            let name = $name.to_string();
            println!("{name}");
            match $run.await {
                Ok(value) => {
                    println!("  PASS");
                    Some(value)
                }
                Err(e) => {
                    println!("  FAIL: {e}");
                    failures.push(name);
                    None
                }
            }
        }};
    }
    let pool = scenario!("1, 3: replays and a reused key", replays(&s));
    let pool = match pool {
        Some(pool) => pool,
        None => s.initialized_pool("faults-main", 60).await?,
    };
    scenario!("2: concurrent attempts", concurrent(&s, &pool));
    scenario!(
        "4: kills during an issuance",
        kills_during_issuance(&s, &pool)
    );
    scenario!(
        "8: kills during a pool creation",
        kills_during_pool_creation(&s)
    );
    scenario!(
        "5: the reconciler finishes an abandoned issuance",
        reconciler(&s, &pool)
    );
    scenario!("7: two users, one key", two_users_one_key(&s));
    scenario!(
        format!("6: {runs} randomised runs"),
        randomised(&s, &pool, runs)
    );
    println!("fault suite: {} s", started.elapsed().as_secs());
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("failed: {}", failures.join("; ")))
    }
}

/// Run `relational-tee faults`. Returns the exit code.
pub async fn run(args: &[String]) -> i32 {
    match run_inner(args).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
