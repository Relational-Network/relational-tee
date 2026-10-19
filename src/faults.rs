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
//! Every check reads effects back through the API or Solana: append and
//! Execute DRTs burned, issuance entries, grants, pool documents, wallets,
//! transfers, revocations and each pool's on-chain counter. Chain steps run
//! on devnet, so the suite user's wallet needs devnet SOL; the suite stops at
//! once, naming the address, if it has too little.
//!
//! With `FAULTS_TOKEN` set it runs against a deployment instead: as the
//! token's user, with no kills (release builds can't inject faults), and
//! without what needs users made up on the spot (wallet creation, two users
//! with one key). Grants then go to the existing user `FAULTS_ANALYST_USER_ID`.
//!
//! A transfer whose transaction no node reports any more isn't here: devnet
//! can't be made to forget one, so the fake chain's unit tests cover it
//! (`chain::tests::an_expired_transfer_that_no_node_reports_is_judged_by_its_receipt`).

use std::time::{Duration, Instant};

use axum::http::{header, Method, Request};
use bytes::Bytes;
use http_body_util::Full;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;

use crate::blockchain::counter::{self, counter_address};
use crate::blockchain::SolanaClient;
use crate::http_client::HttpClient;
use crate::seal;
use crate::tee::dev_rsa::RsaSigner;

const USAGE: &str = "usage: relational-tee faults [--runs N]

Runs the idempotency fault-injection suite against FAULTS_API (default
http://127.0.0.1:8443), the local stack started with FAULT_INJECTION=on
(`just faults` starts it). --runs sets the randomised runs (default 20; the
acceptance run is 100). Tokens are signed with the dev token signing key.

With FAULTS_TOKEN (an access token for FAULTS_API's API, from a user with
the Admin role) it runs against a deployment as that user, with no kills and
no users made up: replays, concurrent attempts, a reused key, and randomised
runs. Grants go to FAULTS_ANALYST_USER_ID, a user the deployment knows; without
it, the randomised runs make no grants.";

/// The local runs' suite user.
const OWNER_OID: &str = "d0000000-0000-4000-8000-00000000fa17";

/// The suite user's wallet must hold at least this much devnet SOL.
const MIN_LAMPORTS: u64 = 200_000_000;
/// Each randomised send moves this much to a fresh address, enough for the
/// address to exist.
const SEND_LAMPORTS: u64 = 1_000_000;
const BOUNDARY: &str = "fault-suite-boundary";

/// The saga steps a pool creation or an issuance can crash after.
const SAGA_POINTS: [&str; 5] = ["staged", "tx_stored", "tx_sent", "tx_confirmed", "recorded"];

/// Every pool's analysis, which the stack's workers fetch from GitHub, so
/// `main` must hold this file as it is here.
const AWARDS_REPORT_URL: &str = "https://raw.githubusercontent.com/relational-network/\
    relational-tee/main/drt-examples/awards-report/awards-report-v1.toml";
const AWARDS_REPORT: &str = include_str!("../drt-examples/awards-report/awards-report-v1.toml");
/// Its Execute DRT's name.
const ANALYSIS: &str = "awards-report-v1";

/// A one-row upload in the Awards Report's columns, told apart by `staff`.
fn awards_csv(staff: &str) -> String {
    format!(
        "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,\
         Employer Group,Award,Award Grade,Exam Board Date\n\
         {staff},0100045,Mx,Sam,Example,01/01/1990,Bank A,Group A,Certificate,Pass,01/06/2026\n"
    )
}

/// Two rows, one in each employer group, told apart by `staff`.
fn two_groups_csv() -> String {
    "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,\
     Employer Group,Award,Award Grade,Exam Board Date\n\
     group-a,0100045,Mx,Sam,Example,01/01/1990,Bank A,Group A,Certificate,Pass,01/06/2026\n\
     group-b,0100046,Mx,Alex,Alpha,02/02/1991,Bank B,Group B,Certificate,Pass,01/06/2026\n"
        .into()
}

/// The staff numbers of a page's rows.
fn staff(page: &Reply) -> Vec<String> {
    page.body["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["staff_number"].as_str().map(String::from))
        .collect()
}

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
    /// `Retry-After`, in seconds.
    retry_after: Option<u64>,
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
                retry_after: response.header("retry-after").and_then(|v| v.parse().ok()),
                body: serde_json::from_slice(response.body()).unwrap_or(Value::Null),
            }),
            Err(e) => Outcome::Dropped(e.to_string()),
        }
    }

    /// Send until a worker gives a final answer, as a client retries: after
    /// a dropped connection, a request that ran out of time, a 502 or 503,
    /// or a lost compare-and-swap. The wait grows, because devnet's public
    /// RPC rate-limits bursts. A `429` from the edge's per-address limit
    /// waits as long as its `Retry-After` asks, up to a minute.
    async fn settle(&self, call: &Call) -> Result<Reply, String> {
        let mut last = String::new();
        let mut wait = Duration::from_millis(1500);
        for _ in 0..40 {
            match self.send(call, None).await {
                Outcome::Reply(r) if r.status == 429 => {
                    let asked = r.retry_after.unwrap_or(5).clamp(1, 60);
                    last = format!("429 {}", r.body);
                    tokio::time::sleep(Duration::from_secs(asked)).await;
                    continue;
                }
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
    matches!(reply.status, 408 | 502 | 503)
        || (reply.status == 409 && reply.body["code"] == "conflict")
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn random(below: u32) -> u32 {
    OsRng.next_u32() % below
}

#[derive(Clone)]
struct User {
    token: String,
    user_id: String,
}

/// Signs dev tokens for the users the suite makes up (local runs only).
struct Minter {
    signer: RsaSigner,
    entra: crate::config::EntraConfig,
}

/// The suite user's wallet and pool, and the stack's transport key.
struct Suite {
    api: Api,
    solana: SolanaClient,
    /// `None` against a deployment, where the suite has only the users it's
    /// given and makes no kills.
    minter: Option<Minter>,
    owner: User,
    /// The owner's wallet address, which mints each pool's counter.
    owner_address: Pubkey,
    wallet_id: String,
    /// Against a deployment, the user grants go to.
    analyst: Option<User>,
    kid: String,
    transport: p256::PublicKey,
}

impl Suite {
    /// Whether the suite runs against a deployment, with no kills.
    fn deployed(&self) -> bool {
        self.minter.is_none()
    }

    /// How to send a randomised run's request: once, twice, two at once,
    /// or, on the local stack, crashing at one of `points` and retrying.
    fn mode(&self, points: &[&'static str]) -> Mode {
        let modes = if self.deployed() { 3 } else { 4 };
        match random(modes) {
            0 => Mode::Once,
            1 => Mode::Twice,
            2 => Mode::Together,
            _ => Mode::Crash(points[random(points.len() as u32) as usize]),
        }
    }

    async fn user(&self, oid: &str) -> Result<User, String> {
        self.signed_in(oid, "Admin").await
    }

    async fn signed_in(&self, oid: &str, role: &str) -> Result<User, String> {
        let minter = self
            .minter
            .as_ref()
            .ok_or("against a deployment the suite can't make up users")?;
        let mut spec = crate::auth::entra::mint::Spec::valid(&minter.entra);
        spec.oid = oid.into();
        spec.roles = [role]
            .into_iter()
            .filter(|r| !r.is_empty())
            .map(String::from)
            .collect();
        spec.email = Some(format!("{oid}@faults.invalid"));
        spec.name = Some("Fault suite".into());
        let token = spec.sign(&minter.signer)?;
        self.signed_in_as(token).await
    }

    async fn signed_in_as(&self, token: String) -> Result<User, String> {
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

    /// A pool creation for the owner's wallet, with the Awards Report.
    fn pool_call(&self, name: &str, supply: u64) -> Call {
        self.pool_call_with(name, supply, 1)
    }

    fn pool_call_with(&self, name: &str, supply: u64, execute_supply: u64) -> Call {
        let body = json!({
            "wallet_id": self.wallet_id,
            "pool_name": name,
            "append_supply": supply,
            "analysis": {
                "code_repo_url": AWARDS_REPORT_URL,
                "code_hash_hex": hex::encode(Sha256::digest(AWARDS_REPORT)),
                "supply": execute_supply,
            },
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

    /// The pool's unburned append DRTs, read from Solana by the suite itself
    /// rather than through the workers it checks.
    async fn remaining(&self, pool: &str) -> Result<u64, String> {
        self.remaining_of(pool, "append").await
    }

    async fn remaining_of(&self, pool: &str, drt: &str) -> Result<u64, String> {
        let summary = self
            .api
            .get(&format!("/v1/drt/pools/{pool}/summary"), &self.owner.token)
            .await?;
        let mint = summary["drts"]
            .as_array()
            .and_then(|drts| drts.iter().find(|d| d["drt_type"] == drt))
            .and_then(|d| d["mint"].as_str()?.parse::<Pubkey>().ok())
            .ok_or_else(|| format!("the summary has no {drt} mint: {summary}"))?;
        let mut last = String::new();
        for _ in 0..15 {
            match self.solana.rpc().get_token_supply(&mint).await {
                Ok(supply) => {
                    return supply.amount.parse().map_err(|_| {
                        format!("the mint's supply isn't a number: {}", supply.amount)
                    })
                }
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(format!("reading the {drt} mint's supply: {last}"))
    }

    /// The pool's grants, newest first.
    async fn grant_list(&self, pool: &str) -> Result<Vec<Value>, String> {
        let grants = self
            .api
            .get(&format!("/v1/drt/pools/{pool}/grants"), &self.owner.token)
            .await?;
        Ok(grants["grants"].as_array().cloned().unwrap_or_default())
    }

    /// One of the pool's grants, as `GET …/grants` lists it.
    async fn grant_entry(&self, pool: &str, grant_id: &str) -> Result<Value, String> {
        self.grant_list(pool)
            .await?
            .into_iter()
            .find(|g| g["grant_id"] == grant_id)
            .ok_or_else(|| format!("pool {pool} lists no grant {grant_id}"))
    }

    /// The pool's grants to `analyst`, by status.
    async fn grants_of(&self, pool: &str, analyst: &User) -> Result<Vec<String>, String> {
        Ok(self
            .grant_list(pool)
            .await?
            .iter()
            .filter(|g| g["analyst_user_id"] == analyst.user_id.as_str())
            .filter_map(|g| g["status"].as_str().map(String::from))
            .collect())
    }

    /// The pool's generation as its on-chain counter shows it, read by the
    /// suite itself.
    async fn counter(&self, pool: &str) -> Result<u64, String> {
        let address = counter_address(&self.owner_address, pool).map_err(|e| e.message)?;
        let mut last = String::new();
        for _ in 0..15 {
            match self.solana.rpc().get_account(&address, "confirmed").await {
                Ok(account) => return counter::generation(account.as_ref(), &self.owner_address),
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(format!("reading the pool's counter: {last}"))
    }

    /// An edit of `grant`'s targets to employer group `group`, from the
    /// revision it lists.
    fn scope_call(&self, pool: &str, grant: &Value, group: &str) -> Call {
        let body = json!({
            "grant_id": grant["grant_id"],
            "analyst_user_id": grant["analyst_user_id"],
            "analysis_id": ANALYSIS,
            "revision": grant["scope_revision"],
            "scope": [{ "key": "employer_group", "value": group }],
        });
        self.call(
            &self.owner,
            Method::POST,
            format!("/v1/drt/pools/{pool}/grant-scope"),
            Body::Json(body),
        )
    }

    /// The revocation of `grant_id`, the grant of `analyst`.
    fn revoke_grant_call(&self, pool: &str, analyst: &User, grant_id: &str) -> Call {
        let mut call = self.grant_call(pool, "revoke-grant", analyst);
        if let Body::Json(body) = &mut call.body {
            body["grant_id"] = json!(grant_id);
        }
        call
    }

    /// The analysis's first page, as `analyst` sees it.
    fn query_call(&self, pool: &str, analyst: &User) -> Call {
        Call {
            method: Method::POST,
            path: format!("/v1/drt/pools/{pool}/analyses/{ANALYSIS}/query"),
            token: analyst.token.clone(),
            key: None,
            body: Body::Json(json!({})),
        }
    }

    fn grant_call(&self, pool: &str, route: &str, analyst: &User) -> Call {
        // The synthetic fixture's employer group.
        self.grant_call_to(pool, route, analyst, "Group A")
    }

    /// `route` for `analyst`; a grant gives them employer group `group`.
    fn grant_call_to(&self, pool: &str, route: &str, analyst: &User, group: &str) -> Call {
        let mut body = json!({ "analyst_user_id": analyst.user_id, "analysis_id": ANALYSIS });
        if route == "grant" {
            body["scope"] = json!([{ "key": "employer_group", "value": group }]);
        }
        self.call(
            &self.owner,
            Method::POST,
            format!("/v1/drt/pools/{pool}/{route}"),
            Body::Json(body),
        )
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
        let init = self.upload_call(&pool, "initialize", &awards_csv("seed"));
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

    let init = s.upload_call(&pool, "initialize", &awards_csv("seed"));
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
        return Err(format!(
            "the append DRTs went from {before} to {after}, not down by 1"
        ));
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
    let call = s.upload_call(pool, "issue", &awards_csv("concurrent"));
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
        let call = s.upload_call(pool, "issue", &awards_csv(point));
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
    let call = s.upload_call(pool, "issue", &awards_csv("abandoned"));
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

/// Criterion 9: a worker killed after each saga step of a grant, and the
/// request retried on another, burns one Execute DRT and records one active
/// grant; a revocation killed the same way ends that grant and burns
/// nothing.
async fn kills_during_grants(s: &Suite) -> Result<(), String> {
    let name = format!("faults-grants-{}", random(1_000_000));
    let create = s.pool_call_with(&name, 1, SAGA_POINTS.len() as u64);
    let pool = s.api.settle(&create).await?.expect(201)?.str("pool_pda")?;
    for point in SAGA_POINTS {
        // Analysts need no app role.
        let analyst = s.signed_in(&uuid(), "").await?;
        let before = s.remaining_of(&pool, ANALYSIS).await?;
        let grant = s.grant_call(&pool, "grant", &analyst);
        s.api.crash(&grant, point).await?;
        s.api.settle(&grant).await?.expect(200)?;
        let after = s.remaining_of(&pool, ANALYSIS).await?;
        if after + 1 != before {
            return Err(format!(
                "after {point}: the Execute DRTs went from {before} to {after}, not down by 1"
            ));
        }
        let grants = s.grants_of(&pool, &analyst).await?;
        if grants != ["active"] {
            return Err(format!(
                "after {point}: the analyst's grants are {grants:?}"
            ));
        }

        let revoke = s.grant_call(&pool, "revoke-grant", &analyst);
        s.api.crash(&revoke, point).await?;
        let revoked = s.api.settle(&revoke).await?.expect(200)?;
        if revoked.body["status"] != "revoked" {
            return Err(format!(
                "after {point}: the revocation left {}",
                revoked.body
            ));
        }
        if s.remaining_of(&pool, ANALYSIS).await? != after {
            return Err(format!("after {point}: the revocation burned a DRT"));
        }
        let grants = s.grants_of(&pool, &analyst).await?;
        if grants != ["revoked"] {
            return Err(format!(
                "after {point}: the analyst's grants are {grants:?}"
            ));
        }
        println!("    killed after {point}: one burn, one grant, revoked once");
    }
    Ok(())
}

/// Scenario 10: a scope edit killed after storing its anchor, with no
/// retry. The edit is in the pool's document but not yet on its counter, so
/// the analyst gets `503 pool_settling`, never the old rows, until a worker
/// or the reconciler lands the counter's mint; then the new rows. The
/// counter rises by one, and a late retry of the edit mints nothing more.
async fn unlanded_anchor(s: &Suite) -> Result<(), String> {
    let name = format!("faults-anchor-{}", random(1_000_000));
    let pool = s
        .api
        .settle(&s.pool_call(&name, 2))
        .await?
        .expect(201)?
        .str("pool_pda")?;
    let init = s.upload_call(&pool, "initialize", &two_groups_csv());
    s.api.settle(&init).await?.expect(200)?;
    let analyst = s.signed_in(&uuid(), "").await?;
    let grant = s
        .api
        .settle(&s.grant_call(&pool, "grant", &analyst))
        .await?
        .expect(200)?;
    let query = s.query_call(&pool, &analyst);
    let rows = staff(&s.api.settle(&query).await?.expect(200)?);
    if rows != ["group-a"] {
        return Err(format!("before the edit the analyst sees {rows:?}"));
    }
    let before = s.counter(&pool).await?;

    let edit = s.scope_call(&pool, &grant.body, "Group B");
    let grant_id = grant.str("grant_id")?;
    // A 503 can also be a refusal before anything was written, such as the
    // RPC's rate limit: send the edit until its document shows it.
    let mut written = false;
    for attempt in 0..5 {
        if attempt > 0 {
            // Past devnet's rate-limit window.
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        match s.api.send(&edit, Some("tx_stored")).await {
            Outcome::Reply(r) if r.status == 429 => {
                let asked = r.retry_after.unwrap_or(5).clamp(1, 60);
                tokio::time::sleep(Duration::from_secs(asked)).await;
                continue;
            }
            Outcome::Reply(r) if r.status != 502 && r.status != 503 => {
                return Err(format!(
                    "the worker didn't exit at tx_stored: {} {}",
                    r.status, r.body
                ));
            }
            _ => {}
        }
        if s.grant_entry(&pool, &grant_id).await?["scope_revision"] == 2 {
            written = true;
            break;
        }
    }
    if !written {
        return Err("the edit was never written before its anchor".into());
    }
    let started = Instant::now();
    let mut settling = 0;
    loop {
        if started.elapsed() > Duration::from_secs(15 * 60) {
            return Err("the analyst didn't see the new rows within 15 minutes".into());
        }
        match s.api.send(&query, None).await {
            Outcome::Reply(r) if r.status == 503 && r.body["code"] == "pool_settling" => {
                settling += 1
            }
            Outcome::Reply(r) if r.status == 200 => match staff(&r).as_slice() {
                [only] if only == "group-b" => break,
                rows => {
                    return Err(format!(
                        "with the edit written, the analyst was shown {rows:?}"
                    ))
                }
            },
            // A worker restarting, or the RPC refusing a burst.
            Outcome::Reply(r) if retryable(&r) || r.status == 429 => {}
            Outcome::Reply(r) => return Err(format!("the analyst got {} {}", r.status, r.body)),
            Outcome::Dropped(_) => {}
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!(
        "    {settling} answers of 503 pool_settling, then the new rows after {} s",
        started.elapsed().as_secs()
    );
    let after = s.counter(&pool).await?;
    if after != before + 1 {
        return Err(format!(
            "the counter went from {before} to {after}, not up by 1"
        ));
    }
    let retried = s.api.settle(&edit).await?.expect(200)?;
    if retried.body["scope_revision"] != 2 {
        return Err(format!("the retried edit left {}", retried.body));
    }
    if s.counter(&pool).await? != after {
        return Err("the retried edit minted the counter again".into());
    }
    Ok(())
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

/// The randomised runs' grants: a pool of their own, made at the first
/// grant run with an Execute DRT for every run, its analysts, and every grant
/// they revoked.
#[derive(Default)]
struct GrantRuns {
    pool: Option<String>,
    /// Each analyst, with their active grant's ID while they have one.
    analysts: Vec<(User, Option<String>)>,
    revoked: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum GrantOp {
    Grant,
    Scope(usize),
    Revoke(usize),
}

/// One randomised run of a grant (`op` 10), a scope edit (11) or a grant
/// revocation (12), checking that a grant burns one Execute DRT and leaves
/// its analyst one active grant, an edit moves the revision by exactly one
/// and burns nothing, a revocation burns nothing, and no revoked grant comes
/// back. An edit or revocation with no active grant to act on grants instead,
/// as does a grant against a deployment whose one analyst has none.
async fn grant_run(
    s: &Suite,
    g: &mut GrantRuns,
    runs: u32,
    op: u32,
) -> Result<(&'static str, Mode), String> {
    if g.pool.is_none() {
        let name = format!("faults-grant-runs-{}", random(1_000_000));
        let call = s.pool_call_with(&name, 1, u64::from(runs));
        g.pool = Some(s.api.settle(&call).await?.expect(201)?.str("pool_pda")?);
        if let Some(analyst) = &s.analyst {
            g.analysts.push((analyst.clone(), None));
        }
    }
    let pool = g.pool.clone().unwrap_or_default();
    let active = g.analysts.iter().position(|(_, grant)| grant.is_some());
    let idle = g.analysts.iter().position(|(_, grant)| grant.is_none());
    let can_grant = !s.deployed() || idle.is_some();
    let kind = match (op, active) {
        (_, None) => GrantOp::Grant,
        (10, Some(_)) if can_grant => GrantOp::Grant,
        (10 | 11, Some(i)) => GrantOp::Scope(i),
        (_, Some(i)) => GrantOp::Revoke(i),
    };
    let mode = s.mode(&SAGA_POINTS);
    let before = s.remaining_of(&pool, ANALYSIS).await?;
    let name = match kind {
        GrantOp::Grant => {
            let i = match idle {
                Some(i) if s.deployed() => i,
                _ => {
                    // Analysts need no app role.
                    g.analysts.push((s.signed_in(&uuid(), "").await?, None));
                    g.analysts.len() - 1
                }
            };
            let analyst = g.analysts[i].0.clone();
            let call = s.grant_call(&pool, "grant", &analyst);
            let grant_id = exercise(&s.api, &call, mode)
                .await?
                .expect(200)?
                .str("grant_id")?;
            let after = s.remaining_of(&pool, ANALYSIS).await?;
            if after + 1 != before {
                return Err(format!(
                    "the Execute DRTs went from {before} to {after}, not down by 1"
                ));
            }
            let grants = s.grants_of(&pool, &analyst).await?;
            if grants.iter().filter(|status| *status == "active").count() != 1 {
                return Err(format!("the analyst's grants are {grants:?}"));
            }
            g.analysts[i].1 = Some(grant_id);
            "grant"
        }
        GrantOp::Scope(i) => {
            let grant_id = g.analysts[i].1.clone().unwrap_or_default();
            let grant = s.grant_entry(&pool, &grant_id).await?;
            let revision = grant["scope_revision"].as_u64().unwrap_or_default();
            let group = if grant["scope"][0]["value"] == "Group A" {
                "Group B"
            } else {
                "Group A"
            };
            let call = s.scope_call(&pool, &grant, group);
            exercise(&s.api, &call, mode).await?.expect(200)?;
            let edited = s.grant_entry(&pool, &grant_id).await?;
            if edited["scope_revision"] != revision + 1 || edited["scope"][0]["value"] != group {
                return Err(format!(
                    "an edit from revision {revision} to {group} left {edited}"
                ));
            }
            if s.remaining_of(&pool, ANALYSIS).await? != before {
                return Err("a scope edit burned an Execute DRT".into());
            }
            "scope edit"
        }
        GrantOp::Revoke(i) => {
            let (analyst, grant_id) = (&g.analysts[i].0, g.analysts[i].1.clone());
            let grant_id = grant_id.unwrap_or_default();
            let call = s.revoke_grant_call(&pool, analyst, &grant_id);
            let revoked = exercise(&s.api, &call, mode).await?.expect(200)?;
            if revoked.body["status"] != "revoked" {
                return Err(format!("the revocation left {}", revoked.body));
            }
            if s.remaining_of(&pool, ANALYSIS).await? != before {
                return Err("a revocation burned an Execute DRT".into());
            }
            g.analysts[i].1 = None;
            g.revoked.push(grant_id);
            "grant revocation"
        }
    };
    let grants = s.grant_list(&pool).await?;
    for id in &g.revoked {
        let status = grants
            .iter()
            .find(|e| e["grant_id"] == id.as_str())
            .map(|e| e["status"].clone());
        if status != Some(json!("revoked")) {
            return Err(format!("revoked grant {id} is now {status:?}"));
        }
    }
    Ok((name, mode))
}

/// Criterion 6: randomised runs across issue, pool creation, wallet
/// creation, send, credential revocation, grants, scope edits and grant
/// revocations, with duplicates, concurrent attempts and crashes, checking
/// after each that there's no double burn, double transfer, lost update,
/// second wallet or undone revocation.
async fn randomised(s: &Suite, pool: &str, runs: u32) -> Result<(), String> {
    let mut grants = GrantRuns::default();
    for run in 1..=runs {
        let op = loop {
            let op = random(13);
            let skipped =
                s.deployed() && (matches!(op, 4 | 5) || (op >= 10 && s.analyst.is_none()));
            if !skipped {
                break op;
            }
        };
        let (name, mode) = match op {
            0..=2 => {
                let mode = s.mode(&SAGA_POINTS);
                let before = s.remaining(pool).await?;
                let call = s.upload_call(pool, "issue", &awards_csv(&format!("run{run}")));
                exercise(&s.api, &call, mode).await?.expect(200)?;
                issued_once(s, pool, &call, before).await?;
                ("issue", mode)
            }
            3 => {
                let mode = s.mode(&SAGA_POINTS);
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
                let mode = s.mode(&["recorded"]);
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
                let mode = s.mode(&["tx_stored", "tx_sent", "tx_confirmed", "recorded"]);
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
            10..=12 => grant_run(s, &mut grants, runs, op)
                .await
                .map_err(|e| format!("run {run}: {e}"))?,
            _ => {
                let mode = s.mode(&["recorded"]);
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

/// The suite against the stack at `base`: its transport key from the
/// attestation, the owner signed in with a dev token (or `FAULTS_TOKEN`'s
/// user), and the owner's wallet, made if there's none.
async fn setup(base: String) -> Result<Suite, String> {
    let lookup = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
    let api = Api {
        http: HttpClient::new()
            .with_timeout(Duration::from_secs(180))
            .with_max_body(64 << 20),
        base,
    };
    let network = crate::config::solana_from_lookup(&lookup)?;
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
    let token = lookup("FAULTS_TOKEN");
    let minter = match token {
        Some(_) => None,
        None => Some(Minter {
            signer: RsaSigner::load(&crate::config::dev_token_key_from_lookup(&lookup))?,
            entra: crate::config::entra_from_lookup(&lookup)?,
        }),
    };
    let mut suite = Suite {
        solana: SolanaClient::new(&network.rpc_url.clone(), network),
        api,
        minter,
        owner: User {
            token: String::new(),
            user_id: String::new(),
        },
        owner_address: Pubkey::default(),
        wallet_id: String::new(),
        analyst: None,
        kid: attestation["kid"].as_str().unwrap_or_default().to_string(),
        transport,
    };
    suite.owner = match token {
        Some(token) => suite.signed_in_as(token).await?,
        None => suite.user(OWNER_OID).await?,
    };
    if suite.deployed() {
        suite.analyst = lookup("FAULTS_ANALYST_USER_ID").map(|user_id| User {
            token: String::new(),
            user_id,
        });
    }

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
    suite.owner_address = address
        .parse()
        .map_err(|_| format!("the suite's wallet has no valid address: {wallet}"))?;
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
    if s.deployed() {
        println!("4, 5, 7, 8, 9, 10: skipped against a deployment (kills, made-up users)");
        if s.analyst.is_none() {
            println!("6: no FAULTS_ANALYST_USER_ID, so the randomised runs make no grants");
        }
    } else {
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
            "9: kills during a grant and its revocation",
            kills_during_grants(&s)
        );
        scenario!(
            "10: a scope edit whose anchor hasn't landed",
            unlanded_anchor(&s)
        );
    }
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
