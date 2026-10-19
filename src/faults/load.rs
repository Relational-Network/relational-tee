// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The load run (dev builds only): `relational-tee load`, which `just load`
//! runs against one worker of the local stack, held to a deployed worker's
//! CPU and memory.
//!
//! It makes a pool of synthetic rows and grants analysts one employer group
//! each. Then, for a while, all at once: clients open and query the analysis
//! as the admin or an analyst, uploaders issue more rows (each upload makes
//! every table build again), and a probe asks `/health/ready` five times a
//! second. It ends with an overload: more slow uploads than the memory
//! budget holds, each declaring the largest body and sending it a byte at a
//! time, so that those the budget can't hold get `503 worker_busy`, while the
//! probe keeps asking.
//!
//! It prints each kind's outcomes and latencies, and fails if a request got
//! anything but an answer or a defined refusal, if a health probe failed or
//! its p99 passed a second, or if the overload got no `503 worker_busy`.
//! `just load` adds the container's peak memory and whether it was killed.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::http::Method;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use super::{random, setup, uuid, Body, Call, Outcome, Suite, User, ANALYSIS, BOUNDARY};
use crate::config::MAX_BODY_SIZE;

const USAGE: &str = "usage: relational-tee load [--seconds N] [--clients N] [--uploaders N]
                           [--rows N] [--upload-rows N] [--analysts N] [--slow N]

Runs the load against LOAD_API (default http://127.0.0.1:8444, the stack's
first worker as `just load` starts it). --seconds sets how long the mixed
load runs (120), --clients the clients opening and querying the analysis
(32), --uploaders the clients issuing --upload-rows rows at a time (2 and
50000), --rows the pool's first upload (100000), --analysts the analysts
granted one employer group each (3), and --slow the slow uploads of the
overload (24). Tokens are signed with the dev token signing key, and the
suite user's wallet needs devnet SOL, as for `relational-tee faults`.";

/// The synthetic rows' employer groups, awards and sortable columns.
const GROUPS: [&str; 8] = [
    "Group A", "Group B", "Group C", "Group D", "Group E", "Group F", "Group G", "Group H",
];
const AWARDS: [&str; 3] = [
    "Award A",
    "Certificate in Subject A",
    "Diploma in Subject B",
];
const SORTS: [&str; 4] = ["staff_number", "surname", "employer", "exam_board_date"];

/// How often the probe asks, and the p99 it must stay under.
const PROBE_EVERY: Duration = Duration::from_millis(200);
const HEALTH_P99_MS: f64 = 1000.0;
/// How long the overload's slow uploads are held: longer than an upload
/// waits for memory before it's refused.
const SLOW_HOLD: Duration = Duration::from_secs(20);

/// Refusals a loaded worker may answer with.
const REFUSALS: [&str; 7] = [
    "503 worker_busy",
    "503 analysis_busy",
    "503 pool_settling",
    "503 rpc_unavailable",
    "422 too_large_for_memory",
    "413 pool_full",
    "409 conflict",
];

struct Options {
    seconds: u64,
    clients: usize,
    uploaders: usize,
    rows: usize,
    upload_rows: usize,
    analysts: usize,
    slow: usize,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self {
            seconds: 120,
            clients: 32,
            uploaders: 2,
            rows: 100_000,
            upload_rows: 50_000,
            analysts: 3,
            slow: 24,
        };
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            if matches!(flag.as_str(), "-h" | "--help") {
                return Err(USAGE.into());
            }
            let value: usize = args
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| format!("{flag} needs a number\n\n{USAGE}"))?;
            match flag.as_str() {
                "--seconds" => options.seconds = value as u64,
                "--clients" => options.clients = value,
                "--uploaders" => options.uploaders = value,
                "--rows" => options.rows = value,
                "--upload-rows" => options.upload_rows = value,
                "--analysts" => options.analysts = value,
                "--slow" => options.slow = value,
                other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
            }
        }
        if options.slow == 0 {
            return Err(format!(
                "--slow must be at least 1: the run checks the overload\n\n{USAGE}"
            ));
        }
        Ok(options)
    }
}

/// `rows` rows in the Awards Report's columns, spread over the employer
/// groups and awards, told apart by `tag`.
fn rows_csv(tag: &str, rows: usize) -> String {
    let mut csv = String::with_capacity(rows * 120 + 200);
    csv.push_str(
        "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,\
         Employer Group,Award,Award Grade,Exam Board Date\n",
    );
    for i in 0..rows {
        let group = GROUPS[i % GROUPS.len()];
        let employer = char::from(b'A' + (i % 16) as u8);
        let award = AWARDS[i % AWARDS.len()];
        let (day, month, year) = (1 + i % 28, 1 + (i / 28) % 12, 2015 + i % 11);
        let _ = writeln!(
            csv,
            "{tag}-{i},{:07},Mx,Sam,Example{},01/01/1990,Bank {employer},{group},{award},Pass,\
             {day:02}/{month:02}/{year}",
            i % 10_000_000,
            i % 97,
        );
    }
    csv
}

/// A reply's status, with its error code if it has one.
fn label(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Reply(r) if r.status < 400 => r.status.to_string(),
        Outcome::Reply(r) => match r.body["code"].as_str() {
            Some(code) => format!("{} {code}", r.status),
            None => r.status.to_string(),
        },
        Outcome::Dropped(_) => "dropped".into(),
    }
}

fn acceptable(label: &str) -> bool {
    label.starts_with('2') || label.starts_with("429") || REFUSALS.contains(&label)
}

/// An error reply's message, for the report.
fn message(outcome: &Outcome) -> Option<String> {
    match outcome {
        Outcome::Reply(r) if r.status >= 400 => r.body["error"].as_str().map(String::from),
        Outcome::Dropped(e) => Some(e.clone()),
        Outcome::Reply(_) => None,
    }
}

#[derive(Default)]
struct Tally {
    outcomes: BTreeMap<String, usize>,
    /// One message of each refusal.
    samples: BTreeMap<String, String>,
    millis: Vec<f64>,
}

/// Every request's outcome and latency, by kind.
#[derive(Clone, Default)]
struct Tallies(Arc<Mutex<BTreeMap<&'static str, Tally>>>);

impl Tallies {
    fn add(&self, kind: &'static str, label: String, took: Duration) {
        self.add_with(kind, label, None, took);
    }

    fn add_with(&self, kind: &'static str, label: String, sample: Option<String>, took: Duration) {
        let mut all = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let tally = all.entry(kind).or_default();
        if let Some(sample) = sample {
            tally.samples.entry(label.clone()).or_insert(sample);
        }
        *tally.outcomes.entry(label).or_default() += 1;
        tally.millis.push(took.as_secs_f64() * 1000.0);
    }

    /// Record `outcome` of a request of `kind` that took `took`.
    fn record(&self, kind: &'static str, outcome: &Outcome, took: Duration) {
        self.add_with(kind, label(outcome), message(outcome), took);
    }

    /// Print each kind, and return what failed.
    fn report(&self) -> Vec<String> {
        let mut all = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mut failed = Vec::new();
        for (kind, tally) in all.iter_mut() {
            tally.millis.sort_by(f64::total_cmp);
            let at = |p: f64| {
                let i = ((tally.millis.len().saturating_sub(1)) as f64 * p).round() as usize;
                tally.millis.get(i).copied().unwrap_or_default()
            };
            println!(
                "  {kind:<12} n={:<6} p50={:>7.1} ms  p95={:>7.1} ms  p99={:>7.1} ms  max={:>8.1} ms  {:?}",
                tally.millis.len(),
                at(0.5),
                at(0.95),
                at(0.99),
                at(1.0),
                tally.outcomes,
            );
            for (label, sample) in &tally.samples {
                let sample: String = sample.chars().take(160).collect();
                println!("      {label}: {sample}");
            }
            let bad: Vec<_> = tally
                .outcomes
                .keys()
                .filter(|label| match *kind {
                    "health" => label.as_str() != "200",
                    "overload" => !matches!(label.as_str(), "held" | "503 worker_busy"),
                    _ => !acceptable(label),
                })
                .cloned()
                .collect();
            if !bad.is_empty() {
                failed.push(format!("{kind} got {bad:?}"));
            }
            if *kind == "health" && at(0.99) > HEALTH_P99_MS {
                failed.push(format!("health's p99 was {:.0} ms", at(0.99)));
            }
            if *kind == "overload" && !tally.outcomes.contains_key("503 worker_busy") {
                failed.push("the overload got no 503 worker_busy".into());
            }
        }
        failed
    }
}

/// The pool, and the users who query it: its owner and each analyst.
struct Target {
    pool: String,
    users: Vec<User>,
}

async fn prepare(s: &Suite, o: &Options) -> Result<Target, String> {
    // More than the uploads can use: the pool's 200 MiB cap stops them first.
    let append = o.seconds * o.uploaders as u64 + 2;
    let name = format!("load-{}", random(1_000_000));
    let create = s.pool_call_with(&name, append, o.analysts as u64 + 1);
    let pool = s.api.settle(&create).await?.expect(201)?.str("pool_pda")?;
    let init = s.upload_call(&pool, "initialize", &rows_csv("init", o.rows));
    s.api.settle(&init).await?.expect(200)?;
    let mut users = vec![s.owner.clone()];
    for i in 0..o.analysts {
        let analyst = s.signed_in(&uuid(), "").await?;
        let group = GROUPS[i % GROUPS.len()];
        let grant = s.grant_call_to(&pool, "grant", &analyst, group);
        s.api.settle(&grant).await?.expect(200)?;
        users.push(analyst);
    }
    println!(
        "load: pool {pool}, {} rows, {} analysts",
        o.rows, o.analysts
    );
    Ok(Target { pool, users })
}

fn health_call() -> Call {
    Call {
        method: Method::GET,
        path: "/health/ready".into(),
        token: String::new(),
        key: None,
        body: Body::Empty,
    }
}

async fn probe(s: Arc<Suite>, stop: Arc<AtomicBool>, tallies: Tallies) {
    let call = health_call();
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let outcome = s.api.send(&call, None).await;
        tallies.record("health", &outcome, started.elapsed());
        tokio::time::sleep(PROBE_EVERY).await;
    }
}

/// A query with random filters, sort and page.
fn random_query() -> Value {
    let mut query = json!({
        "sort": {
            "field": SORTS[random(SORTS.len() as u32) as usize],
            "direction": if random(2) == 0 { "asc" } else { "desc" },
        },
        "pagination": { "limit": 100, "offset": u64::from(random(20)) * 100 },
    });
    if random(2) == 0 {
        let award = AWARDS[random(AWARDS.len() as u32) as usize];
        query["filters"]["award"] = json!({ "mode": "selected", "values": [award] });
    }
    if random(2) == 0 {
        query["filters"]["exam_board_date"] = json!({ "from": "01/01/2018", "to": "31/12/2022" });
    }
    query
}

async fn query(s: Arc<Suite>, target: Arc<Target>, stop: Arc<AtomicBool>, tallies: Tallies) {
    let pool = &target.pool;
    while !stop.load(Ordering::Relaxed) {
        let Some(user) = target.users.get(random(target.users.len() as u32) as usize) else {
            return;
        };
        let (kind, call) = if random(10) < 3 {
            let path = format!("/v1/drt/pools/{pool}/analyses/{ANALYSIS}?include=page");
            let call = Call {
                method: Method::GET,
                path,
                token: user.token.clone(),
                key: None,
                body: Body::Empty,
            };
            ("open", call)
        } else {
            let call = Call {
                method: Method::POST,
                path: format!("/v1/drt/pools/{pool}/analyses/{ANALYSIS}/query"),
                token: user.token.clone(),
                key: None,
                body: Body::Json(random_query()),
            };
            ("query", call)
        };
        let started = Instant::now();
        let outcome = s.api.send(&call, None).await;
        tallies.record(kind, &outcome, started.elapsed());
        if let Outcome::Reply(r) = &outcome {
            if let Some(secs) = r.retry_after {
                tokio::time::sleep(Duration::from_secs(secs.min(5))).await;
            }
        }
    }
}

async fn upload(
    s: Arc<Suite>,
    target: Arc<Target>,
    rows: usize,
    stop: Arc<AtomicBool>,
    tallies: Tallies,
) {
    let mut n = 0;
    while !stop.load(Ordering::Relaxed) {
        n += 1;
        let tag = format!("u{}-{n}", random(1_000_000));
        let call = s.upload_call(&target.pool, "issue", &rows_csv(&tag, rows));
        let started = Instant::now();
        let outcome = s.api.send(&call, None).await;
        let label = label(&outcome);
        tallies.record("upload", &outcome, started.elapsed());
        if label == "413 pool_full" {
            return;
        }
        if let Outcome::Reply(r) = &outcome {
            if let Some(secs) = r.retry_after {
                tokio::time::sleep(Duration::from_secs(secs.min(5))).await;
            }
        }
    }
}

/// Read a response's start until its error code shows, the connection
/// ends, or 4 KiB have come.
async fn read_answer(reader: &mut OwnedReadHalf) -> Vec<u8> {
    let mut answer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = match answer.is_empty() {
            true => reader.read(&mut chunk).await,
            false => {
                match tokio::time::timeout(Duration::from_secs(2), reader.read(&mut chunk)).await {
                    Ok(read) => read,
                    Err(_) => return answer,
                }
            }
        };
        match read {
            Ok(n) if n > 0 => answer.extend(chunk.iter().take(n)),
            _ => return answer,
        }
        let text = String::from_utf8_lossy(&answer);
        if answer.len() >= 4096 || text.contains("\"code\":\"") {
            return answer;
        }
    }
}

/// The status and error code of a raw HTTP/1.1 response.
fn raw_label(answer: &[u8]) -> String {
    let text = String::from_utf8_lossy(answer);
    let status = text.split_whitespace().nth(1).unwrap_or("dropped");
    match text
        .split_once("\"code\":\"")
        .and_then(|(_, rest)| rest.split('"').next())
    {
        Some(code) => format!("{status} {code}"),
        None => status.to_string(),
    }
}

/// An issuance that declares the largest body and sends it a byte every
/// half second: an upload the budget holds memory for until it's done. Its
/// label is the worker's answer, or `held` if it had none within
/// [`SLOW_HOLD`].
async fn slow_upload(
    address: String,
    host: String,
    path: String,
    token: String,
    kid: String,
) -> String {
    let Ok(stream) = TcpStream::connect(&address).await else {
        return "dropped".into();
    };
    let (mut reader, mut writer) = stream.into_split();
    let part = |name: &str, value: &str| {
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
    };
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n\
         Idempotency-Key: {}\r\nContent-Type: multipart/form-data; boundary={BOUNDARY}\r\n\
         Content-Length: {MAX_BODY_SIZE}\r\n\r\n{}{}{}--{BOUNDARY}\r\nContent-Disposition: \
         form-data; name=\"ct\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        uuid(),
        part("v", "1"),
        part("kid", &kid),
        part("enc", "AAAA"),
    );
    if writer.write_all(head.as_bytes()).await.is_err() {
        return "dropped".into();
    }
    let trickle = async {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if writer.write_all(b"a").await.is_err() {
                return;
            }
        }
    };
    tokio::select! {
        answer = read_answer(&mut reader) => raw_label(&answer),
        () = trickle => "dropped".into(),
        () = tokio::time::sleep(SLOW_HOLD) => "held".into(),
    }
}

/// `slow` slow uploads at once, through the API's address.
async fn overload(
    s: &Suite,
    target: &Target,
    slow: usize,
    tallies: &Tallies,
) -> Result<(), String> {
    let authority = s
        .api
        .base
        .strip_prefix("http://")
        .ok_or("the overload needs plain HTTP, as the local stack serves")?
        .trim_end_matches('/')
        .to_string();
    let path = format!("/v1/drt/pools/{}/issue", target.pool);
    let mut uploads = JoinSet::new();
    for _ in 0..slow {
        let (address, host, path) = (authority.clone(), authority.clone(), path.clone());
        let (token, kid) = (s.owner.token.clone(), s.kid.clone());
        let tallies = tallies.clone();
        uploads.spawn(async move {
            let started = Instant::now();
            let label = slow_upload(address, host, path, token, kid).await;
            tallies.add("overload", label, started.elapsed());
        });
    }
    while uploads.join_next().await.is_some() {}
    Ok(())
}

async fn run_inner(args: &[String]) -> Result<(), String> {
    let o = Options::parse(args)?;
    let base = std::env::var("LOAD_API").unwrap_or_else(|_| "http://127.0.0.1:8444".into());
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let s = Arc::new(setup(base).await?);
    let target = Arc::new(prepare(&s, &o).await?);
    let tallies = Tallies::default();

    let stop = Arc::new(AtomicBool::new(false));
    let mut tasks = JoinSet::new();
    tasks.spawn(probe(s.clone(), stop.clone(), tallies.clone()));
    for _ in 0..o.clients {
        tasks.spawn(query(
            s.clone(),
            target.clone(),
            stop.clone(),
            tallies.clone(),
        ));
    }
    for _ in 0..o.uploaders {
        let task = upload(
            s.clone(),
            target.clone(),
            o.upload_rows,
            stop.clone(),
            tallies.clone(),
        );
        tasks.spawn(task);
    }
    println!(
        "load: {} s of {} clients querying and {} uploading {} rows at a time",
        o.seconds, o.clients, o.uploaders, o.upload_rows
    );
    tokio::time::sleep(Duration::from_secs(o.seconds)).await;

    // The overload, with the probe still asking; the other clients stop.
    let probe_stop = Arc::new(AtomicBool::new(false));
    stop.store(true, Ordering::Relaxed);
    let probing = tokio::spawn(probe(s.clone(), probe_stop.clone(), tallies.clone()));
    while tasks.join_next().await.is_some() {}
    println!(
        "load: {} slow uploads of {} MiB each",
        o.slow,
        MAX_BODY_SIZE >> 20
    );
    overload(&s, &target, o.slow, &tallies).await?;
    probe_stop.store(true, Ordering::Relaxed);
    let _ = probing.await;

    println!("load: results");
    let failed = tallies.report();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("failed: {}", failed.join("; ")))
    }
}

/// Run `relational-tee load`. Returns the exit code.
pub async fn run(args: &[String]) -> i32 {
    match run_inner(args).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
