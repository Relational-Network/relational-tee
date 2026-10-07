// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential issuance, revocation, and pool discovery endpoints.
//!
//! Everything here reads or changes the pool document (see
//! [`crate::storage::pools`]).

pub mod initialize;
pub mod issue;
pub mod reads;
pub mod revoke;
pub mod schema;

use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use std::str::FromStr;

use crate::error::ApiError;

// ============================================================================
// Helpers
// ============================================================================

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Decode a 32-char hex string into 16 raw bytes. Used for right_id and pool_uuid.
pub(crate) fn decode_right_id(hex: &str) -> Result<[u8; 16], ApiError> {
    if hex.len() != 32 {
        return Err(ApiError::internal("expected 32-char hex (16 bytes)"));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ApiError::internal("invalid hex in 16-byte id"))?;
    }
    Ok(out)
}

/// Count CSV rows (excluding header).
fn count_csv_rows(csv_bytes: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(csv_bytes);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() > 1 {
        (lines.len() - 1) as u64 // subtract header
    } else {
        0
    }
}

fn validation_failed(errors: usize) -> ApiError {
    ApiError::bad_request(format!("CSV validation failed: {errors} error(s)"))
        .with_code("validation_failed")
}

pub(crate) fn pool_not_found(pool_pda: &str) -> ApiError {
    ApiError::not_found(format!("pool metadata not found for {pool_pda}"))
}

pub(crate) fn parse_pda(pool_pda: &str) -> Result<Pubkey, ApiError> {
    Pubkey::from_str(pool_pda).map_err(|_| ApiError::bad_request("invalid pool PDA address"))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Instant;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, HeaderMap, Request, StatusCode};
    use axum::Router;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::entra::mint::Spec;
    use crate::auth::entra::tests::{config, entra_key};
    use crate::blockchain::drt::pda::{derive_grant_pda, derive_user_ata, Commitments};
    use crate::blockchain::drt::types::{Pool, APPEND_DRT_NAME, DISC_POOL_ACCOUNT};
    use crate::blockchain::fake::{self, FakeChain};
    use crate::config::MAX_BODY_SIZE;
    use crate::data_validation::{FieldSchema, FieldType};
    use crate::idempotency::{KEY_HEADER, REPLAYED_HEADER};
    use crate::seal::request_aad;
    use crate::seal::tests::{form, sealed_form, BOUNDARY};
    use crate::state::AppState;
    use crate::storage::pools::{DrtMetadata, PoolDoc, PoolKind, Upload, INITIAL};
    use crate::storage::staged::{Saga, Staged};
    use crate::storage::{Change, Storage};
    use crate::tee::tests::fixed_key;
    use crate::tee::EcKey;

    pub(crate) const POOL_UUID: [u8; 16] = [7; 16];
    const APPEND_RIGHT_ID: [u8; 16] = [8; 16];
    const CSV: &[u8] = b"name,score\nalice,1\nbob,2\n";

    fn admin_token(oid: &str) -> String {
        let mut spec = Spec::valid(&config());
        spec.oid = oid.into();
        spec.roles = vec!["Admin".into()];
        spec.sign(entra_key()).unwrap()
    }

    pub(crate) async fn send(
        app: &Router,
        request: Request<Body>,
    ) -> (StatusCode, HeaderMap, Value) {
        let response = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = to_bytes(body, 1 << 20).await.unwrap();
        (
            parts.status,
            parts.headers,
            serde_json::from_slice(&body).unwrap_or_default(),
        )
    }

    fn upload(path: &str, key: &str, token: &str, body: Vec<u8>) -> Request<Body> {
        Request::post(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(&KEY_HEADER, key)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(body))
            .unwrap()
    }

    /// A worker on a fake chain.
    pub(crate) struct Worker {
        pub app: Router,
        pub chain: Arc<FakeChain>,
        pub storage: Arc<Storage>,
        pub commitments: Arc<Commitments>,
        transport: Arc<EcKey>,
    }

    /// An admin who has signed in and has a wallet.
    pub(crate) struct Admin {
        pub token: String,
        pub user_id: String,
        pub wallet_id: String,
        pub address: Pubkey,
    }

    pub(crate) fn worker() -> Worker {
        let chain = Arc::new(FakeChain::default());
        let mut state = AppState::for_tests();
        state.solana_client = Arc::new(fake::start(chain.clone()));
        let transport = state.transport.get(state.transport.current_kid()).unwrap();
        let storage = state.storage.clone();
        let commitments = state.commitments.clone();
        Worker {
            app: crate::router(state),
            chain,
            storage,
            commitments,
            transport,
        }
    }

    /// The caller's user ID, which their first request creates.
    pub(crate) async fn sign_in(app: &Router, token: &str) -> String {
        let me = Request::get("/v1/users/me")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let (status, _, me) = send(app, me).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        me["user_id"].as_str().unwrap().into()
    }

    impl Worker {
        /// An admin who learns their user ID, as the dashboard does, and
        /// creates a wallet.
        pub(crate) async fn admin(&self, oid: &str) -> Admin {
            let token = admin_token(oid);
            let user_id = sign_in(&self.app, &token).await;
            let create_wallet = Request::post("/v1/wallets")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(&KEY_HEADER, uuid::Uuid::new_v4().to_string())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let (status, _, wallet) = send(&self.app, create_wallet).await;
            assert_eq!(status, StatusCode::CREATED, "{wallet}");
            let wallet = &wallet["wallet"];
            Admin {
                token,
                user_id,
                wallet_id: wallet["wallet_id"].as_str().unwrap().into(),
                address: Pubkey::from_str(wallet["public_address"].as_str().unwrap()).unwrap(),
            }
        }

        /// A pool of `owner`'s, on chain and in storage, with an append DRT
        /// whose mint is `append_mint`, and `initial` as its first upload.
        pub(crate) async fn pool(&self, owner: &Admin, initial: Option<Upload>) -> Pubkey {
            let pool_pda = Pubkey::new_unique();
            let account = Pool {
                uuid: POOL_UUID,
                owner: owner.address,
                created_at: 0,
                sealed: true,
                bump: 255,
            };
            let data = [&DISC_POOL_ACCOUNT[..], &borsh::to_vec(&account).unwrap()].concat();
            self.chain.data.lock().unwrap().push((pool_pda, data));
            let append = DrtMetadata {
                right_id_hex: hex::encode(APPEND_RIGHT_ID),
                mint: append_mint(&pool_pda).to_string(),
                supply: 5,
                code_repo_url: String::new(),
                code_hash_hex: hex::encode([0; 32]),
            };
            self.storage
                .pools()
                .create(&PoolDoc {
                    pool_pda: pool_pda.to_string(),
                    pool_name: "Sealed".into(),
                    kind: PoolKind::Malta,
                    pool_uuid_hex: hex::encode(POOL_UUID),
                    drts: BTreeMap::from([(APPEND_DRT_NAME.to_string(), append)]),
                    owner_wallet_id: owner.wallet_id.clone(),
                    owner_pubkey: owner.address.to_string(),
                    schema_id: "s".into(),
                    schema: ["name", "score"]
                        .map(|name| FieldSchema {
                            name: name.into(),
                            field_type: FieldType::Text,
                            nullable: false,
                        })
                        .to_vec(),
                    analysis: None,
                    created_by: owner.user_id.clone(),
                    created_at: chrono::Utc::now(),
                    creation_signature: "sig".into(),
                    initial,
                    issuances: Vec::new(),
                    revocations: Vec::new(),
                    grants: Vec::new(),
                })
                .await
                .unwrap();
            pool_pda
        }

        /// A pool as [`Self::pool`] makes it, without an initial upload,
        /// whose uploads are checked against `schema`.
        async fn pool_with_schema(&self, owner: &Admin, schema: Vec<FieldSchema>) -> Pubkey {
            let pool_pda = self.pool(owner, None).await;
            self.storage
                .pools()
                .update::<ApiError>(&pool_pda.to_string(), |doc| {
                    doc.schema = schema.clone();
                    Ok(Change::Changed)
                })
                .await
                .unwrap();
            pool_pda
        }

        /// `holder` owns `amount` of the pool's append DRT.
        fn holds_append_drts(&self, holder: &Admin, pool_pda: &Pubkey, amount: u64) {
            self.holds(holder, &append_mint(pool_pda), amount);
        }

        /// `holder` owns `amount` of the DRT whose mint is `mint`.
        pub(crate) fn holds(&self, holder: &Admin, mint: &Pubkey, amount: u64) {
            let mut account = vec![0u8; 165];
            account[64..72].copy_from_slice(&amount.to_le_bytes());
            let ata = derive_user_ata(&holder.address, mint);
            let mut data = self.chain.data.lock().unwrap();
            data.retain(|(address, _)| *address != ata);
            data.push((ata, account));
        }

        /// `csv`, sealed for `admin`'s `POST` of `path` with `key`.
        fn sealed(&self, admin: &Admin, path: &str, key: &str, csv: &[u8]) -> Vec<u8> {
            let transport = self.transport.as_ref();
            let aad = request_aad("POST", path, key, &transport.thumbprint(), &admin.user_id);
            sealed_form(transport, &aad, csv)
        }
    }

    /// A pool's append mint, which only needs to be stable per pool here.
    fn append_mint(pool_pda: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[b"append", pool_pda.as_ref()], &Pubkey::default()).0
    }

    pub(crate) fn initial_upload(uploaded_by: &str) -> Upload {
        Upload {
            record_id: INITIAL.into(),
            upload_id: "first".into(),
            sha256: sha256_hex(CSV),
            rows: 2,
            uploaded_by: uploaded_by.into(),
            uploaded_at: chrono::Utc::now(),
            signature: None,
            commitment: None,
        }
    }

    #[tokio::test]
    async fn a_sealed_upload_opens_only_for_the_request_it_was_sealed_for() {
        let worker = worker();
        let owner = worker.admin("oid-admin").await;
        let pool_pda = worker.pool(&owner, None).await;
        let (app, storage) = (worker.app.clone(), worker.storage.clone());

        let path = format!("/v1/drt/pools/{pool_pda}/initialize");
        let key = uuid::Uuid::new_v4().to_string();
        let csv = CSV;
        let sealed = worker.sealed(&owner, &path, &key, csv);
        let transport = worker.transport.as_ref();
        let aad = request_aad("POST", &path, &key, &transport.thumbprint(), &owner.user_id);
        let (admin, user_id) = (owner.token.clone(), owner.user_id.clone());

        // The same ciphertext for another pool, route, key or user doesn't open.
        let other_pool = format!("/v1/drt/pools/{}/initialize", Pubkey::new_unique());
        let issue = format!("/v1/drt/pools/{pool_pda}/issue");
        let other_key = uuid::Uuid::new_v4().to_string();
        let other_user = admin_token("oid-someone-else");
        for (path, key, token) in [
            (&other_pool, &key, &admin),
            (&issue, &key, &admin),
            (&path, &other_key, &admin),
            (&path, &key, &other_user),
        ] {
            let (status, _, err) = send(&app, upload(path, key, token, sealed.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {err}");
            assert_eq!(err["code"], "sealed_payload_invalid", "{path}");
            assert_eq!(err["error"], "sealed payload invalid");
        }

        // For its own request it opens, and initialises the pool. Without
        // FAULT_INJECTION=on, X-Fault-Exit does nothing.
        let mut request = upload(&path, &key, &admin, sealed);
        request.headers_mut().insert(
            "x-fault-exit",
            axum::http::HeaderValue::from_static("recorded"),
        );
        let (status, headers, first) = send(&app, request).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert!(headers.get(&REPLAYED_HEADER).is_none());
        assert_eq!(
            first,
            json!({ "rows": 2, "record_id": "initial", "state": "ready" })
        );
        let upload_id = crate::ids::upload_id(&user_id, &pool_pda.to_string(), &key);
        let stored = storage
            .pools()
            .read_dataset(&pool_pda.to_string(), &upload_id)
            .await
            .unwrap();
        assert_eq!(stored.as_deref().map(Vec::as_slice), Some(csv));

        // A retry sealed afresh replays: the fingerprint covers the plaintext.
        let resealed = sealed_form(transport, &aad, csv);
        let (status, headers, again) = send(&app, upload(&path, &key, &admin, resealed)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[&REPLAYED_HEADER], "true");
        assert_eq!(again, first);

        // Plaintext uploads, and the parts of the construction HPKE replaced, are refused.
        let fresh = uuid::Uuid::new_v4().to_string();
        let plaintext = form(&[("file", csv)]);
        let (status, _, err) = send(&app, upload(&path, &fresh, &admin, plaintext)).await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_request"))
        );
        let old = form(&[
            ("encrypted_data", &b"AAAA"[..]),
            ("ephemeral_public_key", b"BBBB"),
            ("nonce", b"CCCC"),
        ]);
        let (status, _, err) = send(&app, upload(&path, &fresh, &admin, old)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err["code"], "sealed_payload_invalid");
    }

    #[tokio::test]
    async fn a_retried_issuance_burns_under_the_commitment_it_staged() {
        let worker = worker();
        let admin = worker.admin("oid-admin").await;
        let pool_pda = worker
            .pool(&admin, Some(initial_upload(&admin.user_id)))
            .await;
        worker.holds_append_drts(&admin, &pool_pda, 1);
        let path = format!("/v1/drt/pools/{pool_pda}/issue");
        let key = uuid::Uuid::new_v4().to_string();
        let record_id = crate::ids::upload_id(&admin.user_id, &pool_pda.to_string(), &key);

        // An earlier attempt staged this issuance under another commitment
        // key, and its burn landed.
        let earlier = Commitments::derive(&fixed_key(99)).commitment(
            &record_id,
            &POOL_UUID,
            &APPEND_RIGHT_ID,
        );
        let staged = Staged {
            record: "idempotency/earlier.json".into(),
            staged_at: chrono::Utc::now(),
            saga: Saga::Issue {
                pool_pda: pool_pda.to_string(),
                upload: Upload {
                    record_id: record_id.clone(),
                    upload_id: record_id.clone(),
                    sha256: sha256_hex(CSV),
                    rows: 2,
                    uploaded_by: admin.user_id.clone(),
                    uploaded_at: chrono::Utc::now(),
                    signature: None,
                    commitment: Some(hex::encode(earlier)),
                },
            },
        };
        worker
            .storage
            .sagas()
            .stage(&format!("issue-{record_id}"), staged)
            .await
            .unwrap();
        let chain = &worker.chain;
        chain
            .accounts
            .lock()
            .unwrap()
            .push(derive_grant_pda(&earlier).0);
        *chain.history.lock().unwrap() = vec![json!({ "signature": "sig-earlier", "err": null })];
        chain.lands.store(true, std::sync::atomic::Ordering::SeqCst);

        let sealed = worker.sealed(&admin, &path, &key, CSV);
        let (status, _, issued) =
            send(&worker.app, upload(&path, &key, &admin.token, sealed)).await;
        assert_eq!(status, StatusCode::OK, "{issued}");
        assert_eq!(issued["redeem_signature"], "sig-earlier");
        assert!(chain.sent().is_empty(), "no second burn");
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        let entry = doc.upload(&record_id).expect("the issuance is recorded");
        assert_eq!(entry.commitment_bytes(), Some(earlier));
    }

    #[tokio::test]
    async fn an_admin_who_does_not_own_a_pool_gets_403_on_its_writes() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let other = worker.admin("oid-other").await;
        let pool_pda = worker
            .pool(&owner, Some(initial_upload(&owner.user_id)))
            .await;
        let base = format!("/v1/drt/pools/{pool_pda}");
        let json_post = |path: String, token: &str, body: &Value| {
            Request::post(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(&KEY_HEADER, uuid::Uuid::new_v4().to_string())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let revoke = json!({ "wallet_id": other.wallet_id, "credential_ids": [INITIAL] });

        let mut requests = vec![(
            "revoke",
            json_post(format!("{base}/revoke"), &other.token, &revoke),
        )];
        for route in ["initialize", "issue"] {
            let path = format!("{base}/{route}");
            let key = uuid::Uuid::new_v4().to_string();
            let sealed = worker.sealed(&other, &path, &key, CSV);
            requests.push((route, upload(&path, &key, &other.token, sealed)));
        }
        for (route, request) in requests {
            let (status, _, err) = send(&worker.app, request).await;
            assert_eq!(
                (status, err["code"].as_str()),
                (StatusCode::FORBIDDEN, Some("forbidden")),
                "{route}: {err}"
            );
        }

        // The pool's owner gets past the same check.
        let revoke = json!({ "wallet_id": owner.wallet_id, "credential_ids": [INITIAL] });
        let request = json_post(format!("{base}/revoke"), &owner.token, &revoke);
        let (status, _, revoked) = send(&worker.app, request).await;
        assert_eq!(status, StatusCode::OK, "{revoked}");
    }

    /// `admin`'s request to create a pool with `analysis`.
    fn create_pool(admin: &Admin, analysis: Value) -> Request<Body> {
        let body = json!({
            "wallet_id": admin.wallet_id,
            "pool_name": "Awards",
            "append_supply": 3,
            "analysis": analysis,
        });
        Request::post("/v1/drt/pools/malta")
            .header(header::AUTHORIZATION, format!("Bearer {}", admin.token))
            .header(&KEY_HEADER, uuid::Uuid::new_v4().to_string())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn awards_report_hash() -> String {
        hex::encode(Sha256::digest(
            crate::analysis::definition::tests::AWARDS_REPORT,
        ))
    }

    #[tokio::test]
    async fn a_pool_takes_its_schema_and_execute_drt_from_its_analysis() {
        use crate::analysis::fetch::tests::AWARDS_REPORT_URL;

        let worker = worker();
        let admin = worker.admin("oid-admin").await;
        worker
            .chain
            .lands
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let hash = awards_report_hash();
        let analysis =
            json!({ "code_repo_url": AWARDS_REPORT_URL, "code_hash_hex": hash, "supply": 200 });
        let (status, _, created) = send(&worker.app, create_pool(&admin, analysis)).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert!(
            created["mints"]["awards-report-v1"].is_string(),
            "{created}"
        );

        let pool_pda = created["pool_pda"].as_str().unwrap();
        let doc = worker.storage.pools().get(pool_pda).await.unwrap().unwrap();
        assert_eq!(doc.schema, crate::data_validation::tests::awards_schema());
        assert_eq!(doc.schema_id, "awards-report-v1");
        let analysis = doc.analysis.clone().unwrap();
        assert_eq!(
            (
                analysis.code_repo_url.as_str(),
                analysis.code_hash_hex.as_str()
            ),
            (AWARDS_REPORT_URL, hash.as_str())
        );
        let execute = &doc.drts["awards-report-v1"];
        assert_eq!(
            (execute.supply, execute.code_repo_url.as_str()),
            (200, AWARDS_REPORT_URL)
        );
        assert_eq!(doc.drts[APPEND_DRT_NAME].supply, 3);
        assert!(
            worker.storage.scripts().get(&hash).await.unwrap().is_some(),
            "stored by hash"
        );

        let schema = Request::get(format!("/v1/drt/pools/{pool_pda}/schema"))
            .header(header::AUTHORIZATION, format!("Bearer {}", admin.token))
            .body(Body::empty())
            .unwrap();
        let (status, _, schema) = send(&worker.app, schema).await;
        assert_eq!(status, StatusCode::OK, "{schema}");
        assert_eq!(
            schema["fields"][0],
            json!({ "name": "Staff Number", "field_type": "text", "nullable": true })
        );
        assert_eq!(schema["fields"][5]["field_type"], "date");
    }

    #[tokio::test]
    async fn pool_creation_refuses_an_analysis_that_does_not_check_out() {
        use crate::analysis::fetch::tests::AWARDS_REPORT_URL;

        let worker = worker();
        let admin = worker.admin("oid-admin").await;
        let hash = awards_report_hash();
        let elsewhere = AWARDS_REPORT_URL.replace("awards-report-v1.toml", "other.toml");
        for (analysis, says) in [
            (
                json!({ "code_repo_url": AWARDS_REPORT_URL, "code_hash_hex": "ab".repeat(32), "supply": 1 }),
                "doesn't hash",
            ),
            (
                json!({ "code_repo_url": "https://example.com/awards.toml", "code_hash_hex": hash, "supply": 1 }),
                "isn't under",
            ),
            (
                json!({ "code_repo_url": elsewhere, "code_hash_hex": hash, "supply": 1 }),
                "404",
            ),
            (
                json!({ "code_repo_url": AWARDS_REPORT_URL, "code_hash_hex": "00".repeat(32), "supply": 1 }),
                "SHA-256",
            ),
            (
                json!({ "code_repo_url": AWARDS_REPORT_URL, "code_hash_hex": hash, "supply": 0 }),
                "supply",
            ),
        ] {
            let (status, _, err) = send(&worker.app, create_pool(&admin, analysis.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{analysis}: {err}");
            assert!(
                err["error"].as_str().unwrap().contains(says),
                "{analysis}: {err}"
            );
        }
        assert!(worker.chain.sent().is_empty(), "nothing reached the chain");
    }

    #[tokio::test]
    async fn two_workers_page_one_list_with_each_others_cursors() {
        use crate::storage::pools::tests::pool;
        use crate::storage::tests::two_workers;

        let (a, b, _files) = two_workers();
        for i in 0..5 {
            a.pools()
                .create(&pool(&format!("P{i}"), "w1"))
                .await
                .unwrap();
        }
        let router = |storage: Storage| {
            let mut state = AppState::for_tests();
            state.storage = Arc::new(storage);
            crate::router(state)
        };
        let workers = [router(a), router(b)];
        let token = admin_token("oid-reader");
        let page = |worker: usize, cursor: Option<String>| {
            let query = cursor.map(|c| format!("&cursor={c}")).unwrap_or_default();
            let request = Request::get(format!("/v1/drt/pools/list?limit=2{query}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap();
            let app = workers[worker].clone();
            async move {
                let (status, _, body) = send(&app, request).await;
                assert_eq!(status, StatusCode::OK, "{body}");
                body
            }
        };

        // Each page, asked of either worker with the cursor the other gave,
        // is the same page.
        let mut cursor = None;
        let mut seen = Vec::new();
        for turn in 0..3 {
            let here = page(turn % 2, cursor.clone()).await;
            let there = page((turn + 1) % 2, cursor.clone()).await;
            assert_eq!(here, there, "page {turn}");
            for entry in here["pools"].as_array().unwrap() {
                seen.push(entry["pool_pda"].as_str().unwrap().to_string());
            }
            cursor = here["next_cursor"].as_str().map(String::from);
        }
        assert!(cursor.is_none(), "three pages of two hold five pools");
        seen.sort();
        assert_eq!(seen, ["P0", "P1", "P2", "P3", "P4"]);
    }

    /// `rows` synthetic rows of the Awards Report's columns, with made-up
    /// values at the lengths a real export has.
    fn awards_scale_csv(rows: usize) -> String {
        const TITLES: [&str; 5] = ["Mr", "Ms", "Mrs", "Dr", "Mx"];
        const FIRST: [&str; 6] = ["Alexis", "Sam", "Jordan", "Casey", "Riley", "Morgan"];
        const SURNAMES: [&str; 6] = [
            "Alphason",
            "Bravo",
            "Charleston",
            "Deltawood",
            "Echolands",
            "Foxtrot",
        ];
        const EMPLOYERS: [(&str, &str); 4] = [
            ("Bank A", "Group A"),
            ("Bank A Network", "Group A"),
            ("Bank B", "Group B"),
            ("Bank C", "Group C"),
        ];
        const AWARDS: [&str; 3] = [
            "Professional Certificate in Subject Area A",
            "Professional Diploma in Subject B",
            "Certificate in Subject Area C",
        ];
        const GRADES: [&str; 4] = ["Pass", "Merit", "Distinction", "Pass with Distinction"];
        let mut csv = format!("{}\n", crate::data_validation::tests::AWARDS_HEADER);
        for i in 0..rows {
            let (employer, group) = EMPLOYERS[i % EMPLOYERS.len()];
            csv.push_str(&format!(
                "{:06},{:07},{},{},{},{:02}/{:02}/{},{employer},{group},{},{},{:02}/{:02}/2026\n",
                i % 1_000_000,
                100_000 + i,
                TITLES[i % TITLES.len()],
                FIRST[i % FIRST.len()],
                SURNAMES[i % SURNAMES.len()],
                1 + i % 28,
                1 + i % 12,
                1960 + i % 40,
                AWARDS[i % AWARDS.len()],
                GRADES[i % GRADES.len()],
                1 + i % 28,
                1 + i % 12,
            ));
        }
        csv
    }

    /// The pilot's largest pools hold about 100,000 rows, which an admin may
    /// upload at once, and which the pool's analysis then queries.
    #[tokio::test]
    #[ignore = "pilot scale, slow in unoptimised builds: run `just scale`"]
    async fn a_pilot_sized_dataset_uploads_within_the_body_limit() {
        const ROWS: usize = 100_000;
        let schema = crate::data_validation::tests::awards_schema();
        let fields = schema.len();
        let csv = awards_scale_csv(ROWS);
        let worker = worker();
        let admin = worker.admin("oid-admin").await;
        let pool_pda = worker.pool_with_schema(&admin, schema).await;
        worker.holds_append_drts(&admin, &pool_pda, 1);
        worker
            .chain
            .lands
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let mut body_size = 0;
        let mut timings = Vec::new();
        for (route, rows) in [("initialize", "rows"), ("issue", "rows_issued")] {
            let path = format!("/v1/drt/pools/{pool_pda}/{route}");
            let key = uuid::Uuid::new_v4().to_string();
            let body = worker.sealed(&admin, &path, &key, csv.as_bytes());
            body_size = body.len();
            assert!(
                body_size <= MAX_BODY_SIZE,
                "{route}: the {body_size}-byte body is over the limit"
            );
            let started = Instant::now();
            let (status, _, response) =
                send(&worker.app, upload(&path, &key, &admin.token, body)).await;
            let elapsed = started.elapsed();
            assert_eq!(status, StatusCode::OK, "{route}: {response}");
            assert_eq!(response[rows], ROWS, "{route}: {response}");
            timings.push(format!("{route} {:.2} s", elapsed.as_secs_f64()));
        }

        // Rows never enter the pool document, which records each upload's
        // digest and row count.
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        let digest = sha256_hex(csv.as_bytes());
        assert_eq!(doc.uploads().count(), 2);
        assert!(doc
            .uploads()
            .all(|u| u.sha256 == digest && u.rows == ROWS as u64));
        let doc_size = serde_json::to_vec(&doc).unwrap().len();
        assert!(
            doc_size < 16 * 1024,
            "the pool document is {doc_size} bytes"
        );

        let mib = |bytes: usize| bytes as f64 / f64::from(1 << 20);
        let overhead = body_size - csv.len();
        eprintln!(
            "pilot scale: {ROWS} rows of {fields} fields, {:.1} MiB ({} bytes a row)",
            mib(csv.len()),
            csv.len() / ROWS,
        );
        eprintln!(
            "sealed body: {:.1} MiB of the {:.0} MiB limit ({:.0}%); {ROWS} rows fit while \
             rows average up to {} bytes",
            mib(body_size),
            mib(MAX_BODY_SIZE),
            100.0 * body_size as f64 / MAX_BODY_SIZE as f64,
            (MAX_BODY_SIZE - overhead) / ROWS,
        );
        eprintln!(
            "uploads: {}; pool document: {doc_size} bytes",
            timings.join(", ")
        );

        // The Awards Report over both uploads, as an admin: the first query
        // builds the table, and the later ones read it from memory.
        let hash = worker
            .storage
            .scripts()
            .put(crate::analysis::definition::tests::AWARDS_REPORT.as_bytes())
            .await
            .unwrap();
        worker
            .storage
            .pools()
            .update::<ApiError>(&pool_pda.to_string(), |doc| {
                doc.analysis = Some(crate::storage::pools::AnalysisRef {
                    analysis_id: "awards-report-v1".into(),
                    display_name: "Awards Report".into(),
                    code_repo_url: String::new(),
                    code_hash_hex: hash.clone(),
                });
                Ok(Change::Changed)
            })
            .await
            .unwrap();
        let path = format!("/v1/drt/pools/{pool_pda}/analyses/awards-report-v1/query");
        let filtered = json!({
            "filters": {
                "award": { "mode": "selected", "values": ["Certificate in Subject Area C"] },
                "exam_board_date": { "from": "01/03/2026", "to": "30/06/2026" },
            },
            "sort": { "field": "surname", "direction": "asc" },
            "pagination": { "limit": 500, "offset": 1000 },
        });
        let mut query_timings = Vec::new();
        for (label, body) in [
            ("first (builds the table)", json!({})),
            ("warm", json!({})),
            ("filtered and sorted, 500 rows", filtered),
        ] {
            let request = Request::post(&path)
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.token))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let started = Instant::now();
            let (status, _, page) = send(&worker.app, request).await;
            let elapsed = started.elapsed();
            assert_eq!(status, StatusCode::OK, "{label}: {page}");
            if label == "warm" {
                assert_eq!(page["total_matched"], 2 * ROWS);
            }
            query_timings.push(format!("{label} {:.0} ms", elapsed.as_secs_f64() * 1000.0));
        }
        eprintln!(
            "analysis over {} rows: {}",
            2 * ROWS,
            query_timings.join(", ")
        );
        let table = crate::analysis::table::Table::build(
            &crate::analysis::definition::tests::awards_report(),
            &[csv.as_bytes(), csv.as_bytes()],
            &crate::analysis::table::Scope::All,
        )
        .unwrap();
        eprintln!(
            "the admin's table: {:.1} MiB for {} rows, indexes included",
            mib(table.bytes),
            table.rows
        );
    }
}
