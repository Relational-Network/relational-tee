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

fn pool_not_found(pool_pda: &str) -> ApiError {
    ApiError::not_found(format!("pool metadata not found for {pool_pda}"))
}

fn parse_pda(pool_pda: &str) -> Result<Pubkey, ApiError> {
    Pubkey::from_str(pool_pda).map_err(|_| ApiError::bad_request("invalid pool PDA address"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, HeaderMap, Request, StatusCode};
    use axum::Router;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::entra::mint::Spec;
    use crate::auth::entra::tests::{config, entra_key};
    use crate::blockchain::drt::types::{Pool, DISC_POOL_ACCOUNT};
    use crate::blockchain::fake::{self, FakeChain};
    use crate::data_validation::ValidationMode;
    use crate::idempotency::{KEY_HEADER, REPLAYED_HEADER};
    use crate::seal::request_aad;
    use crate::seal::tests::{form, sealed_form, BOUNDARY};
    use crate::state::AppState;
    use crate::storage::pools::{PoolDoc, PoolKind};
    use crate::tee::KeyName;

    fn admin_token(oid: &str) -> String {
        let mut spec = Spec::valid(&config());
        spec.oid = oid.into();
        spec.roles = vec!["Admin".into()];
        spec.sign(entra_key()).unwrap()
    }

    async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
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

    #[tokio::test]
    async fn a_sealed_upload_opens_only_for_the_request_it_was_sealed_for() {
        let chain = Arc::new(FakeChain::default());
        let mut state = AppState::for_tests();
        state.solana_client = Arc::new(fake::start(chain.clone()));
        let (keys, storage) = (state.keys.clone(), state.storage.clone());
        let app = crate::router(state);

        // The caller learns their user ID, as the dashboard does, and has a wallet.
        let admin = admin_token("oid-admin");
        let me = Request::get("/v1/users/me")
            .header(header::AUTHORIZATION, format!("Bearer {admin}"))
            .body(Body::empty())
            .unwrap();
        let (_, _, me) = send(&app, me).await;
        let user_id = me["user_id"].as_str().unwrap().to_string();
        let create_wallet = Request::post("/v1/wallets")
            .header(header::AUTHORIZATION, format!("Bearer {admin}"))
            .header(&KEY_HEADER, uuid::Uuid::new_v4().to_string())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _, wallet) = send(&app, create_wallet).await;
        assert_eq!(status, StatusCode::CREATED, "{wallet}");
        let wallet = &wallet["wallet"];
        let owner = Pubkey::from_str(wallet["public_address"].as_str().unwrap()).unwrap();

        // A pool of theirs, on chain and in storage, waiting for its first upload.
        let pool_pda = Pubkey::new_unique();
        let account = Pool {
            uuid: [7; 16],
            owner,
            created_at: 0,
            sealed: true,
            bump: 255,
        };
        let data = [&DISC_POOL_ACCOUNT[..], &borsh::to_vec(&account).unwrap()].concat();
        chain.data.lock().unwrap().push((pool_pda, data));
        storage
            .pools()
            .create(&PoolDoc {
                pool_pda: pool_pda.to_string(),
                pool_name: "Sealed".into(),
                kind: PoolKind::Malta,
                pool_uuid_hex: hex::encode([7; 16]),
                drts: BTreeMap::new(),
                owner_wallet_id: wallet["wallet_id"].as_str().unwrap().into(),
                owner_pubkey: owner.to_string(),
                schema_id: "s".into(),
                schema: Vec::new(),
                validation_mode: ValidationMode::None,
                created_by: user_id.clone(),
                created_at: chrono::Utc::now(),
                creation_signature: "sig".into(),
                initial: None,
                issuances: Vec::new(),
                revocations: Vec::new(),
            })
            .await
            .unwrap();

        let transport = &keys.get(KeyName::Transport).current;
        let kid = transport.thumbprint();
        let path = format!("/v1/drt/pools/{pool_pda}/initialize");
        let key = uuid::Uuid::new_v4().to_string();
        let csv = b"name,score\nalice,1\nbob,2\n";
        let aad = request_aad("POST", &path, &key, &kid, &user_id);
        let sealed = sealed_form(transport, &aad, csv);

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

        // For its own request it opens, and initialises the pool.
        let (status, headers, first) = send(&app, upload(&path, &key, &admin, sealed)).await;
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
        assert_eq!(stored.as_deref(), Some(&csv[..]));

        // A retry sealed afresh replays: the fingerprint covers the plaintext.
        let resealed = sealed_form(transport, &aad, csv);
        let (status, headers, again) = send(&app, upload(&path, &key, &admin, resealed)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[&REPLAYED_HEADER], "true");
        assert_eq!(again, first);

        // Plaintext uploads, and the parts of the construction HPKE replaced, are refused.
        let fresh = uuid::Uuid::new_v4().to_string();
        let plaintext = form(&[("file", &csv[..])]);
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
}
