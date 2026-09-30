// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Sealed uploads: RFC 9180 HPKE in base mode with DHKEM(P-256,
//! HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, to the transport key.
//!
//! An upload is a multipart form with four parts: `v` (`1`), `kid` (the RFC
//! 7638 thumbprint of the transport key version it's sealed to), `enc` (the
//! encapsulated key, unpadded base64url) and `ct` (the ciphertext of the
//! CSV). The HPKE `info` is `relational-tee/hpke/v1`, and the AAD binds the
//! ciphertext to one request (see [`request_aad`]), so it can't be replayed
//! against another pool, route, `Idempotency-Key`, transport key or user.
//! Uploads are opened after authentication and before the idempotency
//! check, whose fingerprint covers the plaintext. They open with the current
//! transport key version, or another version the manifest lists (see
//! [`TransportKeys`]).
//!
//! Every failure is `400 sealed_payload_invalid`, with no detail; the
//! worker logs the reason. A plaintext `file` part is refused as a bad
//! request.

use axum::extract::multipart::MultipartError;
use axum::extract::Multipart;
use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, OpModeR};
use tracing::warn;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::error::ApiError;
use crate::tee::EcKey;

pub(crate) mod keys;
#[cfg(test)]
mod rfc9180;

pub use keys::{Listed, TransportKeys};

/// The HPKE `info` of every sealed request.
pub const INFO: &[u8] = b"relational-tee/hpke/v1";
/// The first line of a request's AAD.
pub const REQUEST_AAD_LABEL: &str = "relational-tee/req/v1";
/// The sealed format's version, the `v` part.
pub const FORMAT_VERSION: &str = "1";

type Kem = DhP256HkdfSha256;

/// Why a sealed payload was refused. Logged, never returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealError(pub &'static str);

impl From<SealError> for ApiError {
    fn from(e: SealError) -> Self {
        warn!(reason = e.0, "Refused a sealed payload");
        ApiError::bad_request("sealed payload invalid").with_code("sealed_payload_invalid")
    }
}

/// A sealed upload, as `multipart/form-data`.
#[derive(ToSchema)]
#[allow(dead_code)] // Only documents the form: uploads are read part by part.
pub struct SealedUploadForm {
    /// The sealed format's version: `1`.
    pub v: String,
    /// The RFC 7638 thumbprint of the transport key it's sealed to, from `GET /v1/attestation`.
    pub kid: String,
    /// The HPKE encapsulated key, unpadded base64url.
    pub enc: String,
    /// The HPKE ciphertext of the CSV (`application/octet-stream`).
    #[schema(value_type = String, format = Binary)]
    pub ct: Vec<u8>,
}

/// A sealed upload's parts.
#[derive(Debug)]
pub struct SealedUpload {
    /// The transport key version it's sealed to.
    pub kid: String,
    enc: Vec<u8>,
    ct: Bytes,
}

fn multipart_error(e: MultipartError) -> ApiError {
    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large("the upload is too large")
    } else {
        SealError("the multipart body is malformed").into()
    }
}

impl SealedUpload {
    /// Read the parts `v`, `kid`, `enc` and `ct`, each exactly once, and
    /// nothing else.
    pub async fn read(mut multipart: Multipart) -> Result<Self, ApiError> {
        // v, kid, enc, ct
        let mut parts: [Option<Bytes>; 4] = Default::default();
        while let Some(field) = multipart.next_field().await.map_err(multipart_error)? {
            let slot = match field.name() {
                Some("v") => 0,
                Some("kid") => 1,
                Some("enc") => 2,
                Some("ct") => 3,
                Some("file") => {
                    return Err(ApiError::bad_request(
                        "plaintext uploads aren't accepted: seal the CSV to the transport key \
                         and send the parts v, kid, enc and ct",
                    ))
                }
                _ => return Err(SealError("an unexpected part").into()),
            };
            let value = field.bytes().await.map_err(multipart_error)?;
            if parts[slot].replace(value).is_some() {
                return Err(SealError("a part appears twice").into());
            }
        }
        let [Some(v), Some(kid), Some(enc), Some(ct)] = parts else {
            return Err(SealError("a part is missing").into());
        };
        if v != FORMAT_VERSION.as_bytes() {
            return Err(SealError("an unknown format version").into());
        }
        let kid = String::from_utf8(kid.to_vec()).map_err(|_| SealError("kid isn't UTF-8"))?;
        let enc = std::str::from_utf8(&enc)
            .ok()
            .and_then(|enc| URL_SAFE_NO_PAD.decode(enc).ok())
            .ok_or(SealError("enc isn't unpadded base64url"))?;
        Ok(Self { kid, enc, ct })
    }
}

/// A request's AAD: the label, the method, the concrete path (percent-encoded,
/// without the query), the `Idempotency-Key` in canonical lowercase form, the
/// `kid` and the caller's `user_id`, as UTF-8 lines joined by `\n`, with no
/// trailing newline.
pub fn request_aad(
    method: &str,
    path: &str,
    idempotency_key: &str,
    kid: &str,
    user_id: &str,
) -> Vec<u8> {
    [
        REQUEST_AAD_LABEL,
        method,
        path,
        idempotency_key,
        kid,
        user_id,
    ]
    .join("\n")
    .into_bytes()
}

/// Open `upload` with the transport key version its `kid` names, if the
/// worker accepts it.
pub fn open_upload(
    transport: &TransportKeys,
    upload: &SealedUpload,
    aad: &[u8],
) -> Result<Vec<u8>, SealError> {
    let key = transport.get(&upload.kid).ok_or(SealError(
        "kid names no transport key version this worker accepts",
    ))?;
    open(&key, &upload.enc, INFO, &upload.ct, aad)
}

/// Open a single-shot HPKE ciphertext sealed to `key`.
fn open(key: &EcKey, enc: &[u8], info: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, SealError> {
    let scalar = Zeroizing::new(key.secret().to_bytes());
    let recipient = <Kem as hpke::Kem>::PrivateKey::from_bytes(scalar.as_slice())
        .map_err(|_| SealError("the transport key isn't a P-256 key"))?;
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc)
        .map_err(|_| SealError("enc isn't a P-256 public key"))?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        &recipient,
        &encapped,
        info,
        ct,
        aad,
    )
    .map_err(|_| SealError("the ciphertext doesn't open"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tee::tests::{fixed_key, Versions};
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::{header, Request};
    use hpke::{OpModeS, Serializable};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::TryRngCore;
    use serde_json::Value;
    use std::sync::Arc;

    /// Seal `plaintext` to `recipient` as a client does: the `enc` and `ct`
    /// parts.
    pub(crate) fn seal(recipient: &EcKey, aad: &[u8], plaintext: &[u8]) -> (String, Vec<u8>) {
        let point = recipient.public_key().to_encoded_point(false);
        let public = <Kem as hpke::Kem>::PublicKey::from_bytes(point.as_bytes()).unwrap();
        let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(
            &OpModeS::Base,
            &public,
            INFO,
            plaintext,
            aad,
            &mut rand_core::OsRng.unwrap_err(),
        )
        .unwrap();
        (URL_SAFE_NO_PAD.encode(enc.to_bytes()), ct)
    }

    pub(crate) const BOUNDARY: &str = "sealed-upload-boundary";

    /// A multipart body of `parts`, with `ct` sent as a binary file part,
    /// as a browser sends a `Blob`.
    pub(crate) fn form(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, value) in parts {
            let disposition = if *name == "ct" || *name == "file" {
                format!(
                    "form-data; name=\"{name}\"; filename=\"blob\"\r\n\
                     Content-Type: application/octet-stream"
                )
            } else {
                format!("form-data; name=\"{name}\"")
            };
            body.extend_from_slice(
                format!("--{BOUNDARY}\r\nContent-Disposition: {disposition}\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(value);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    /// The four parts of an upload sealed to `recipient` under `aad`.
    pub(crate) fn sealed_form(recipient: &EcKey, aad: &[u8], csv: &[u8]) -> Vec<u8> {
        let (enc, ct) = seal(recipient, aad, csv);
        form(&[
            ("v", &b"1"[..]),
            ("kid", recipient.thumbprint().as_bytes()),
            ("enc", enc.as_bytes()),
            ("ct", &ct),
        ])
    }

    async fn read(body: Vec<u8>) -> Result<SealedUpload, ApiError> {
        let request = Request::post("/")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(body))
            .unwrap();
        let multipart = Multipart::from_request(request, &()).await.unwrap();
        SealedUpload::read(multipart).await
    }

    fn hex(value: &Value) -> Vec<u8> {
        ::hex::decode(value.as_str().unwrap()).unwrap()
    }

    #[test]
    fn the_rfc_9180_vector_for_this_suite_passes() {
        let vector: Value = serde_json::from_str(rfc9180::VECTOR).unwrap();
        assert_eq!(
            [
                &vector["mode"],
                &vector["kem_id"],
                &vector["kdf_id"],
                &vector["aead_id"]
            ],
            [0, 0x10, 1, 2]
        );
        let (sk, pk) = <Kem as hpke::Kem>::derive_keypair(&hex(&vector["ikmR"]));
        assert_eq!(sk.to_bytes().to_vec(), hex(&vector["skRm"]));
        assert_eq!(pk.to_bytes().to_vec(), hex(&vector["pkRm"]));

        // Every encryption opens in order, and every export matches.
        let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex(&vector["enc"])).unwrap();
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &encapped,
            &hex(&vector["info"]),
        )
        .unwrap();
        let encryptions = vector["encryptions"].as_array().unwrap();
        assert_eq!(encryptions.len(), 257);
        for e in encryptions {
            let plaintext = receiver.open(&hex(&e["ct"]), &hex(&e["aad"])).unwrap();
            assert_eq!(plaintext, hex(&e["pt"]));
        }
        for x in vector["exports"].as_array().unwrap() {
            let mut exported = vec![0u8; x["L"].as_u64().unwrap() as usize];
            receiver
                .export(&hex(&x["exporter_context"]), &mut exported)
                .unwrap();
            assert_eq!(exported, hex(&x["exported_value"]));
        }

        // The worker's own path, from a released key, opens the first one.
        let key = EcKey::new(p256::SecretKey::from_slice(&hex(&vector["skRm"])).unwrap());
        let first = &encryptions[0];
        let opened = open(
            &key,
            &hex(&vector["enc"]),
            &hex(&vector["info"]),
            &hex(&first["ct"]),
            &hex(&first["aad"]),
        );
        assert_eq!(opened.unwrap(), hex(&first["pt"]));
    }

    #[test]
    fn the_aad_is_the_request_lines_joined_by_newlines() {
        let aad = request_aad(
            "POST",
            "/v1/drt/pools/Pool1111111111111111111111111111111111111111/issue",
            "2f6c1c1e-8d3a-4b1e-9f55-0a7c2b1d4e33",
            "kid-1",
            "7a1d0e9c-5b39-4f7e-8f0a-3c2b1d4e5f60",
        );
        assert_eq!(
            aad,
            b"relational-tee/req/v1\n\
              POST\n\
              /v1/drt/pools/Pool1111111111111111111111111111111111111111/issue\n\
              2f6c1c1e-8d3a-4b1e-9f55-0a7c2b1d4e33\n\
              kid-1\n\
              7a1d0e9c-5b39-4f7e-8f0a-3c2b1d4e5f60"
        );
    }

    const PATH: &str = "/v1/drt/pools/Pool1111111111111111111111111111111111111111/issue";
    const KEY: &str = "2f6c1c1e-8d3a-4b1e-9f55-0a7c2b1d4e33";
    const USER: &str = "7a1d0e9c-5b39-4f7e-8f0a-3c2b1d4e5f60";

    /// Test key 1 as the current transport key, and test key 2 as another
    /// version the manifest lists.
    async fn rotating() -> TransportKeys {
        let keys = keys::tests::rotating();
        let listed = [
            keys::tests::listed(fixed_key(1).thumbprint(), None),
            keys::tests::listed(fixed_key(2).thumbprint(), Some("v2")),
        ];
        keys.follow(&listed).await.unwrap();
        keys
    }

    fn only(current: EcKey) -> TransportKeys {
        TransportKeys::new(current, Arc::new(Versions(Default::default())))
    }

    #[tokio::test]
    async fn uploads_open_only_for_the_request_and_key_they_were_sealed_for() {
        let transport = rotating().await;
        let csv = b"name,score\nalice,1\n";
        for version in [&fixed_key(1), &fixed_key(2)] {
            let kid = version.thumbprint();
            let aad = request_aad("POST", PATH, KEY, &kid, USER);
            let upload = read(sealed_form(version, &aad, csv)).await.unwrap();
            assert_eq!(upload.kid, kid);
            assert_eq!(open_upload(&transport, &upload, &aad).unwrap(), csv);

            let other_route = PATH.replace("/issue", "/initialize");
            for changed in [
                request_aad("PUT", PATH, KEY, &kid, USER),
                request_aad("POST", &PATH.replace("Pool1", "Pool2"), KEY, &kid, USER),
                request_aad("POST", &other_route, KEY, &kid, USER),
                request_aad("POST", PATH, &KEY.replace('2', "3"), &kid, USER),
                request_aad("POST", PATH, KEY, &kid, &USER.replace('7', "8")),
            ] {
                let err = open_upload(&transport, &upload, &changed).unwrap_err();
                assert_eq!(err.0, "the ciphertext doesn't open");
            }
        }

        // A version the manifest doesn't list.
        let stranger = fixed_key(3);
        let aad = request_aad("POST", PATH, KEY, &stranger.thumbprint(), USER);
        let upload = read(sealed_form(&stranger, &aad, csv)).await.unwrap();
        assert_eq!(
            open_upload(&transport, &upload, &aad).unwrap_err().0,
            "kid names no transport key version this worker accepts"
        );
    }

    /// A CSV the dashboard's `sealUpload()` sealed to a throwaway transport
    /// key, for a request with the AAD fields above.
    #[tokio::test]
    async fn an_upload_sealed_by_the_dashboard_opens() {
        let recipient = EcKey::from_jwk(&serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "k094fYqq5_F4N6aNsU7UGwG06HIPWDN5AvdB_GRf5pA",
            "y": "RVfJCauMmkv9_qKnWzh30wzNzYQLC0qrH2VSOx1oPRg",
            "d": "3BD3jjiT7ensa5czL23S7UYvPUoi3YnBKNdbZzN4uLI",
        }))
        .unwrap();
        let kid = "CTxdXno6cJWKqceMSKStFUo7kEjnkXWNXeFIRbLUklE";
        assert_eq!(recipient.thumbprint(), kid);
        let enc = "BMXnzzQx-kAfRgegnnDeOnS7gFlHVIvlPn2FAWndsQE3arZ3EaL8Vu8HRvSUtOiFONautOPlpac7gEFPnoHc8_0";
        let ct = URL_SAFE_NO_PAD
            .decode("18ykp6oFtph-QXAv09_IwzfoQ6o7f-JvRAg4_vmdIL4AU4gMNWqFqH0")
            .unwrap();
        let upload = read(form(&[
            ("v", &b"1"[..]),
            ("kid", kid.as_bytes()),
            ("enc", enc.as_bytes()),
            ("ct", &ct),
        ]))
        .await
        .unwrap();
        let transport = only(recipient);

        let aad = request_aad("POST", PATH, KEY, kid, USER);
        let csv = open_upload(&transport, &upload, &aad).unwrap();
        assert_eq!(csv, b"name,score\nalice,1\nbob,2\n");
        let initialize = PATH.replace("/issue", "/initialize");
        let elsewhere = request_aad("POST", &initialize, KEY, kid, USER);
        assert!(open_upload(&transport, &upload, &elsewhere).is_err());
    }

    #[tokio::test]
    async fn another_version_opens_only_while_the_manifest_lists_it() {
        let transport = rotating().await;
        let previous = fixed_key(2);
        let aad = request_aad("POST", PATH, KEY, &previous.thumbprint(), USER);
        let upload = read(sealed_form(&previous, &aad, b"a\n")).await.unwrap();
        assert_eq!(open_upload(&transport, &upload, &aad).unwrap(), b"a\n");

        // The manifest that retires it.
        let current = keys::tests::listed(fixed_key(1).thumbprint(), None);
        transport.follow(&[current]).await.unwrap();
        assert_eq!(
            open_upload(&transport, &upload, &aad).unwrap_err().0,
            "kid names no transport key version this worker accepts"
        );
    }

    #[tokio::test]
    async fn the_form_has_exactly_the_four_parts() {
        let key = fixed_key(1);
        let kid = key.thumbprint();
        let (enc, ct) = seal(&key, b"aad", b"a,b\n");
        let good: [(&str, &[u8]); 4] = [
            ("v", b"1"),
            ("kid", kid.as_bytes()),
            ("enc", enc.as_bytes()),
            ("ct", &ct),
        ];
        assert!(read(form(&good)).await.is_ok());

        let padded = format!("{enc}=");
        let cases: Vec<Vec<(&str, &[u8])>> = vec![
            good[..3].to_vec(),
            [&good[..], &good[1..2]].concat(),
            [&good[..], &[("encrypted_data", &b"x"[..])]].concat(),
            vec![("v", &b"2"[..]), good[1], good[2], good[3]],
            vec![good[0], good[1], ("enc", padded.as_bytes()), good[3]],
            vec![good[0], good[1], ("enc", &b"not base64!"[..]), good[3]],
        ];
        for parts in cases {
            let err = read(form(&parts)).await.unwrap_err();
            assert_eq!(err.code, "sealed_payload_invalid", "{parts:?}");
            assert_eq!(err.message, "sealed payload invalid");
        }

        let err = read(form(&[("file", &b"name\nalice\n"[..])]))
            .await
            .unwrap_err();
        assert_eq!(
            (err.status, err.code),
            (StatusCode::BAD_REQUEST, "bad_request")
        );
        assert!(err.message.contains("plaintext"), "{}", err.message);
    }

    #[tokio::test]
    async fn an_invalid_encapsulated_key_is_refused() {
        let transport = only(fixed_key(1));
        let kid = fixed_key(1).thumbprint();
        let aad = request_aad("POST", PATH, KEY, &kid, USER);
        let (_, ct) = seal(&fixed_key(1), &aad, b"a\n");
        let not_a_point = URL_SAFE_NO_PAD.encode([4u8; 65]);
        let upload = read(form(&[
            ("v", &b"1"[..]),
            ("kid", kid.as_bytes()),
            ("enc", not_a_point.as_bytes()),
            ("ct", &ct),
        ]))
        .await
        .unwrap();
        assert_eq!(
            open_upload(&transport, &upload, &aad).unwrap_err().0,
            "enc isn't a P-256 public key"
        );
    }
}
