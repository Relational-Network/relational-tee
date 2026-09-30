// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A dev reference-values manifest (dev builds only).
//!
//! `relational-tee dev-manifest` (`just dev-manifest`) signs a manifest that
//! approves what dev workers present: the fake MAA's claims with the fixed
//! dev host data, the dev transport key (and its previous version, if there
//! is one) and the dev `tls-key`. It signs with the dev manifest key,
//! `manifest-signing-key.jwk` beside the other dev keys (`just dev-keys`
//! creates it), and stores the manifest where dev workers serve it. A
//! dashboard that pins that key's public half then verifies local workers
//! exactly as it verifies real ones. Release builds contain none of this:
//! CD signs their manifests.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;
use serde_json::{json, Value};

use crate::config::StorageConfig;
use crate::seal::Listed;
use crate::store::{Created, Fetched, ObjectStore, Replaced, REFERENCE_VALUES};
use crate::tee::dev_keys::{key_path, previous_key_path, private_jwk, read_key, write_private};
use crate::tee::{dev_maa, EcKey, KeyName};

/// The dev manifest key: a private JWK beside the other dev keys.
pub const SIGNING_KEY_FILE: &str = "manifest-signing-key.jwk";

/// Manifests are valid for 30 days.
const VALIDITY_DAYS: i64 = 30;

const USAGE: &str = "usage: relational-tee dev-manifest [--commit SHA] [--sequence N] [--days N] \
    [--bad expired|host-data|transport-key|signature] [--public-key]

Signs a reference-values manifest that approves the dev workers (the fake
MAA's claims and dev host data, the dev transport key and its previous
version, the dev tls-key) with the dev manifest key, and stores it as
{ENVIRONMENT}/{sequence}.jws and {ENVIRONMENT}/latest.jws in the
reference-values container of the configured storage (STORAGE_BACKEND,
DATA_DIR, STORAGE_BLOB_URL). The claim set's authority is FAKE_MAA_ISSUER
(default http://localhost:9000). The sequence defaults to the current Unix
time, and always exceeds the latest manifest's.

--public-key prints the dev manifest key's public JWK, the value for a
dashboard's VITE_MANIFEST_PUBLIC_KEY, and signs nothing. --bad signs a
manifest a dashboard must refuse: expired, approving other host data, not
listing the transport key, or signed with another key.";

/// Create `{dir}/manifest-signing-key.jwk` (EC P-256) if it's missing.
pub fn generate_missing(dir: &Path) -> io::Result<Option<PathBuf>> {
    let path = dir.join(SIGNING_KEY_FILE);
    if path.exists() {
        return Ok(None);
    }
    let key = EcKey::new(SecretKey::random(&mut OsRng));
    write_private(&path, private_jwk(&key).as_bytes())?;
    Ok(Some(path))
}

/// The public half of a manifest key, as a dashboard pins it.
pub fn public_jwk(key: &EcKey) -> Value {
    let mut jwk = key.public_jwk();
    if let Some(members) = jwk.as_object_mut() {
        members.remove("kid");
    }
    jwk
}

/// A manifest's content.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub environment: String,
    pub sequence: u64,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub claim_sets: Vec<Value>,
    /// The approved transport key versions: RFC 7638 thumbprints, and the
    /// version workers release each by.
    pub transport: Vec<Listed>,
    /// SHA-256 of each approved `tls-key` version's SubjectPublicKeyInfo.
    pub tls_spki_sha256: Vec<[u8; 32]>,
    pub commit: String,
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

impl Manifest {
    /// The manifest approving the dev workers whose keys are in `keys_dir`,
    /// with tokens from the fake MAA at `authority`, valid from `now`.
    pub fn for_dev_keys(
        keys_dir: &Path,
        environment: &str,
        authority: &str,
        commit: &str,
        sequence: u64,
        now: DateTime<Utc>,
    ) -> Result<Self, String> {
        let read = |path: PathBuf| read_key(&path).map_err(|e| e.to_string());
        let mut transport = vec![Listed {
            kid: read(key_path(keys_dir, KeyName::Transport))?.thumbprint(),
            version: None,
        }];
        let previous = previous_key_path(keys_dir, KeyName::Transport);
        if previous.exists() {
            transport.push(Listed {
                kid: read(previous)?.thumbprint(),
                version: Some("previous".into()),
            });
        }
        let tls = read(key_path(keys_dir, KeyName::Tls))?;
        Ok(Self {
            environment: environment.into(),
            sequence,
            not_before: now,
            not_after: now + Duration::days(VALIDITY_DAYS),
            claim_sets: vec![dev_maa::claim_set(authority)],
            transport,
            tls_spki_sha256: vec![crate::tls::spki_sha256(&tls)?],
            commit: commit.into(),
        })
    }

    pub fn payload(&self) -> Value {
        let transport: Vec<Value> = self
            .transport
            .iter()
            .map(|listed| match &listed.version {
                Some(version) => json!({ "kid": listed.kid, "version": version }),
                None => json!({ "kid": listed.kid }),
            })
            .collect();
        let tls: Vec<Value> = self
            .tls_spki_sha256
            .iter()
            .map(|hash| json!({ "spki_sha256": STANDARD.encode(hash) }))
            .collect();
        json!({
            "environment": self.environment,
            "sequence": self.sequence,
            "not_before": rfc3339(self.not_before),
            "not_after": rfc3339(self.not_after),
            "claim_sets": self.claim_sets,
            "keys": { "transport": transport, "tls": tls },
            "provenance": { "commit": self.commit },
        })
    }
}

/// A compact JWS (ES256) of `payload`, signed with `key` and naming its
/// thumbprint as `kid`.
pub fn sign(key: &EcKey, payload: &Value) -> Result<String, String> {
    let header = json!({ "alg": "ES256", "kid": key.thumbprint() });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let pkcs8 = key
        .secret()
        .to_pkcs8_der()
        .map_err(|e| format!("encoding the manifest key: {e}"))?;
    let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_bytes())
        .map_err(|e| format!("loading the manifest key: {e}"))?;
    let signature = signer
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .map_err(|_| "ES256 signing failed".to_string())?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    ))
}

/// The `sequence` of the JWS at `path`, if there's one there.
async fn stored_sequence(store: &dyn ObjectStore, path: &str) -> Result<Option<u64>, String> {
    let body = match store
        .get(path, None)
        .await
        .map_err(|e| format!("reading {path}: {e}"))?
    {
        Fetched::Found { body, .. } => body,
        _ => return Ok(None),
    };
    let payload = std::str::from_utf8(body.trim_ascii())
        .ok()
        .and_then(|jws| jws.split('.').nth(1))
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|p| serde_json::from_slice::<Value>(&p).ok());
    Ok(payload.and_then(|p| p["sequence"].as_u64()))
}

/// The sequence for a new manifest: the current Unix time, or one more than
/// the latest manifest's if that's higher, so it never goes down.
pub async fn next_sequence(
    store: &dyn ObjectStore,
    environment: &str,
    now: DateTime<Utc>,
) -> Result<u64, String> {
    let latest = stored_sequence(store, &format!("{environment}/latest.jws")).await?;
    let now = now.timestamp().max(0) as u64;
    Ok(latest.map_or(now, |s| now.max(s + 1)))
}

/// Store `jws` as `{environment}/{sequence}.jws`, create-only, and as
/// `{environment}/latest.jws`.
pub async fn publish(
    store: &dyn ObjectStore,
    environment: &str,
    sequence: u64,
    jws: &str,
) -> Result<(), String> {
    let numbered = format!("{environment}/{sequence}.jws");
    let created = store
        .put_if_absent(&numbered, jws.to_string().into())
        .await
        .map_err(|e| format!("writing {numbered}: {e}"))?;
    if created == Created::AlreadyExists {
        return Err(format!(
            "{numbered} already exists; pass a higher --sequence"
        ));
    }
    let latest = format!("{environment}/latest.jws");
    for _ in 0..3 {
        let written = match store
            .get(&latest, None)
            .await
            .map_err(|e| format!("reading {latest}: {e}"))?
        {
            Fetched::Found { etag, .. } => matches!(
                store
                    .put_if_match(&latest, jws.to_string().into(), &etag)
                    .await,
                Ok(Replaced::Done(_))
            ),
            _ => matches!(
                store.put_if_absent(&latest, jws.to_string().into()).await,
                Ok(Created::New(_))
            ),
        };
        if written {
            return Ok(());
        }
    }
    Err(format!("{latest} kept changing while it was being written"))
}

/// A deliberately bad manifest, for testing a dashboard's refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bad {
    Expired,
    HostData,
    TransportKey,
    Signature,
}

impl Bad {
    const ALL: [Bad; 4] = [
        Self::Expired,
        Self::HostData,
        Self::TransportKey,
        Self::Signature,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::HostData => "host-data",
            Self::TransportKey => "transport-key",
            Self::Signature => "signature",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|bad| bad.as_str() == value)
            .ok_or_else(|| format!("unknown --bad {value:?}\n\n{USAGE}"))
    }

    /// Spoil `manifest`; for [`Bad::Signature`] the signer does it.
    fn apply(self, manifest: &mut Manifest) {
        let unknown_key = || EcKey::new(SecretKey::random(&mut OsRng)).thumbprint();
        match self {
            Self::Expired => {
                manifest.not_after = manifest.not_before - Duration::days(1);
                manifest.not_before = manifest.not_after - Duration::days(VALIDITY_DAYS);
            }
            Self::HostData => {
                for set in &mut manifest.claim_sets {
                    set["x-ms-sevsnpvm-hostdata"] = json!(["00".repeat(32)]);
                }
            }
            Self::TransportKey => {
                manifest.transport = vec![Listed {
                    kid: unknown_key(),
                    version: None,
                }]
            }
            Self::Signature => {}
        }
    }
}

/// What `dev-manifest` was asked to do.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    commit: Option<String>,
    sequence: Option<u64>,
    days: Option<i64>,
    bad: Option<Bad>,
    public_key: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut parsed = Args::default();
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n\n{USAGE}"))
        };
        let positive = |v: String| {
            v.parse::<u32>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{flag} needs a positive whole number\n\n{USAGE}"))
        };
        match flag.as_str() {
            "--commit" => parsed.commit = Some(value()?),
            "--sequence" => {
                parsed.sequence = Some(
                    value()?
                        .parse()
                        .map_err(|_| format!("--sequence needs a whole number\n\n{USAGE}"))?,
                )
            }
            "--days" => parsed.days = Some(positive(value()?)?.into()),
            "--bad" => parsed.bad = Some(Bad::parse(&value()?)?),
            "--public-key" => parsed.public_key = true,
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
        }
    }
    Ok(parsed)
}

/// The `reference-values` container of the configured storage.
async fn open_store(storage: StorageConfig) -> Result<Arc<dyn ObjectStore>, String> {
    Ok(match storage {
        StorageConfig::Azure(azure) => {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let blob = crate::store::azure::AzureBlob::new(&azure, REFERENCE_VALUES)?;
            blob.ensure_container()
                .await
                .map_err(|e| format!("preparing {REFERENCE_VALUES} at {}: {e}", azure.blob_url))?;
            Arc::new(blob)
        }
        StorageConfig::Files { dir } => Arc::new(crate::store::files::LocalFiles::new(
            dir.join(REFERENCE_VALUES),
        )),
    })
}

async fn run_inner(args: &[String]) -> Result<(), String> {
    let args = parse_args(args)?;
    let lookup = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
    let keys_dir = PathBuf::from(
        lookup("DEV_KEYS_DIR").unwrap_or_else(|| crate::tee::dev_keys::DEFAULT_DIR.into()),
    );
    let signing_key = read_key(&keys_dir.join(SIGNING_KEY_FILE)).map_err(|e| e.to_string())?;
    let pinned = public_jwk(&signing_key).to_string();
    if args.public_key {
        println!("{pinned}");
        return Ok(());
    }

    let environment = crate::config::environment_from_lookup(&lookup)?;
    let authority = lookup("FAKE_MAA_ISSUER").unwrap_or_else(|| dev_maa::DEFAULT_ISSUER.into());
    let store = open_store(crate::config::storage_from_lookup(&lookup)?).await?;
    let now = Utc::now();
    let sequence = match args.sequence {
        Some(sequence) => sequence,
        None => next_sequence(store.as_ref(), &environment, now).await?,
    };
    let mut manifest = Manifest::for_dev_keys(
        &keys_dir,
        &environment,
        authority.trim_end_matches('/'),
        args.commit.as_deref().unwrap_or("dev"),
        sequence,
        now,
    )?;
    if let Some(days) = args.days {
        manifest.not_after = now + Duration::days(days);
    }
    let signer = match args.bad {
        Some(bad) => {
            bad.apply(&mut manifest);
            if bad == Bad::Signature {
                EcKey::new(SecretKey::random(&mut OsRng))
            } else {
                signing_key
            }
        }
        None => signing_key,
    };
    let jws = sign(&signer, &manifest.payload())?;
    publish(store.as_ref(), &environment, sequence, &jws).await?;

    let label = args.bad.map_or(String::new(), |bad| {
        format!(" (deliberately bad: {})", bad.as_str())
    });
    println!(
        "Signed {REFERENCE_VALUES}/{environment}/{sequence}.jws and latest.jws{label}, valid {} to {}",
        rfc3339(manifest.not_before),
        rfc3339(manifest.not_after),
    );
    println!("VITE_MANIFEST_PUBLIC_KEY={pinned}");
    Ok(())
}

/// Run `relational-tee dev-manifest`. Returns the exit code.
pub async fn run(args: &[String]) -> i32 {
    match run_inner(args).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Attestation;
    use crate::reference_values::ReferenceValues;
    use crate::seal::TransportKeys;
    use crate::state::AppState;
    use crate::store::files::LocalFiles;
    use crate::tee::dev_keys::generate_missing as generate_dev_keys;
    use crate::tee::local::LocalDev;
    use crate::tee::KeyProvider;
    use crate::tee::WorkerKeys;
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn temp_keys() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("relational-tee-manifest-{}", uuid::Uuid::new_v4()));
        generate_dev_keys(&dir).expect("dev keys");
        dir
    }

    /// The payload of `jws` if its ES256 signature verifies with `jwk`, as
    /// a dashboard checks it.
    fn verify_es256(jws: &str, jwk: &Value) -> Option<Value> {
        let (signing_input, signature) = jws.rsplit_once('.')?;
        let coordinate = |name: &str| URL_SAFE_NO_PAD.decode(jwk[name].as_str()?).ok();
        let point = [vec![4], coordinate("x")?, coordinate("y")?].concat();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
            .verify(
                signing_input.as_bytes(),
                &URL_SAFE_NO_PAD.decode(signature).ok()?,
            )
            .ok()?;
        let payload = URL_SAFE_NO_PAD
            .decode(signing_input.split_once('.')?.1)
            .ok()?;
        serde_json::from_slice(&payload).ok()
    }

    async fn get(app: &axum::Router, path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let body = to_bytes(body, 1 << 20).await.unwrap().to_vec();
        (parts.status, parts.headers, body)
    }

    #[tokio::test]
    async fn the_dev_manifest_approves_what_a_dev_worker_serves() {
        let dir = temp_keys();
        let provider = LocalDev::new(dir.clone());
        let keys = WorkerKeys::release_all(&provider).await.expect("keys");
        let transport_kid = keys.get(KeyName::Transport).current.thumbprint();
        let attestation = Attestation::new(&keys.get(KeyName::Transport).current);
        attestation.refresh(&provider).await.expect("dev token");
        let transport = Arc::new(TransportKeys::new(
            keys.get(KeyName::Transport).current.clone(),
            Arc::new(LocalDev::new(dir.clone())),
        ));

        let store = Arc::new(LocalFiles::temporary());
        let now = Utc::now();
        let sequence = next_sequence(store.as_ref(), "dev", now).await.unwrap();
        let authority = dev_maa::DEFAULT_ISSUER;
        let manifest =
            Manifest::for_dev_keys(&dir, "dev", authority, "abc123", sequence, now).unwrap();
        let signing_key = read_key(&dir.join(SIGNING_KEY_FILE)).unwrap();
        let jws = sign(&signing_key, &manifest.payload()).unwrap();
        publish(store.as_ref(), "dev", sequence, &jws)
            .await
            .unwrap();

        let mut state = AppState::for_tests();
        state.reference_values = Arc::new(ReferenceValues::new(
            store.clone(),
            "dev",
            transport.clone(),
        ));
        state.reference_values.refresh().await.unwrap();
        state.transport = transport;
        state.attestation = Arc::new(attestation);
        let app = crate::router(state);

        // What a dashboard checks, in order: the manifest's signature and window...
        let (status, headers, served) = get(&app, "/v1/reference-values").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "application/jose");
        let served = String::from_utf8(served).unwrap();
        let manifest = verify_es256(&served, &public_jwk(&signing_key)).expect("signed");
        let window =
            |name: &str| DateTime::parse_from_rfc3339(manifest[name].as_str().unwrap()).unwrap();
        assert!(window("not_before") <= Utc::now() && Utc::now() < window("not_after"));
        assert_eq!(manifest["sequence"], sequence);
        assert_eq!(manifest["environment"], "dev");
        assert_eq!(manifest["provenance"]["commit"], "abc123");

        // ...the MAA token's signature, issuer and claims...
        let (status, _, body) = get(&app, "/v1/attestation").await;
        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&body).unwrap();
        let jwks = dev_maa::DevMaa::load(&dir, authority).unwrap().jwks();
        let claims = dev_maa::tests::verify(body["maa_token"].as_str().unwrap(), &jwks, authority);
        let approved = manifest["claim_sets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|set| {
                set["authority"] == authority
                    && set["x-ms-attestation-type"] == claims["x-ms-attestation-type"]
                    && set["x-ms-compliance-status"] == claims["x-ms-compliance-status"]
                    && claims["x-ms-sevsnpvm-is-debuggable"] == false
                    && claims["x-ms-sevsnpvm-vmpl"] == 0
                    && set["x-ms-sevsnpvm-hostdata"]
                        .as_array()
                        .unwrap()
                        .contains(&claims["x-ms-sevsnpvm-hostdata"])
            });
        assert!(approved, "{claims}");

        // ...and the served transport key: bound in the token, and listed.
        assert_eq!(claims["x-ms-runtime"]["keys"][0], body["transport_jwk"]);
        assert_eq!(body["kid"], body["transport_jwk"]["kid"]);
        assert_eq!(body["kid"], transport_kid.as_str());
        assert!(manifest["keys"]["transport"]
            .as_array()
            .unwrap()
            .contains(&json!({ "kid": body["kid"] })));
        let tls = read_key(&key_path(&dir, KeyName::Tls)).unwrap();
        assert_eq!(
            manifest["keys"]["tls"][0]["spki_sha256"],
            STANDARD.encode(crate::tls::spki_sha256(&tls).unwrap())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn sequences_only_go_up_and_each_is_signed_once() {
        let store = LocalFiles::temporary();
        let now = Utc::now();
        let first = next_sequence(&store, "dev", now).await.unwrap();
        assert_eq!(first, now.timestamp() as u64);
        let jws = |sequence: u64| {
            crate::reference_values::tests::unsigned_jws(&json!({ "sequence": sequence }))
        };
        publish(&store, "dev", first + 100, &jws(first + 100))
            .await
            .unwrap();
        assert_eq!(
            next_sequence(&store, "dev", now).await.unwrap(),
            first + 101
        );
        assert!(publish(&store, "dev", first + 100, &jws(first + 100))
            .await
            .is_err());
        publish(&store, "dev", 3, &jws(3)).await.unwrap();
        let Fetched::Found { body, .. } = store.get("dev/latest.jws", None).await.unwrap() else {
            panic!("latest");
        };
        assert_eq!(
            body,
            jws(3).as_bytes(),
            "an explicit sequence is written as asked"
        );
        assert!(matches!(
            store
                .get(&format!("dev/{}.jws", first + 100), None)
                .await
                .unwrap(),
            Fetched::Found { .. }
        ));
    }

    #[test]
    fn bad_manifests_fail_the_check_they_name() {
        let dir = temp_keys();
        let now = Utc::now();
        let good =
            Manifest::for_dev_keys(&dir, "dev", "http://localhost:9000", "c", 5, now).unwrap();
        let spoiled = |bad: Bad| {
            let mut manifest = good.clone();
            bad.apply(&mut manifest);
            manifest
        };
        let expired = spoiled(Bad::Expired);
        assert!(expired.not_after < now && expired.not_before < expired.not_after);
        assert_ne!(
            spoiled(Bad::HostData).claim_sets[0]["x-ms-sevsnpvm-hostdata"],
            good.claim_sets[0]["x-ms-sevsnpvm-hostdata"]
        );
        let current = &good.transport[0].kid;
        assert!(spoiled(Bad::TransportKey)
            .transport
            .iter()
            .all(|listed| &listed.kid != current));
        assert_eq!(spoiled(Bad::Signature).payload(), good.payload());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_listed_previous_transport_key_version_opens_on_a_dev_worker() {
        let dir = temp_keys();
        let previous_path = previous_key_path(&dir, KeyName::Transport);
        std::fs::copy(key_path(&dir, KeyName::StorageRoot), &previous_path).unwrap();
        let previous = read_key(&previous_path).unwrap();
        let manifest = Manifest::for_dev_keys(&dir, "dev", "x", "c", 5, Utc::now()).unwrap();
        assert_eq!(
            manifest.payload()["keys"]["transport"][1],
            json!({ "kid": previous.thumbprint(), "version": "previous" })
        );

        let provider = Arc::new(LocalDev::new(dir.clone()));
        let current = provider.release(KeyName::Transport).await.unwrap().current;
        let transport = Arc::new(TransportKeys::new(current, provider));
        assert!(transport.get(&previous.thumbprint()).is_none());
        let store = Arc::new(LocalFiles::temporary());
        let jws = sign(
            &read_key(&dir.join(SIGNING_KEY_FILE)).unwrap(),
            &manifest.payload(),
        );
        publish(store.as_ref(), "dev", 5, &jws.unwrap())
            .await
            .unwrap();
        ReferenceValues::new(store, "dev", transport.clone())
            .refresh()
            .await
            .unwrap();
        assert_eq!(
            transport.get(&previous.thumbprint()).unwrap().public_key(),
            previous.public_key()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn flags_shape_the_manifest() {
        let args =
            |list: &[&str]| parse_args(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(args(&[]).unwrap(), Args::default());
        let parsed = args(&["--commit", "abc", "--sequence", "7", "--bad", "expired"]).unwrap();
        assert_eq!(parsed.commit.as_deref(), Some("abc"));
        assert_eq!(parsed.sequence, Some(7));
        assert_eq!(parsed.bad, Some(Bad::Expired));
        assert!(args(&["--public-key"]).unwrap().public_key);
        assert_eq!(args(&["--days", "2"]).unwrap().days, Some(2));
        for bad in [
            &["--days", "0"][..],
            &["--sequence", "-1"],
            &["--bad", "nope"],
            &["--commit"],
            &["--frobnicate"],
        ] {
            assert!(args(bad).is_err(), "{bad:?}");
        }
    }
}
