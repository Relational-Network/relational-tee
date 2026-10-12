// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! TLS with `tls-key`.
//!
//! The private key is `tls-key`, released to attested workers and never
//! written anywhere. Its certificate chain lives in the `tls` container,
//! unsealed, at `{spki_sha256}/chain.pem`, where `spki_sha256` is the
//! lowercase hex SHA-256 of the key's SubjectPublicKeyInfo, so a chain
//! belongs to one key version and clients can pin the key across renewals.
//!
//! While a key has no chain, the worker writes a CSR for the API hostname,
//! signed with `tls-key`, to `{spki_sha256}/csr.pem`, create-only: the first
//! worker's write wins and the others find it there. Something outside the
//! worker (the certificate job) signs it and writes `chain.pem`. The worker
//! checks for the chain every 10 seconds until it has one, then every 5
//! minutes, and swaps a new one in through the certificate resolver, with no
//! restart.
//!
//! It serves a chain only if the leaf's public key is `tls-key`'s and a
//! client would accept it now: rustls's own server certificate verifier
//! checks that it chains to a root in Mozilla's set, that each certificate
//! is within its validity, and that the leaf names the API hostname and may
//! serve TLS. Dev builds also trust the last certificate a chain carries, so
//! a local CA's chain, or a self-signed one, serves there. Any other chain
//! is ignored and raises an alert, and the chain already served stays until
//! it expires.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use p256::pkcs8::EncodePrivateKey;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::store::{Created, ETag, Fetched, ObjectStore};
use crate::tee::EcKey;

/// How often to look for a chain before the first one loads.
const FIRST_CHAIN_POLL: Duration = Duration::from_secs(10);
/// How often to look for a renewed chain.
const CHAIN_POLL: Duration = Duration::from_secs(5 * 60);

/// A chain being served.
struct Served {
    certified: Arc<CertifiedKey>,
    not_after: Option<DateTime<Utc>>,
    etag: ETag,
}

/// `tls-key`, its CSR, and the chain currently served for it.
pub struct Certificates {
    key: Arc<dyn SigningKey>,
    spki_sha256: String,
    /// The API hostname, which a served leaf must name.
    hostname: String,
    csr_pem: String,
    store: Arc<dyn ObjectStore>,
    served: RwLock<Option<Served>>,
    csr_written: AtomicBool,
    /// Roots trusted besides Mozilla's: only tests' own CAs.
    trusted: Vec<CertificateDer<'static>>,
}

/// Whether a client trusting Mozilla's roots, and `trusted`, would accept
/// `chain` for `hostname` at `now`.
fn verify_chain(
    chain: &[CertificateDer<'static>],
    trusted: &[CertificateDer<'static>],
    hostname: &str,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or_else(|| "the chain holds no certificate".to_string())?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for root in trusted {
        roots
            .add(root.clone())
            .map_err(|e| format!("a trusted root doesn't parse: {e}"))?;
    }
    #[cfg(feature = "dev")]
    if let Some(root) = chain.last() {
        // Dev builds only: a local CA's root, or a self-signed leaf.
        let _ = roots.add(root.clone());
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|e| format!("building the verifier: {e}"))?;
    let name = ServerName::try_from(hostname.to_string())
        .map_err(|e| format!("{hostname:?} isn't a server name: {e}"))?;
    let seconds = u64::try_from(now.timestamp()).unwrap_or_default();
    verifier
        .verify_server_cert(
            leaf,
            intermediates,
            &name,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

impl fmt::Debug for Certificates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificates")
            .field("spki_sha256", &self.spki_sha256)
            .finish_non_exhaustive()
    }
}

/// What `/health` reports about the served chain.
pub struct Status {
    pub spki_sha256: String,
    pub loaded: bool,
    pub not_after: Option<DateTime<Utc>>,
}

/// The SHA-256 of `key`'s SubjectPublicKeyInfo: in hex it names the key's
/// chain and CSR, and the reference values pin it.
pub fn spki_sha256(key: &EcKey) -> Result<[u8; 32], String> {
    let pkcs8 = key
        .secret()
        .to_pkcs8_der()
        .map_err(|e| format!("encoding the key: {e}"))?;
    let key_pair = KeyPair::try_from(&PrivatePkcs8KeyDer::from(pkcs8.as_bytes()))
        .map_err(|e| format!("loading the key: {e}"))?;
    Ok(Sha256::digest(key_pair.subject_public_key_info()).into())
}

/// The names a CSR asks for: the API hostname and, for `localhost`, the
/// loopback addresses too.
fn csr_names(hostname: &str) -> Vec<String> {
    let mut names = vec![hostname.to_string()];
    if hostname == "localhost" {
        names.extend(["127.0.0.1".to_string(), "::1".to_string()]);
    }
    names
}

impl Certificates {
    /// Prepare `tls_key` to serve `hostname`, with chains and CSRs in `store`
    /// (the `tls` container).
    pub fn new(
        tls_key: &EcKey,
        hostname: &str,
        store: Arc<dyn ObjectStore>,
    ) -> Result<Self, String> {
        let pkcs8 = tls_key
            .secret()
            .to_pkcs8_der()
            .map_err(|e| format!("encoding tls-key: {e}"))?;
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes());
        let key =
            rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(der.clone_key()))
                .map_err(|e| format!("loading tls-key: {e}"))?;
        let key_pair = KeyPair::try_from(&der).map_err(|e| format!("loading tls-key: {e}"))?;
        let spki_sha256 = hex::encode(spki_sha256(tls_key)?);

        let mut params =
            CertificateParams::new(csr_names(hostname)).map_err(|e| format!("CSR names: {e}"))?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, hostname);
        let csr_pem = params
            .serialize_request(&key_pair)
            .and_then(|csr| csr.pem())
            .map_err(|e| format!("creating the CSR: {e}"))?;

        Ok(Self {
            key,
            spki_sha256,
            hostname: hostname.to_string(),
            csr_pem,
            store,
            served: RwLock::new(None),
            csr_written: AtomicBool::new(false),
            trusted: Vec::new(),
        })
    }

    /// Also trust chains from `root`, a test's own CA.
    #[cfg(test)]
    pub(crate) fn trust(&mut self, root: CertificateDer<'static>) {
        self.trusted.push(root);
    }

    pub fn spki_sha256(&self) -> &str {
        &self.spki_sha256
    }

    fn chain_path(&self) -> String {
        format!("{}/chain.pem", self.spki_sha256)
    }

    fn csr_path(&self) -> String {
        format!("{}/csr.pem", self.spki_sha256)
    }

    /// Whether a chain is loaded and its leaf hasn't expired.
    pub fn valid(&self) -> bool {
        self.valid_at(Utc::now())
    }

    fn valid_at(&self, now: DateTime<Utc>) -> bool {
        self.served.read().is_ok_and(|served| {
            served
                .as_ref()
                .is_some_and(|s| s.not_after.is_some_and(|t| t > now))
        })
    }

    pub fn status(&self) -> Status {
        let served = self.served.read().ok();
        let served = served.as_ref().and_then(|s| s.as_ref());
        Status {
            spki_sha256: self.spki_sha256.clone(),
            loaded: served.is_some(),
            not_after: served.and_then(|s| s.not_after),
        }
    }

    /// Look for the chain once: load a new one, or write the CSR if there's
    /// none yet. A served chain that has expired raises an alert.
    pub async fn refresh(&self) -> Result<(), String> {
        let cached = self
            .served
            .read()
            .ok()
            .and_then(|s| s.as_ref().map(|s| s.etag.clone()));
        let path = self.chain_path();
        let result = match self
            .store
            .get(&path, cached.as_ref())
            .await
            .map_err(|e| format!("reading {path}: {e}"))?
        {
            Fetched::NotModified => Ok(()),
            Fetched::Missing => self.write_csr().await,
            Fetched::Found { body, etag } => self.load(&body, etag),
        };
        if let Some(not_after) = self.status().not_after.filter(|t| *t <= Utc::now()) {
            error!(
                alert = "tls_chain_expired",
                chain = %path,
                not_after = %not_after.to_rfc3339(),
                "The served certificate chain has expired, and no valid one replaced it"
            );
        }
        result
    }

    async fn write_csr(&self) -> Result<(), String> {
        if self.csr_written.load(Ordering::Relaxed) {
            return Ok(());
        }
        let path = self.csr_path();
        let created = self
            .store
            .put_if_absent(&path, self.csr_pem.clone().into())
            .await
            .map_err(|e| format!("writing {path}: {e}"))?;
        match created {
            Created::New(_) => {
                info!(csr = %path, "Wrote a CSR for tls-key; waiting for its chain")
            }
            Created::AlreadyExists => {
                info!(csr = %path, "Waiting for the chain of tls-key's CSR")
            }
        }
        self.csr_written.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn load(&self, pem: &[u8], etag: ETag) -> Result<(), String> {
        let chain = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|e| format!("reading {}: {e}", self.chain_path()))?;
        let Some(leaf) = chain.first() else {
            return Err(format!("{} holds no certificate", self.chain_path()));
        };
        let not_after = not_after(leaf.as_ref());
        let certified = CertifiedKey::new(chain, self.key.clone());
        if let Err(e) = certified.keys_match() {
            error!(
                alert = "tls_chain_mismatch",
                chain = %self.chain_path(),
                error = %e,
                "Ignoring a certificate chain whose key isn't tls-key"
            );
            return Err(format!("{} doesn't match tls-key", self.chain_path()));
        }
        if let Err(e) = verify_chain(&certified.cert, &self.trusted, &self.hostname, Utc::now()) {
            error!(
                alert = "tls_chain_invalid",
                chain = %self.chain_path(),
                error = %e,
                "Ignoring a certificate chain a client wouldn't accept; the served one stays"
            );
            return Err(format!("{} isn't valid: {e}", self.chain_path()));
        }
        info!(
            chain = %self.chain_path(),
            not_after = ?not_after.map(|t| t.to_rfc3339()),
            "Serving a new certificate chain"
        );
        if let Ok(mut served) = self.served.write() {
            *served = Some(Served {
                certified: Arc::new(certified),
                not_after,
                etag,
            });
        }
        Ok(())
    }

    /// Look for chains in the background, for the process lifetime.
    pub fn spawn(self: &Arc<Self>) {
        let certificates = Arc::clone(self);
        crate::work::supervise("certificates", move || {
            let certificates = certificates.clone();
            async move {
                loop {
                    if let Err(e) = certificates.refresh().await {
                        warn!(error = %e, "Certificate chain check failed");
                    }
                    let loaded = certificates.served.read().is_ok_and(|s| s.is_some());
                    tokio::time::sleep(if loaded { CHAIN_POLL } else { FIRST_CHAIN_POLL }).await;
                }
            }
        });
    }

    /// The rustls configuration serving the current chain: TLS 1.3 only
    /// (rustls is built without TLS 1.2), with aws-lc-rs's AES-GCM and
    /// ChaCha20-Poly1305 suites.
    pub fn server_config(self: &Arc<Self>) -> Arc<rustls::ServerConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("aws-lc-rs supports TLS 1.3")
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.served
            .read()
            .ok()?
            .as_ref()
            .map(|s| s.certified.clone())
    }
}

/// One DER element: its tag, its contents, and what follows it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        l if l < 0x80 => (l as usize, rest),
        0x81..=0x84 => {
            let n = (first & 0x7f) as usize;
            if rest.len() < n {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (len, &rest[n..])
        }
        _ => return None,
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

const SEQUENCE: u8 = 0x30;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;

/// The `notAfter` of a DER certificate.
pub fn not_after(der: &[u8]) -> Option<DateTime<Utc>> {
    let (tag, certificate, _) = element(der)?;
    (tag == SEQUENCE).then_some(())?;
    let (tag, tbs, _) = element(certificate)?;
    (tag == SEQUENCE).then_some(())?;
    let mut fields = tbs;
    if fields.first() == Some(&VERSION) {
        fields = element(fields)?.2;
    }
    // serialNumber, signature, issuer, then validity.
    for _ in 0..3 {
        fields = element(fields)?.2;
    }
    let (tag, validity, _) = element(fields)?;
    (tag == SEQUENCE).then_some(())?;
    let (_, _, rest) = element(validity)?;
    let (tag, time, _) = element(rest)?;
    let text = std::str::from_utf8(time).ok()?;
    let parsed = match tag {
        UTC_TIME => {
            // Two-digit years: 50–99 are 19xx, 00–49 are 20xx (RFC 5280).
            let year: u32 = text.get(..2)?.parse().ok()?;
            let century = if year >= 50 { "19" } else { "20" };
            NaiveDateTime::parse_from_str(&format!("{century}{text}"), "%Y%m%d%H%M%SZ").ok()?
        }
        GENERALIZED_TIME => NaiveDateTime::parse_from_str(text, "%Y%m%d%H%M%SZ").ok()?,
        _ => return None,
    };
    Some(parsed.and_utc())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::store::files::LocalFiles;
    use crate::tee::tests::fixed_key;
    use rustls::pki_types::CertificateSigningRequestDer;

    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(contents.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(contents);
        out
    }

    /// A certificate skeleton with the given validity times.
    fn certificate(not_before: (u8, &str), not_after: (u8, &str), padding: usize) -> Vec<u8> {
        let tbs = [
            der(VERSION, &der(0x02, &[2])),
            der(0x02, &[1]),
            der(SEQUENCE, &[]),
            der(SEQUENCE, &vec![0x05; padding]),
            der(
                SEQUENCE,
                &[
                    der(not_before.0, not_before.1.as_bytes()),
                    der(not_after.0, not_after.1.as_bytes()),
                ]
                .concat(),
            ),
        ]
        .concat();
        der(SEQUENCE, &der(SEQUENCE, &tbs))
    }

    #[test]
    fn reads_utc_and_generalized_times() {
        let utc = certificate((UTC_TIME, "250101000000Z"), (UTC_TIME, "351231235959Z"), 0);
        assert_eq!(
            not_after(&utc).unwrap().to_rfc3339(),
            "2035-12-31T23:59:59+00:00"
        );
        let generalized = certificate(
            (UTC_TIME, "250101000000Z"),
            (GENERALIZED_TIME, "20600101000000Z"),
            300,
        );
        assert_eq!(
            not_after(&generalized).unwrap().to_rfc3339(),
            "2060-01-01T00:00:00+00:00"
        );
        assert!(not_after(&utc[..utc.len() - 4]).is_none());
        assert!(not_after(b"not der").is_none());
    }

    type Ca = rcgen::CertifiedIssuer<'static, KeyPair>;

    /// Make `params` valid from `from` days from now until `to` days from now.
    fn valid_between(params: &mut CertificateParams, (from, to): (i64, i64)) {
        use chrono::Datelike;
        let day = |days: i64| {
            let t = Utc::now() + chrono::Duration::days(days);
            rcgen::date_time_ymd(t.year(), t.month() as u8, t.day() as u8)
        };
        params.not_before = day(from);
        params.not_after = day(to);
    }

    /// A CA of the tests' own, which no client trusts but the tests'.
    fn ca(name: &str) -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        valid_between(&mut params, (-10, 3650));
        rcgen::CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
    }

    /// A PEM leaf for `key` naming `host`, valid from `from` days from now
    /// until `to` days from now, issued by `issuer`.
    fn leaf(issuer: &Ca, key: &EcKey, host: &str, validity: (i64, i64)) -> String {
        let mut params = CertificateParams::new(vec![host.to_string()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        valid_between(&mut params, validity);
        params.signed_by(&key_pair(key), issuer).unwrap().pem()
    }

    /// A chain for tls-key, test key 3, as a CA would issue it for 30 days.
    fn good(ca: &Ca, days: i64) -> String {
        leaf(ca, &fixed_key(3), "localhost", (-1, days))
    }

    fn key_pair(key: &EcKey) -> KeyPair {
        let pkcs8 = key.secret().to_pkcs8_der().unwrap();
        KeyPair::try_from(&PrivatePkcs8KeyDer::from(pkcs8.as_bytes())).unwrap()
    }

    /// Certificates for test key 3 over `store`, trusting `ca`.
    fn certificates(store: Arc<LocalFiles>, ca: &Ca) -> Certificates {
        let mut certificates = Certificates::new(&fixed_key(3), "localhost", store).unwrap();
        certificates.trust(ca.der().clone());
        certificates
    }

    /// Certificates serving a valid chain, for readiness tests.
    pub(crate) fn serving() -> Arc<Certificates> {
        let ca = ca("Test CA");
        let certificates = certificates(Arc::new(LocalFiles::temporary()), &ca);
        certificates
            .load(good(&ca, 30).as_bytes(), ETag("\"test\"".into()))
            .unwrap();
        Arc::new(certificates)
    }

    async fn body(store: &LocalFiles, path: &str) -> Option<String> {
        match store.get(path, None).await.unwrap() {
            Fetched::Found { body, .. } => Some(String::from_utf8(body.to_vec()).unwrap()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn writes_one_csr_then_serves_only_a_chain_for_tls_key() {
        let ca = ca("Test CA");
        let store = Arc::new(LocalFiles::temporary());
        let a = certificates(store.clone(), &ca);
        let b = certificates(store.clone(), &ca);
        assert_eq!(a.spki_sha256().len(), 64);
        assert_eq!(a.spki_sha256(), b.spki_sha256(), "keyed by the public key");

        a.refresh().await.unwrap();
        b.refresh().await.unwrap();
        let csr = body(&store, &a.csr_path()).await.expect("a CSR");
        assert_eq!(csr, a.csr_pem, "the first write wins");
        let csr_der =
            CertificateSigningRequestDer::from_pem_slice(csr.as_bytes()).expect("a PEM CSR");
        let spki = key_pair(&fixed_key(3)).subject_public_key_info();
        assert!(
            csr_der.as_ref().windows(spki.len()).any(|w| w == spki),
            "the CSR is for tls-key"
        );
        assert!(!a.valid() && !a.status().loaded);

        // A chain for another key is ignored.
        let foreign = leaf(&ca, &fixed_key(4), "localhost", (-1, 30));
        store
            .put_if_absent(&a.chain_path(), foreign.into())
            .await
            .unwrap();
        assert!(a.refresh().await.is_err());
        assert!(!a.valid());

        // The right one is served, and swapped when it changes.
        let store = Arc::new(LocalFiles::temporary());
        let c = certificates(store.clone(), &ca);
        store
            .put_if_absent(&c.chain_path(), good(&ca, 30).into())
            .await
            .unwrap();
        c.refresh().await.unwrap();
        assert!(c.valid());
        let first = c.status().not_after.unwrap();
        assert!(first > Utc::now() + chrono::Duration::days(29));
        c.refresh().await.unwrap();

        let Fetched::Found { etag, .. } = store.get(&c.chain_path(), None).await.unwrap() else {
            panic!("chain");
        };
        store
            .put_if_match(&c.chain_path(), good(&ca, 60).into(), &etag)
            .await
            .unwrap();
        c.refresh().await.unwrap();
        assert!(c.status().not_after.unwrap() > first + chrono::Duration::days(29));
    }

    #[test]
    fn a_candidate_a_client_would_refuse_leaves_the_good_chain_serving() {
        let trusted = ca("Test CA");
        let other = ca("Other CA");
        let certificates = certificates(Arc::new(LocalFiles::temporary()), &trusted);
        certificates
            .load(good(&trusted, 30).as_bytes(), ETag("\"good\"".into()))
            .unwrap();
        let served = certificates.status().not_after;

        let intermediate = {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .distinguished_name
                .push(DnType::CommonName, "Test Intermediate");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            valid_between(&mut params, (-5, 365));
            rcgen::CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), &trusted)
                .unwrap()
        };
        let key = fixed_key(3);
        let complete = format!(
            "{}{}",
            leaf(&intermediate, &key, "localhost", (-1, 90)),
            intermediate.pem()
        );
        let candidates = [
            ("expired", good(&trusted, -1)),
            ("not yet valid", leaf(&trusted, &key, "localhost", (2, 30))),
            (
                "for another host",
                leaf(&trusted, &key, "api.pilot.example", (-1, 30)),
            ),
            (
                "for another key",
                leaf(&trusted, &fixed_key(4), "localhost", (-1, 30)),
            ),
            (
                "from an untrusted CA",
                leaf(&other, &key, "localhost", (-1, 30)),
            ),
            (
                "without its intermediate",
                leaf(&intermediate, &key, "localhost", (-1, 30)),
            ),
            ("not PEM", "-----BEGIN CERTIFICATE-----\nnope\n".to_string()),
            ("empty", String::new()),
        ];
        for (what, pem) in candidates {
            if what == "from an untrusted CA" && cfg!(feature = "dev") {
                // Dev builds trust the last certificate a chain carries.
                continue;
            }
            assert!(
                certificates
                    .load(pem.as_bytes(), ETag(format!("\"{what}\"")))
                    .is_err(),
                "{what}"
            );
            assert_eq!(certificates.status().not_after, served, "{what}");
            assert!(certificates.valid(), "{what}");
        }

        // A complete renewal replaces it, and readiness follows its expiry.
        certificates
            .load(complete.as_bytes(), ETag("\"renewed\"".into()))
            .unwrap();
        assert!(certificates.status().not_after > served);
        assert!(!certificates.valid_at(Utc::now() + chrono::Duration::days(91)));
    }

    #[cfg(feature = "dev")]
    #[test]
    fn dev_builds_also_trust_a_root_the_chain_carries() {
        let local = ca("Local CA");
        let certificates = Certificates::new(
            &fixed_key(3),
            "localhost",
            Arc::new(LocalFiles::temporary()),
        )
        .unwrap();
        let chain = format!("{}{}", good(&local, 30), local.pem());
        certificates
            .load(chain.as_bytes(), ETag("\"local\"".into()))
            .unwrap();
        assert!(certificates.valid());
    }

    #[test]
    fn localhost_csrs_also_name_the_loopback_addresses() {
        assert_eq!(csr_names("api.pilot.example"), vec!["api.pilot.example"]);
        assert_eq!(
            csr_names("localhost"),
            vec!["localhost", "127.0.0.1", "::1"]
        );
    }
}
