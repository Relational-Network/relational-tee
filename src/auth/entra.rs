// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Entra ID access token validation.
//!
//! A token is accepted only if it is RS256, signed by a key from the pinned
//! tenant's JWKS, and carries the exact `iss` and `tid` of that tenant, the
//! API's client ID as `aud`, an allowed client as `azp`, and a `scp` that
//! includes `access_as_user`; `exp` and `nbf` hold with 60 seconds of skew.
//! The `rsa` crate is never involved: jsonwebtoken verifies RS256 through
//! aws-lc-rs, with public keys only.
//!
//! Dev builds trust one more key, the dev token signing key, so tests and
//! scripts can mint tokens offline. Release builds contain no such key.

use std::collections::HashSet;
use std::sync::Arc;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use super::jwks::{HttpKeySource, KeySet, KeySource};
use crate::config::EntraConfig;

/// The delegated scope every user token must carry.
pub const SCOPE: &str = "access_as_user";

/// Clock skew allowed on `exp` and `nbf`, in seconds.
pub const LEEWAY_SECS: u64 = 60;

/// Why a token was refused. Logged, never returned to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    Malformed(String),
    Algorithm,
    UnknownKey,
    Invalid(String),
    Tenant,
    Client,
    Scope,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "malformed token: {e}"),
            Self::Algorithm => f.write_str("the algorithm isn't RS256"),
            Self::UnknownKey => f.write_str("no trusted key has the token's kid"),
            Self::Invalid(e) => write!(f, "{e}"),
            Self::Tenant => f.write_str("the tid isn't the pinned tenant"),
            Self::Client => f.write_str("the azp isn't an allowed client"),
            Self::Scope => f.write_str("the scp doesn't include access_as_user"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawClaims {
    tid: String,
    oid: String,
    azp: String,
    #[serde(default)]
    scp: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// What a valid token says about its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub tid: String,
    pub oid: String,
    pub roles: Vec<String>,
    pub email: Option<String>,
    pub name: Option<String>,
}

/// Validates access tokens for one tenant and API.
pub struct Verifier {
    config: EntraConfig,
    issuer: String,
    keys: KeySet,
    /// The dev token signing key: `(kid, key)`.
    #[cfg(feature = "dev")]
    dev_key: Option<(String, DecodingKey)>,
}

impl Verifier {
    /// Trust the tenant's keys from Entra ID's JWKS endpoint.
    pub fn for_entra(config: EntraConfig) -> Self {
        let source = Arc::new(HttpKeySource::new(config.jwks_url()));
        Self::with_source(config, source)
    }

    /// Trust the keys `source` serves.
    pub fn with_source(config: EntraConfig, source: Arc<dyn KeySource>) -> Self {
        Self {
            issuer: config.issuer(),
            config,
            keys: KeySet::new(source),
            #[cfg(feature = "dev")]
            dev_key: None,
        }
    }

    /// Also trust the dev token signing key, whose public half is `n` and
    /// `e` (base64url) and whose `kid` is `kid`.
    #[cfg(feature = "dev")]
    pub fn trust_dev_key(mut self, kid: String, n: &str, e: &str) -> Result<Self, String> {
        let key = DecodingKey::from_rsa_components(n, e).map_err(|e| e.to_string())?;
        self.dev_key = Some((kid, key));
        Ok(self)
    }

    async fn key(&self, kid: &str) -> Option<DecodingKey> {
        #[cfg(feature = "dev")]
        if let Some((dev_kid, key)) = &self.dev_key {
            if dev_kid == kid {
                return Some(key.clone());
            }
        }
        self.keys.get(kid).await
    }

    /// How long ago Entra ID's keys were fetched, for `/health`.
    pub async fn keys_age(&self) -> Option<std::time::Duration> {
        self.keys.age().await
    }

    /// Validate `token` and return its caller's claims.
    pub async fn verify(&self, token: &str) -> Result<Claims, Rejected> {
        let header = decode_header(token).map_err(|e| Rejected::Malformed(e.to_string()))?;
        if header.alg != Algorithm::RS256 {
            return Err(Rejected::Algorithm);
        }
        let kid = header
            .kid
            .filter(|k| !k.is_empty())
            .ok_or_else(|| Rejected::Malformed("no kid".into()))?;
        let key = self.key(&kid).await.ok_or(Rejected::UnknownKey)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = LEEWAY_SECS;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.config.api_client_id]);
        validation.required_spec_claims =
            HashSet::from(["exp", "nbf", "iss", "aud"].map(String::from));
        let claims = decode::<RawClaims>(token, &key, &validation)
            .map_err(|e| Rejected::Invalid(e.to_string()))?
            .claims;

        if claims.tid != self.config.tenant_id {
            return Err(Rejected::Tenant);
        }
        if !self.config.allowed_client_ids.contains(&claims.azp) {
            return Err(Rejected::Client);
        }
        // App-only tokens (no scp) come with machine clients, later.
        if !claims
            .scp
            .as_deref()
            .is_some_and(|scp| scp.split(' ').any(|s| s == SCOPE))
        {
            return Err(Rejected::Scope);
        }
        Ok(Claims {
            tid: claims.tid,
            oid: claims.oid,
            roles: claims.roles,
            email: claims.email.filter(|e| !e.is_empty()),
            name: claims.name.filter(|n| !n.is_empty()),
        })
    }
}

/// Minting Entra-shaped tokens, for tests and the dev token signer.
#[cfg(any(test, feature = "dev"))]
pub mod mint {
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::config::EntraConfig;
    use crate::tee::dev_rsa::RsaSigner;

    /// A token to mint: valid by default for `config`; each field can be
    /// changed to make a deliberately bad one.
    #[derive(Debug, Clone)]
    pub struct Spec {
        pub tid: String,
        pub oid: String,
        pub aud: String,
        pub azp: String,
        pub scp: Option<String>,
        pub roles: Vec<String>,
        pub email: Option<String>,
        pub name: Option<String>,
        /// Seconds from now; negative for an expired token.
        pub expires_in: i64,
        /// Seconds from now until the token becomes valid.
        pub not_before_in: i64,
    }

    impl Spec {
        /// A valid token for `config`'s first allowed client.
        pub fn valid(config: &EntraConfig) -> Self {
            Self {
                tid: config.tenant_id.clone(),
                oid: uuid::Uuid::new_v4().to_string(),
                aud: config.api_client_id.clone(),
                azp: config
                    .allowed_client_ids
                    .first()
                    .cloned()
                    .unwrap_or_default(),
                scp: Some(super::SCOPE.into()),
                roles: Vec::new(),
                email: None,
                name: None,
                expires_in: 3600,
                not_before_in: 0,
            }
        }

        pub fn claims(&self) -> Value {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or_default();
            let mut claims = json!({
                "ver": "2.0",
                "iss": format!("https://login.microsoftonline.com/{}/v2.0", self.tid),
                "tid": self.tid,
                "oid": self.oid,
                "sub": self.oid,
                "aud": self.aud,
                "azp": self.azp,
                "iat": now,
                "nbf": now + self.not_before_in,
                "exp": now + self.expires_in,
                "roles": self.roles,
            });
            for (name, value) in [
                ("scp", &self.scp),
                ("email", &self.email),
                ("name", &self.name),
            ] {
                if let Some(value) = value {
                    claims[name] = json!(value);
                }
            }
            claims
        }

        pub fn sign(&self, signer: &RsaSigner) -> Result<String, String> {
            signer.sign(json!({}), &self.claims())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::mint::Spec;
    use super::*;
    use crate::auth::jwks::tests::Fixed;
    use crate::tee::dev_rsa::RsaSigner;
    use std::collections::HashMap;
    use std::sync::OnceLock;

    pub(crate) fn config() -> EntraConfig {
        EntraConfig {
            tenant_id: "7e3e38e3-f24b-4592-a71f-02cfd4e4faec".into(),
            api_client_id: "aa827d93-d487-40bf-8956-b6872ed55290".into(),
            allowed_client_ids: vec!["e2d026c4-13c5-4057-9090-a896e7bbc70f".into()],
        }
    }

    /// The test stand-in for Entra ID's signing key. Generated once: RSA
    /// key generation is slow.
    pub(crate) fn entra_key() -> &'static RsaSigner {
        static KEY: OnceLock<RsaSigner> = OnceLock::new();
        KEY.get_or_init(|| RsaSigner::generate().expect("RSA key"))
    }

    fn other_key() -> &'static RsaSigner {
        static KEY: OnceLock<RsaSigner> = OnceLock::new();
        KEY.get_or_init(|| RsaSigner::generate().expect("RSA key"))
    }

    /// A verifier whose "Entra JWKS" serves [`entra_key`].
    pub(crate) fn verifier() -> Verifier {
        let key = entra_key();
        let decoding = DecodingKey::from_rsa_components(&key.n, &key.e).unwrap();
        Verifier::with_source(
            config(),
            Fixed::new(HashMap::from([(key.kid.clone(), decoding)])),
        )
    }

    async fn check(spec: &Spec) -> Result<Claims, Rejected> {
        verifier().verify(&spec.sign(entra_key()).unwrap()).await
    }

    #[tokio::test]
    async fn a_valid_token_names_its_caller() {
        let mut spec = Spec::valid(&config());
        spec.roles = vec!["Admin".into()];
        spec.email = Some("ada@example.com".into());
        spec.scp = Some("openid access_as_user".into());
        let claims = check(&spec).await.expect("valid");
        assert_eq!(claims.oid, spec.oid);
        assert_eq!(claims.roles, ["Admin"]);
        assert_eq!(claims.email.as_deref(), Some("ada@example.com"));

        // Within the skew, an expired or not-yet-valid token still passes.
        spec.expires_in = -30;
        assert!(check(&spec).await.is_ok());
        spec.expires_in = 3600;
        spec.not_before_in = 30;
        assert!(check(&spec).await.is_ok());
    }

    #[tokio::test]
    async fn every_wrong_claim_is_refused() {
        let valid = Spec::valid(&config());
        type Spoil = fn(&mut Spec);
        let bad: [(&str, Spoil); 8] = [
            ("expired", |s| s.expires_in = -120),
            ("not yet valid", |s| s.not_before_in = 120),
            ("wrong audience", |s| {
                s.aud = "api://aa827d93-d487-40bf-8956-b6872ed55290".into()
            }),
            ("wrong tenant", |s| {
                s.tid = "11111111-1111-1111-1111-111111111111".into()
            }),
            ("unknown client", |s| {
                s.azp = "04b07795-8ddb-461a-bbee-02f9e1bf7b46".into()
            }),
            ("no scope", |s| s.scp = None),
            ("another scope", |s| s.scp = Some("access_as_user_x".into())),
            ("empty scope", |s| s.scp = Some(String::new())),
        ];
        for (label, spoil) in bad {
            let mut spec = valid.clone();
            spoil(&mut spec);
            assert!(check(&spec).await.is_err(), "{label} was accepted");
        }
    }

    #[tokio::test]
    async fn only_rs256_from_a_trusted_key_is_accepted() {
        let spec = Spec::valid(&config());
        let foreign = spec.sign(other_key()).unwrap();
        assert_eq!(verifier().verify(&foreign).await, Err(Rejected::UnknownKey));

        // HS256 with the RSA public key as the secret: the classic confusion.
        let header = serde_json::json!({ "alg": "HS256", "kid": entra_key().kid });
        let hs256 = jsonwebtoken::encode(
            &serde_json::from_value(header).unwrap(),
            &spec.claims(),
            &jsonwebtoken::EncodingKey::from_secret(entra_key().n.as_bytes()),
        )
        .unwrap();
        assert_eq!(verifier().verify(&hs256).await, Err(Rejected::Algorithm));
        assert!(matches!(
            verifier().verify("not.a.token").await,
            Err(Rejected::Malformed(_))
        ));
    }

    /// Release builds have no way to trust another key, so a token signed
    /// with the dev token signing key is refused like any foreign key.
    #[cfg(not(feature = "dev"))]
    #[tokio::test]
    async fn release_builds_refuse_tokens_signed_with_a_dev_key() {
        let dev_key = other_key();
        let token = Spec::valid(&config()).sign(dev_key).unwrap();
        assert_eq!(verifier().verify(&token).await, Err(Rejected::UnknownKey));
    }

    #[cfg(feature = "dev")]
    #[tokio::test]
    async fn dev_builds_also_trust_the_dev_key() {
        let dev_key = other_key();
        let verifier = verifier()
            .trust_dev_key(dev_key.kid.clone(), &dev_key.n, &dev_key.e)
            .unwrap();
        let token = Spec::valid(&config()).sign(dev_key).unwrap();
        assert!(verifier.verify(&token).await.is_ok());
        // The claim checks still apply to it.
        let mut bad = Spec::valid(&config());
        bad.scp = None;
        let token = bad.sign(dev_key).unwrap();
        assert_eq!(verifier.verify(&token).await, Err(Rejected::Scope));
    }
}
