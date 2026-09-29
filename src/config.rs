// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Configuration for the relational-tee worker.
//!
//! Non-sensitive values are hardcoded here. Only values that **must** differ
//! between environments use `env::var` with a default fallback.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use crate::store::azure::{AzureConfig, CredentialConfig};
use crate::tee::skr::SkrConfig;

// ============================================================================
// Auth (AVS JWT)
// ============================================================================

/// Default AVS JWKS URL for token verification.
/// Override with `AVS_JWKS_URL` environment variable.
pub const DEFAULT_AVS_JWKS_URL: &str = "http://127.0.0.1:9100/.well-known/jwks.json";

/// Get AVS JWKS URL from environment or use default.
pub fn avs_jwks_url() -> String {
    env::var("AVS_JWKS_URL").unwrap_or_else(|_| DEFAULT_AVS_JWKS_URL.to_string())
}

/// Expected audience claim in AVS-issued tokens.
pub const AVS_AUDIENCE: &str = "relational-sdk";

/// Expected issuer claim in AVS-issued tokens.
pub const AVS_ISSUER: &str = "attestation-verification-service";

/// JWKS cache TTL in seconds (5 minutes).
pub const JWKS_CACHE_TTL_SECS: u64 = 300;

// ============================================================================
// Server
// ============================================================================

/// Default listening port for HTTPS in the worker.
pub const DEFAULT_PORT: u16 = 8443;

/// Default bind address. Dev builds listen on loopback because they may serve
/// plain HTTP; release builds run in a container behind the load balancer.
#[cfg(feature = "dev")]
pub const DEFAULT_BIND_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
#[cfg(not(feature = "dev"))]
pub const DEFAULT_BIND_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Maximum request body size (50 MiB).
pub const MAX_BODY_SIZE: usize = 50 * 1024 * 1024;

/// How the server speaks to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// HTTPS with a PEM certificate chain and private key read from disk.
    Tls {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// Plain HTTP. Not compiled into release builds.
    #[cfg(feature = "dev")]
    PlainHttp,
}

/// Where the worker's keys come from (`KEY_PROVIDER`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyProviderConfig {
    /// `skr`: the SKR sidecar in the same container group.
    Skr(SkrConfig),
    /// `local`: dev key files in `DEV_KEYS_DIR`. Not compiled into release builds.
    #[cfg(feature = "dev")]
    Local { dir: PathBuf },
}

/// Default SKR sidecar address: localhost, port 9000.
pub const DEFAULT_SKR_ENDPOINT: &str = "http://localhost:9000";

/// Default attestation authority (the shared West Europe MAA endpoint).
pub const DEFAULT_MAA_ENDPOINT: &str = "sharedweu.weu.attest.azure.net";

/// Key Vault placeholder for dev builds, where the fake sidecar ignores it.
#[cfg(feature = "dev")]
const DEV_KEY_VAULT_URL: &str = "https://dev.vault.azure.net";

/// Where durable state lives (`STORAGE_BACKEND`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageConfig {
    /// `azure`: Azure Blob Storage (in dev builds, also `azurite`).
    Azure(AzureConfig),
    /// `files`: local files under `DATA_DIR`, one directory per container.
    /// Dev builds only.
    #[cfg(feature = "dev")]
    Files { dir: PathBuf },
}

/// Azurite's default Blob endpoint, for `STORAGE_BACKEND=azurite`.
#[cfg(feature = "dev")]
pub const AZURITE_BLOB_URL: &str = "http://127.0.0.1:10000/devstoreaccount1";

/// Where dev builds keep local files by default.
#[cfg(feature = "dev")]
pub const DEFAULT_DATA_DIR: &str = "./data";

/// Process configuration read once from the environment at startup.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub transport: Transport,
    pub keys: KeyProviderConfig,
    pub storage: StorageConfig,
}

impl ServerConfig {
    /// Read `BIND_ADDR`, `PORT`, `TLS_CERT_PATH`, `TLS_KEY_PATH`,
    /// and the key provider and storage settings (see
    /// [`key_provider_from_lookup`] and [`storage_from_lookup`]).
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| env::var(key).ok().filter(|v| !v.is_empty()))
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let ip = match lookup("BIND_ADDR") {
            Some(v) => v
                .parse::<IpAddr>()
                .map_err(|e| format!("BIND_ADDR {v:?} is not an IP address: {e}"))?,
            None => DEFAULT_BIND_ADDR,
        };
        let port = match lookup("PORT") {
            Some(v) => v
                .parse::<u16>()
                .map_err(|e| format!("PORT {v:?} is not a port number: {e}"))?,
            None => DEFAULT_PORT,
        };

        let transport = match (lookup("TLS_CERT_PATH"), lookup("TLS_KEY_PATH")) {
            (Some(cert), Some(key)) => Transport::Tls {
                cert_path: cert.into(),
                key_path: key.into(),
            },
            (None, None) => {
                #[cfg(feature = "dev")]
                {
                    Transport::PlainHttp
                }
                #[cfg(not(feature = "dev"))]
                {
                    return Err("TLS_CERT_PATH and TLS_KEY_PATH are required: \
                                release builds never serve plain HTTP"
                        .into());
                }
            }
            _ => return Err("set both TLS_CERT_PATH and TLS_KEY_PATH, or neither".into()),
        };

        Ok(Self {
            addr: SocketAddr::new(ip, port),
            transport,
            keys: key_provider_from_lookup(&lookup)?,
            storage: storage_from_lookup(&lookup)?,
        })
    }
}

/// Read `STORAGE_BACKEND` and its settings: `STORAGE_BLOB_URL` and
/// `MANAGED_IDENTITY_CLIENT_ID` for `azure`. Dev builds add `azurite`
/// (Azurite's dev account, its default endpoint on localhost) and `files`,
/// their default, under `DATA_DIR`; release builds have only `azure`, and
/// require an HTTPS endpoint.
fn storage_from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Result<StorageConfig, String> {
    #[cfg(feature = "dev")]
    let default = "files";
    #[cfg(not(feature = "dev"))]
    let default = "azure";

    match lookup("STORAGE_BACKEND").as_deref().unwrap_or(default) {
        "azure" => {
            let blob_url = lookup("STORAGE_BLOB_URL")
                .ok_or("STORAGE_BLOB_URL is required when STORAGE_BACKEND=azure")?;
            #[cfg(not(feature = "dev"))]
            if !blob_url.starts_with("https://") {
                return Err("STORAGE_BLOB_URL must be an https:// URL".into());
            }
            Ok(StorageConfig::Azure(AzureConfig {
                blob_url,
                credential: CredentialConfig::ManagedIdentity {
                    client_id: lookup("MANAGED_IDENTITY_CLIENT_ID"),
                },
            }))
        }
        #[cfg(feature = "dev")]
        "azurite" => Ok(StorageConfig::Azure(AzureConfig {
            blob_url: lookup("STORAGE_BLOB_URL").unwrap_or_else(|| AZURITE_BLOB_URL.into()),
            credential: CredentialConfig::AzuriteDevAccount,
        })),
        #[cfg(feature = "dev")]
        "files" => Ok(StorageConfig::Files {
            dir: lookup("DATA_DIR")
                .unwrap_or_else(|| DEFAULT_DATA_DIR.into())
                .into(),
        }),
        #[cfg(not(feature = "dev"))]
        other @ ("azurite" | "files") => Err(format!(
            "STORAGE_BACKEND={other} isn't available: release builds contain only azure"
        )),
        other => Err(format!(
            "STORAGE_BACKEND {other:?} is unknown: use azure, azurite or files"
        )),
    }
}

/// Read `KEY_PROVIDER` (`skr`, or `local` in dev builds) and its settings:
/// `SKR_ENDPOINT`, `MAA_ENDPOINT`, `KEY_VAULT_URL` and `KEY_NAMES` for `skr`,
/// `DEV_KEYS_DIR` for `local`. Dev builds default to `local`, release builds
/// to `skr`.
fn key_provider_from_lookup(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<KeyProviderConfig, String> {
    #[cfg(feature = "dev")]
    let default = "local";
    #[cfg(not(feature = "dev"))]
    let default = "skr";

    match lookup("KEY_PROVIDER").as_deref().unwrap_or(default) {
        "skr" => skr_config_from_lookup(lookup).map(KeyProviderConfig::Skr),
        #[cfg(feature = "dev")]
        "local" => Ok(KeyProviderConfig::Local {
            dir: lookup("DEV_KEYS_DIR")
                .unwrap_or_else(|| crate::tee::dev_keys::DEFAULT_DIR.into())
                .into(),
        }),
        #[cfg(not(feature = "dev"))]
        "local" => Err(
            "KEY_PROVIDER=local isn't available: release builds contain only \
                        the skr provider"
                .into(),
        ),
        other => Err(format!(
            "KEY_PROVIDER {other:?} is unknown: use skr or local"
        )),
    }
}

fn skr_config_from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Result<SkrConfig, String> {
    let endpoint = lookup("SKR_ENDPOINT").unwrap_or_else(|| DEFAULT_SKR_ENDPOINT.into());
    if !endpoint.starts_with("http://") {
        return Err(format!("SKR_ENDPOINT {endpoint:?} must be an http:// URL"));
    }
    // The sidecar speaks plain HTTP and returns private keys, so release
    // builds only talk to it over loopback.
    #[cfg(not(feature = "dev"))]
    if !is_loopback_http_url(&endpoint) {
        return Err(format!(
            "SKR_ENDPOINT {endpoint:?} must be on localhost: the sidecar returns keys in the clear"
        ));
    }

    #[cfg(feature = "dev")]
    let vault = lookup("KEY_VAULT_URL").unwrap_or_else(|| DEV_KEY_VAULT_URL.into());
    #[cfg(not(feature = "dev"))]
    let vault = lookup("KEY_VAULT_URL").ok_or("KEY_VAULT_URL is required when KEY_PROVIDER=skr")?;

    let key_names = match lookup("KEY_NAMES") {
        Some(list) => {
            let names: Vec<String> = list.split(',').map(|s| s.trim().to_string()).collect();
            <[String; 4]>::try_from(names).map_err(|_| {
                "KEY_NAMES must list four names: transport, storage root, TLS and commitment"
                    .to_string()
            })?
        }
        None => crate::tee::KeyName::ALL.map(|k| k.as_str().to_string()),
    };
    if key_names.iter().any(|n| n.is_empty()) {
        return Err("KEY_NAMES has an empty name".into());
    }

    Ok(SkrConfig {
        endpoint,
        maa_endpoint: host_only(
            "MAA_ENDPOINT",
            &lookup("MAA_ENDPOINT").unwrap_or_else(|| DEFAULT_MAA_ENDPOINT.into()),
        )?,
        akv_endpoint: host_only("KEY_VAULT_URL", &vault)?,
        key_names,
    })
}

/// The sidecar takes bare hosts: strip `https://` and any trailing slash.
fn host_only(name: &str, value: &str) -> Result<String, String> {
    let host = value
        .strip_prefix("https://")
        .unwrap_or(value)
        .trim_end_matches('/');
    if host.is_empty() || host.contains(['/', '?', '#', ' ']) || host.starts_with("http://") {
        return Err(format!(
            "{name} {value:?} must be a host name or an https:// URL"
        ));
    }
    Ok(host.to_string())
}

// ============================================================================
// Solana
// ============================================================================

// TODO: Solana's public devnet RPC is rate-limited and has no SLA. Switch to a
// paid provider before production, keeping its API key out of the CCE policy,
// which is public.
/// Default Solana RPC endpoint. Override with `SOLANA_RPC_URL`.
pub const DEFAULT_SOLANA_RPC_URL: &str = "https://api.devnet.solana.com";

/// Solana's public RPC endpoints. They are rate-limited and have no SLA, so the
/// server warns at startup when `SOLANA_RPC_URL` is one of them.
pub const PUBLIC_SOLANA_RPC_URLS: &[&str] = &[
    "https://api.devnet.solana.com",
    "https://api.testnet.solana.com",
    "https://api.mainnet-beta.solana.com",
];

/// Default Solana network name. Override with `SOLANA_NETWORK` (`devnet` or
/// `mainnet`).
pub const DEFAULT_SOLANA_NETWORK: &str = "devnet";

/// Solana RPC endpoint from `SOLANA_RPC_URL`, or the devnet default.
pub fn solana_rpc_url() -> String {
    env::var("SOLANA_RPC_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_SOLANA_RPC_URL.to_string())
}

/// Solana network name from `SOLANA_NETWORK`, or the devnet default.
pub fn solana_network() -> String {
    env::var("SOLANA_NETWORK")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_SOLANA_NETWORK.to_string())
}

// ============================================================================
// Transaction history
// ============================================================================

/// History pages cached per worker.
pub const TX_CACHE_CAPACITY: usize = 128;

/// How long a cached history page is served (seconds).
pub const TX_CACHE_TTL_SECS: u64 = 30;

/// Parsed transactions cached per worker, by signature.
pub const TX_DETAIL_CACHE_CAPACITY: usize = 1024;

// ============================================================================
// DRT Smart Contract
// ============================================================================

/// DRT program ID on Solana (devnet). Hardcoded — change and rebuild to update.
/// Canonical: `digital_rights_tokens` Anchor program. IDL lives at
/// `idl/digital_rights_tokens.json`.
pub const DRT_PROGRAM_ID_STR: &str = "8N5hVnK81rWhwfhxt9LfjrbeVT83Jjgy4dKyy4q6HKjk";

/// Get the DRT program `Pubkey` (parsed from the hardcoded constant).
pub fn drt_program_id() -> solana_pubkey::Pubkey {
    use std::str::FromStr;
    solana_pubkey::Pubkey::from_str(DRT_PROGRAM_ID_STR)
        .expect("DRT_PROGRAM_ID_STR is a valid Solana pubkey")
}

// ============================================================================
// JWKS Security
// ============================================================================

/// Whether plain HTTP is allowed for the JWKS URL.
///
/// Hardcoded to `true` for a co-located AVS on localhost. Entra ID, which
/// replaces the AVS, always serves its keys over HTTPS.
pub const ALLOW_HTTP_JWKS: bool = true;

/// Returns `true` when `url` is an `http://` URL whose host is the loopback
/// interface (`localhost`, `127.0.0.1`, or `::1`).
///
/// Used to gate the "plain HTTP JWKS" warning and the production hard-block,
/// and to keep release builds' SKR sidecar traffic on loopback.
/// Substring matching (e.g. `url.contains("localhost")`) is unsafe — a host
/// like `attacker.example.com/localhost/...` would have falsely passed.
/// This parser extracts the authority and matches the host exactly.
pub fn is_loopback_http_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    // Authority ends at the first '/', '?', or '#'.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // Strip optional userinfo (`user:pass@host`).
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    // IPv6 literals are wrapped in `[...]`.
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else {
        host_port
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port)
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_url_accepts_loopback_hosts() {
        assert!(is_loopback_http_url("http://localhost:9100/jwks"));
        assert!(is_loopback_http_url(
            "http://127.0.0.1:9100/.well-known/jwks.json"
        ));
        assert!(is_loopback_http_url("http://[::1]:9100/jwks"));
        assert!(is_loopback_http_url("http://localhost"));
    }

    #[test]
    fn loopback_http_url_rejects_substring_bypass() {
        // The old `url.contains("localhost")` check would have accepted these.
        assert!(!is_loopback_http_url(
            "http://attacker.example.com/localhost"
        ));
        assert!(!is_loopback_http_url("http://localhost.evil.com/jwks"));
        assert!(!is_loopback_http_url("http://user@evil.com/127.0.0.1"));
        assert!(!is_loopback_http_url(
            "http://example.com:8080/path?host=127.0.0.1"
        ));
    }

    fn config_from(vars: &[(&str, &str)]) -> Result<ServerConfig, String> {
        ServerConfig::from_lookup(|key| {
            vars.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        })
    }

    /// Settings a release build requires.
    const RELEASE_BASE: [(&str, &str); 4] = [
        ("TLS_CERT_PATH", "c"),
        ("TLS_KEY_PATH", "k"),
        ("KEY_VAULT_URL", "kv.vault.azure.net"),
        ("STORAGE_BLOB_URL", "https://acct.blob.core.windows.net"),
    ];

    /// `extra` followed by [`RELEASE_BASE`]; the first match wins, so `extra`
    /// overrides the base.
    fn complete(extra: &[(&'static str, &'static str)]) -> Result<ServerConfig, String> {
        let mut vars = extra.to_vec();
        vars.extend(RELEASE_BASE);
        config_from(&vars)
    }

    /// [`RELEASE_BASE`] without the named settings.
    #[cfg(not(feature = "dev"))]
    fn base_without(names: &[&str]) -> Vec<(&'static str, &'static str)> {
        RELEASE_BASE
            .into_iter()
            .filter(|(k, _)| !names.contains(k))
            .collect()
    }

    #[test]
    fn server_config_reads_overrides() {
        let config = complete(&[
            ("BIND_ADDR", "::1"),
            ("PORT", "9443"),
            ("TLS_CERT_PATH", "cert.pem"),
            ("TLS_KEY_PATH", "key.pem"),
        ])
        .expect("valid config");
        assert_eq!(config.addr, "[::1]:9443".parse().unwrap());
        assert_eq!(
            config.transport,
            Transport::Tls {
                cert_path: "cert.pem".into(),
                key_path: "key.pem".into(),
            }
        );
    }

    #[test]
    fn server_config_rejects_half_a_tls_pair_and_bad_values() {
        assert!(config_from(&[("TLS_CERT_PATH", "cert.pem")]).is_err());
        assert!(config_from(&[("TLS_KEY_PATH", "key.pem")]).is_err());
        assert!(complete(&[("PORT", "http")]).is_err());
        assert!(complete(&[("BIND_ADDR", "localhost")]).is_err());
    }

    #[cfg(feature = "dev")]
    #[test]
    fn dev_build_defaults_to_plain_http_on_loopback() {
        let config = config_from(&[]).expect("dev defaults");
        assert_eq!(config.addr, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(config.transport, Transport::PlainHttp);
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn release_build_requires_tls() {
        assert!(config_from(&base_without(&["TLS_CERT_PATH", "TLS_KEY_PATH"])).is_err());
        let config = complete(&[]).expect("release config with TLS");
        assert_eq!(config.addr, "0.0.0.0:8443".parse().unwrap());
    }

    #[test]
    #[allow(clippy::infallible_destructuring_match)] // release builds have only the skr provider
    fn skr_settings_are_read_as_bare_hosts() {
        let config = complete(&[
            ("KEY_PROVIDER", "skr"),
            ("SKR_ENDPOINT", "http://127.0.0.1:9000"),
            ("MAA_ENDPOINT", "https://sharedweu.weu.attest.azure.net/"),
            (
                "KEY_VAULT_URL",
                "https://kv-iob-micres-pilot.vault.azure.net",
            ),
            ("KEY_NAMES", "t,s, tls ,c"),
        ])
        .expect("valid config");
        let skr = match config.keys {
            KeyProviderConfig::Skr(skr) => skr,
            #[cfg(feature = "dev")]
            other => panic!("expected the skr provider, got {other:?}"),
        };
        assert_eq!(skr.endpoint, "http://127.0.0.1:9000");
        assert_eq!(skr.maa_endpoint, "sharedweu.weu.attest.azure.net");
        assert_eq!(skr.akv_endpoint, "kv-iob-micres-pilot.vault.azure.net");
        assert_eq!(skr.key_names, ["t", "s", "tls", "c"].map(String::from));
    }

    #[test]
    fn skr_settings_reject_bad_values() {
        let with =
            |extra: (&'static str, &'static str)| complete(&[extra, ("KEY_PROVIDER", "skr")]);
        assert!(with(("PORT", "9443")).is_ok());
        assert!(with(("KEY_NAMES", "a,b,c")).is_err());
        assert!(with(("SKR_ENDPOINT", "https://localhost:9000")).is_err());
        assert!(with(("MAA_ENDPOINT", "http://maa.example")).is_err());
        assert!(with(("KEY_PROVIDER", "vault")).is_err());
    }

    #[test]
    #[allow(clippy::infallible_destructuring_match)] // release builds have only the azure backend
    fn azure_storage_uses_the_managed_identity() {
        let config = complete(&[
            ("STORAGE_BACKEND", "azure"),
            (
                "MANAGED_IDENTITY_CLIENT_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
        ])
        .expect("valid config");
        let azure = match config.storage {
            StorageConfig::Azure(azure) => azure,
            #[cfg(feature = "dev")]
            other => panic!("expected azure storage, got {other:?}"),
        };
        assert_eq!(azure.blob_url, "https://acct.blob.core.windows.net");
        assert_eq!(
            azure.credential,
            CredentialConfig::ManagedIdentity {
                client_id: Some("00000000-0000-0000-0000-000000000001".into())
            }
        );
        assert!(complete(&[("STORAGE_BACKEND", "s3")]).is_err());
    }

    #[cfg(feature = "dev")]
    #[test]
    fn dev_build_defaults_to_local_dev_keys_and_local_files() {
        let config = config_from(&[]).expect("dev defaults");
        assert_eq!(
            config.keys,
            KeyProviderConfig::Local {
                dir: PathBuf::from("dev/keys")
            }
        );
        assert_eq!(
            config.storage,
            StorageConfig::Files {
                dir: PathBuf::from("./data")
            }
        );
        let elsewhere = config_from(&[("DATA_DIR", "/tmp/rt")]).unwrap();
        assert_eq!(
            elsewhere.storage,
            StorageConfig::Files {
                dir: PathBuf::from("/tmp/rt")
            }
        );
        let azurite = config_from(&[("STORAGE_BACKEND", "azurite")]).unwrap();
        assert_eq!(
            azurite.storage,
            StorageConfig::Azure(AzureConfig {
                blob_url: AZURITE_BLOB_URL.into(),
                credential: CredentialConfig::AzuriteDevAccount,
            })
        );
        assert!(config_from(&[("STORAGE_BACKEND", "memory")]).is_err());
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn release_build_rejects_dev_providers_and_plain_http_storage() {
        let err = complete(&[("KEY_PROVIDER", "local")]).expect_err("local isn't compiled in");
        assert!(err.contains("KEY_PROVIDER=local"), "{err}");
        assert!(complete(&[("STORAGE_BACKEND", "files")]).is_err());
        assert!(complete(&[("STORAGE_BACKEND", "azurite")]).is_err());
        assert!(complete(&[("STORAGE_BLOB_URL", "http://acct.blob.core.windows.net")]).is_err());
        assert!(config_from(&base_without(&["STORAGE_BLOB_URL"])).is_err());
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn release_build_requires_a_vault_and_a_loopback_sidecar() {
        assert!(config_from(&base_without(&["KEY_VAULT_URL"])).is_err());
        let config = complete(&[]).expect("skr default");
        assert!(matches!(config.keys, KeyProviderConfig::Skr(_)));
        assert!(complete(&[("SKR_ENDPOINT", "http://10.0.0.5:9000")]).is_err());
    }

    #[test]
    fn loopback_http_url_rejects_https_and_other_schemes() {
        assert!(!is_loopback_http_url("https://localhost/jwks"));
        assert!(!is_loopback_http_url("file:///tmp/jwks"));
    }
}
