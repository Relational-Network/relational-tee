// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Configuration for the relational-tee worker.
//!
//! Non-sensitive values are hardcoded here. Only values that **must** differ
//! between environments use `env::var` with a default fallback.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(feature = "dev")]
use std::path::PathBuf;

use crate::store::azure::{AzureConfig, CredentialConfig};
use crate::tee::skr::SkrConfig;

// ============================================================================
// Auth (Entra ID)
// ============================================================================

/// Which Entra ID tokens the worker accepts. Pinned per environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntraConfig {
    /// The tenant ID: tokens' `tid`, and part of their `iss`.
    pub tenant_id: String,
    /// The API app registration's client ID: tokens' `aud`.
    pub api_client_id: String,
    /// Client IDs allowed as `azp`: the dashboard, and in dev the Azure CLI.
    pub allowed_client_ids: Vec<String>,
}

impl EntraConfig {
    /// The exact `iss` of the tenant's v2 access tokens.
    pub fn issuer(&self) -> String {
        format!("https://login.microsoftonline.com/{}/v2.0", self.tenant_id)
    }

    /// The tenant's signing keys.
    pub fn jwks_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
            self.tenant_id
        )
    }
}

/// The Azure CLI's well-known client ID. Only the dev API pre-authorizes
/// it, so scripts can get tokens; release builds refuse to allow it.
pub const AZURE_CLI_CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

/// The dev app registrations in Relational's tenant, dev builds' defaults.
#[cfg(feature = "dev")]
pub mod dev_entra {
    pub const TENANT_ID: &str = "7e3e38e3-f24b-4592-a71f-02cfd4e4faec";
    pub const API_CLIENT_ID: &str = "aa827d93-d487-40bf-8956-b6872ed55290";
    pub const DASHBOARD_CLIENT_ID: &str = "e2d026c4-13c5-4057-9090-a896e7bbc70f";
}

/// Dev builds' dashboard origin: the Vite dev server.
#[cfg(feature = "dev")]
pub const DEV_DASHBOARD_ORIGIN: &str = "http://localhost:5173";

/// Where the dev token signing key lives, beside the other dev keys.
#[cfg(feature = "dev")]
pub const DEV_TOKEN_KEY_FILE: &str = "entra-signing-key.pem";

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

/// The largest body the upload routes accept (50 MiB); other routes take
/// 1 MiB ([`crate::edge::REQUESTS`]).
pub const MAX_BODY_SIZE: usize = 50 * 1024 * 1024;

/// How the server speaks to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// HTTPS with `tls-key`, for `hostname`, with the certificate chain from
    /// the `tls` container.
    Https { hostname: String },
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

/// Dev builds' environment name.
#[cfg(feature = "dev")]
pub const DEV_ENVIRONMENT: &str = "dev";

/// Process configuration read once from the environment at startup.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The environment's name, such as `pilot`: it names the environment's
    /// reference values in storage.
    pub environment: String,
    pub addr: SocketAddr,
    pub transport: Transport,
    pub keys: KeyProviderConfig,
    pub storage: StorageConfig,
    pub entra: EntraConfig,
    /// The one origin CORS allows: the environment's dashboard.
    pub dashboard_origin: String,
    pub rate_limits: RateLimits,
    pub reconciler: crate::reconciler::Timing,
    /// The dev token signing key, whose public half dev builds also trust.
    #[cfg(feature = "dev")]
    pub dev_token_key: PathBuf,
    /// `FAULT_INJECTION=on`: honour `X-Fault-Exit` (see [`crate::fault`]).
    #[cfg(feature = "dev")]
    pub fault_injection: bool,
}

impl ServerConfig {
    /// Read `ENVIRONMENT`, `BIND_ADDR`, `PORT`, `TRANSPORT`, `API_HOSTNAME`,
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

        let transport = transport_from_lookup(&lookup)?;

        #[cfg(not(feature = "dev"))]
        if lookup("DEV_TOKEN_KEY").is_some() {
            return Err("DEV_TOKEN_KEY isn't available: release builds trust only \
                        Entra ID's signing keys"
                .into());
        }
        #[cfg(not(feature = "dev"))]
        if lookup("FAULT_INJECTION").is_some() {
            return Err(
                "FAULT_INJECTION isn't available: release builds contain no \
                        fault injection"
                    .into(),
            );
        }

        Ok(Self {
            environment: environment_from_lookup(&lookup)?,
            addr: SocketAddr::new(ip, port),
            transport,
            keys: key_provider_from_lookup(&lookup)?,
            storage: storage_from_lookup(&lookup)?,
            entra: entra_from_lookup(&lookup)?,
            dashboard_origin: dashboard_origin_from_lookup(&lookup)?,
            rate_limits: RateLimits::from_lookup(&lookup)?,
            reconciler: reconciler_from_lookup(&lookup)?,
            #[cfg(feature = "dev")]
            dev_token_key: dev_token_key_from_lookup(&lookup),
            #[cfg(feature = "dev")]
            fault_injection: match lookup("FAULT_INJECTION").as_deref() {
                None | Some("off") => false,
                Some("on") => true,
                Some(other) => return Err(format!("FAULT_INJECTION {other:?} must be on or off")),
            },
        })
    }
}

/// Read `RECONCILER_INTERVAL_SECS` and `RECONCILER_MIN_AGE_SECS`, which
/// only dev builds take; release builds reconcile every 5 minutes, sagas
/// older than 10.
fn reconciler_from_lookup(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<crate::reconciler::Timing, String> {
    let names = ["RECONCILER_INTERVAL_SECS", "RECONCILER_MIN_AGE_SECS"];
    #[cfg(not(feature = "dev"))]
    if let Some(name) = names.iter().find(|name| lookup(name).is_some()) {
        return Err(format!(
            "{name} isn't available: release builds reconcile every 5 minutes"
        ));
    }
    #[allow(unused_mut)] // release builds keep the defaults
    let mut timing = crate::reconciler::Timing::default();
    #[cfg(feature = "dev")]
    {
        let secs = |name: &str| match lookup(name) {
            None => Ok(None),
            Some(v) => v
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .map(|n| Some(std::time::Duration::from_secs(n)))
                .ok_or_else(|| format!("{name} {v:?} isn't a positive whole number")),
        };
        if let Some(interval) = secs(names[0])? {
            timing.interval = interval;
        }
        if let Some(min_age) = secs(names[1])? {
            timing.min_age = min_age;
        }
    }
    Ok(timing)
}

/// Read `ENVIRONMENT`: lowercase letters, digits and hyphens. Release builds
/// require it; dev builds default to `dev`.
pub(crate) fn environment_from_lookup(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    #[cfg(feature = "dev")]
    let name = lookup("ENVIRONMENT").unwrap_or_else(|| DEV_ENVIRONMENT.into());
    #[cfg(not(feature = "dev"))]
    let name = lookup("ENVIRONMENT").ok_or("ENVIRONMENT is required")?;
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !valid {
        return Err(format!(
            "ENVIRONMENT {name:?} must be lowercase letters, digits and hyphens"
        ));
    }
    Ok(name)
}

/// How log lines are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// One JSON object per line, for Azure Monitor.
    Json,
    /// Human-readable lines, for a terminal.
    Text,
}

/// Read `LOG_FORMAT`: `json` or `text`. Release builds default to `json`,
/// dev builds to `text`.
pub fn log_format_from_lookup(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<LogFormat, String> {
    match lookup("LOG_FORMAT").as_deref() {
        None if cfg!(feature = "dev") => Ok(LogFormat::Text),
        None | Some("json") => Ok(LogFormat::Json),
        Some("text") => Ok(LogFormat::Text),
        Some(other) => Err(format!("LOG_FORMAT {other:?} must be json or text")),
    }
}

/// Read `TRANSPORT` and `API_HOSTNAME`. Release builds serve only HTTPS and
/// require the hostname; dev builds default to plain HTTP, and to
/// `localhost` for `TRANSPORT=https`.
fn transport_from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Result<Transport, String> {
    if lookup("TLS_CERT_PATH").is_some() || lookup("TLS_KEY_PATH").is_some() {
        return Err(
            "TLS_CERT_PATH and TLS_KEY_PATH are no longer read: the worker serves \
                    tls-key with the chain for it in the tls container"
                .into(),
        );
    }
    #[cfg(feature = "dev")]
    let default = "http";
    #[cfg(not(feature = "dev"))]
    let default = "https";
    match lookup("TRANSPORT").as_deref().unwrap_or(default) {
        "https" => {
            #[cfg(feature = "dev")]
            let hostname = lookup("API_HOSTNAME").unwrap_or_else(|| "localhost".into());
            #[cfg(not(feature = "dev"))]
            let hostname = lookup("API_HOSTNAME").ok_or("API_HOSTNAME is required")?;
            let valid = !hostname.is_empty()
                && hostname.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.')
                });
            if !valid {
                return Err(format!(
                    "API_HOSTNAME {hostname:?} must be a lowercase DNS name"
                ));
            }
            Ok(Transport::Https { hostname })
        }
        #[cfg(feature = "dev")]
        "http" => Ok(Transport::PlainHttp),
        #[cfg(not(feature = "dev"))]
        "http" => Err("TRANSPORT=http isn't available: release builds serve only HTTPS".into()),
        other => Err(format!("TRANSPORT {other:?} must be https or http")),
    }
}

/// Per-worker request rate limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimits {
    /// `RATE_LIMIT_IP_PER_SECOND`: sustained requests per client IP.
    pub ip_per_second: u32,
    /// `RATE_LIMIT_IP_BURST`: requests a client IP may make at once.
    pub ip_burst: u32,
    /// `RATE_LIMIT_USER_MUTATIONS_PER_SECOND`: POST, PUT, PATCH and DELETE
    /// requests per user.
    pub user_mutations_per_second: u32,
}

impl RateLimits {
    fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let read = |name: &str, default: u32| match lookup(name) {
            None => Ok(default),
            Some(v) => v
                .parse::<u32>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{name} {v:?} isn't a positive whole number")),
        };
        Ok(Self {
            ip_per_second: read("RATE_LIMIT_IP_PER_SECOND", 20)?,
            ip_burst: read("RATE_LIMIT_IP_BURST", 40)?,
            user_mutations_per_second: read("RATE_LIMIT_USER_MUTATIONS_PER_SECOND", 10)?,
        })
    }
}

/// `DEV_TOKEN_KEY`, or `entra-signing-key.pem` in `DEV_KEYS_DIR`.
#[cfg(feature = "dev")]
pub fn dev_token_key_from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> PathBuf {
    lookup("DEV_TOKEN_KEY").map_or_else(
        || {
            PathBuf::from(
                lookup("DEV_KEYS_DIR").unwrap_or_else(|| crate::tee::dev_keys::DEFAULT_DIR.into()),
            )
            .join(DEV_TOKEN_KEY_FILE)
        },
        PathBuf::from,
    )
}

/// A UUID in canonical lowercase form, or an error naming `setting`.
fn uuid_setting(setting: &str, value: &str) -> Result<String, String> {
    uuid::Uuid::parse_str(value.trim())
        .map(|u| u.hyphenated().to_string())
        .map_err(|_| format!("{setting} {value:?} isn't a UUID"))
}

/// The dev app registrations' value for an Entra setting: dev builds'
/// default. Release builds have none.
fn entra_dev_default(name: &str) -> Option<String> {
    #[cfg(feature = "dev")]
    return match name {
        "ENTRA_TENANT_ID" => Some(dev_entra::TENANT_ID.into()),
        "ENTRA_API_CLIENT_ID" => Some(dev_entra::API_CLIENT_ID.into()),
        "ENTRA_ALLOWED_CLIENT_IDS" => Some(format!(
            "{},{AZURE_CLI_CLIENT_ID}",
            dev_entra::DASHBOARD_CLIENT_ID
        )),
        _ => None,
    };
    #[cfg(not(feature = "dev"))]
    {
        let _ = name;
        None
    }
}

/// Read `ENTRA_TENANT_ID`, `ENTRA_API_CLIENT_ID` and
/// `ENTRA_ALLOWED_CLIENT_IDS` (comma-separated). Dev builds default to the
/// dev app registrations; release builds require all three and refuse the
/// Azure CLI as a client.
pub(crate) fn entra_from_lookup(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<EntraConfig, String> {
    let read = |name: &str| {
        lookup(name)
            .or_else(|| entra_dev_default(name))
            .ok_or_else(|| format!("{name} is required"))
    };
    let tenant_id = uuid_setting("ENTRA_TENANT_ID", &read("ENTRA_TENANT_ID")?)?;
    let api_client_id = uuid_setting("ENTRA_API_CLIENT_ID", &read("ENTRA_API_CLIENT_ID")?)?;
    let allowed_client_ids = read("ENTRA_ALLOWED_CLIENT_IDS")?
        .split(',')
        .map(|id| uuid_setting("ENTRA_ALLOWED_CLIENT_IDS", id))
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(not(feature = "dev"))]
    if allowed_client_ids
        .iter()
        .any(|id| id == AZURE_CLI_CLIENT_ID)
    {
        return Err(
            "ENTRA_ALLOWED_CLIENT_IDS names the Azure CLI, which only dev builds allow".into(),
        );
    }
    Ok(EntraConfig {
        tenant_id,
        api_client_id,
        allowed_client_ids,
    })
}

/// Read `DASHBOARD_ORIGIN`, the one origin CORS allows: an `https://`
/// origin, required in release builds; dev builds default to the Vite dev
/// server and also allow `http://`.
fn dashboard_origin_from_lookup(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    #[cfg(feature = "dev")]
    let origin = lookup("DASHBOARD_ORIGIN").unwrap_or_else(|| DEV_DASHBOARD_ORIGIN.into());
    #[cfg(not(feature = "dev"))]
    let origin = lookup("DASHBOARD_ORIGIN").ok_or("DASHBOARD_ORIGIN is required")?;

    let rest = origin
        .strip_prefix("https://")
        .or_else(|| {
            if cfg!(feature = "dev") {
                origin.strip_prefix("http://")
            } else {
                None
            }
        })
        .ok_or_else(|| format!("DASHBOARD_ORIGIN {origin:?} must be an https:// origin"))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', ' ']) {
        return Err(format!(
            "DASHBOARD_ORIGIN {origin:?} must be a scheme and host, with no path"
        ));
    }
    Ok(origin)
}

/// Read `STORAGE_BACKEND` and its settings: `STORAGE_BLOB_URL` and
/// `MANAGED_IDENTITY_CLIENT_ID` for `azure`. Dev builds add `azurite`
/// (Azurite's dev account, its default endpoint on localhost) and `files`,
/// their default, under `DATA_DIR`; release builds have only `azure`, and
/// require an HTTPS endpoint.
pub(crate) fn storage_from_lookup(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<StorageConfig, String> {
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
// Loopback URLs
// ============================================================================

/// Returns `true` when `url` is an `http://` URL whose host is the loopback
/// interface (`localhost`, `127.0.0.1`, or `::1`).
///
/// Keeps release builds' SKR sidecar traffic on loopback.
#[cfg(any(test, not(feature = "dev")))]
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

    #[test]
    fn logs_are_json_in_release_builds_and_text_in_dev_builds_unless_set() {
        let format = |value: Option<&str>| {
            log_format_from_lookup(&|key: &str| {
                (key == "LOG_FORMAT")
                    .then(|| value.map(String::from))
                    .flatten()
            })
        };
        let default = if cfg!(feature = "dev") {
            LogFormat::Text
        } else {
            LogFormat::Json
        };
        assert_eq!(format(None), Ok(default));
        assert_eq!(format(Some("json")), Ok(LogFormat::Json));
        assert_eq!(format(Some("text")), Ok(LogFormat::Text));
        assert!(format(Some("JSON")).is_err());
    }

    fn config_from(vars: &[(&str, &str)]) -> Result<ServerConfig, String> {
        ServerConfig::from_lookup(|key| {
            vars.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        })
    }

    const TENANT: &str = "11111111-1111-1111-1111-111111111111";
    const API: &str = "22222222-2222-2222-2222-222222222222";
    const DASHBOARD: &str = "33333333-3333-3333-3333-333333333333";

    /// Settings a release build requires.
    const RELEASE_BASE: [(&str, &str); 8] = [
        ("ENVIRONMENT", "pilot"),
        ("API_HOSTNAME", "api.pilot.example"),
        ("KEY_VAULT_URL", "kv.vault.azure.net"),
        ("STORAGE_BLOB_URL", "https://acct.blob.core.windows.net"),
        ("ENTRA_TENANT_ID", TENANT),
        ("ENTRA_API_CLIENT_ID", API),
        ("ENTRA_ALLOWED_CLIENT_IDS", DASHBOARD),
        ("DASHBOARD_ORIGIN", "https://app.pilot.example"),
    ];

    #[test]
    fn entra_settings_are_canonical_uuids() {
        let config = complete(&[(
            "ENTRA_ALLOWED_CLIENT_IDS",
            "33333333-3333-3333-3333-333333333333, 44444444-4444-4444-4444-44444444444A",
        )])
        .expect("valid config");
        assert_eq!(
            config.entra,
            EntraConfig {
                tenant_id: TENANT.into(),
                api_client_id: API.into(),
                allowed_client_ids: vec![
                    DASHBOARD.into(),
                    "44444444-4444-4444-4444-44444444444a".into()
                ],
            }
        );
        assert_eq!(
            config.entra.issuer(),
            format!("https://login.microsoftonline.com/{TENANT}/v2.0")
        );
        assert!(complete(&[("ENTRA_TENANT_ID", "contoso")]).is_err());
        assert!(complete(&[("ENTRA_ALLOWED_CLIENT_IDS", "a,b")]).is_err());
        assert_eq!(config.dashboard_origin, "https://app.pilot.example");
        assert!(complete(&[("DASHBOARD_ORIGIN", "https://app.pilot.example/")]).is_err());
    }

    #[cfg(feature = "dev")]
    #[test]
    fn dev_builds_default_to_the_dev_app_registrations_and_vite() {
        let config = config_from(&[]).expect("dev defaults");
        assert_eq!(config.entra.tenant_id, dev_entra::TENANT_ID);
        assert_eq!(config.entra.api_client_id, dev_entra::API_CLIENT_ID);
        assert_eq!(
            config.entra.allowed_client_ids,
            [dev_entra::DASHBOARD_CLIENT_ID, AZURE_CLI_CLIENT_ID]
        );
        assert_eq!(config.dashboard_origin, "http://localhost:5173");
        assert_eq!(
            config.dev_token_key,
            PathBuf::from("dev/keys/entra-signing-key.pem")
        );
        assert_eq!(config.environment, "dev");
    }

    #[cfg(feature = "dev")]
    #[test]
    fn dev_builds_can_speed_up_the_reconciler_and_inject_faults() {
        use std::time::Duration;
        let config = config_from(&[]).unwrap();
        assert_eq!(config.reconciler, crate::reconciler::Timing::default());
        assert!(!config.fault_injection);
        let config = config_from(&[
            ("RECONCILER_INTERVAL_SECS", "15"),
            ("RECONCILER_MIN_AGE_SECS", "45"),
            ("FAULT_INJECTION", "on"),
        ])
        .unwrap();
        assert_eq!(config.reconciler.interval, Duration::from_secs(15));
        assert_eq!(config.reconciler.min_age, Duration::from_secs(45));
        assert!(config.fault_injection);
        assert!(config_from(&[("FAULT_INJECTION", "yes")]).is_err());
        assert!(config_from(&[("RECONCILER_MIN_AGE_SECS", "0")]).is_err());
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn release_builds_refuse_fault_injection_and_reconciler_tuning() {
        for name in [
            "FAULT_INJECTION",
            "RECONCILER_INTERVAL_SECS",
            "RECONCILER_MIN_AGE_SECS",
        ] {
            let err = complete(&[(name, "1")]).expect_err(name);
            assert!(err.contains(name), "{err}");
        }
    }

    #[test]
    fn the_environment_name_can_name_a_storage_directory() {
        assert_eq!(complete(&[]).unwrap().environment, "pilot");
        assert_eq!(
            complete(&[("ENVIRONMENT", "staging-2")])
                .unwrap()
                .environment,
            "staging-2"
        );
        for bad in ["Pilot", "pilot/x", "..", "pilot env"] {
            assert!(complete(&[("ENVIRONMENT", bad)]).is_err(), "{bad}");
        }
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn release_builds_require_entra_settings_and_refuse_dev_clients_and_keys() {
        for name in [
            "ENTRA_TENANT_ID",
            "ENTRA_API_CLIENT_ID",
            "ENTRA_ALLOWED_CLIENT_IDS",
            "DASHBOARD_ORIGIN",
            "ENVIRONMENT",
        ] {
            assert!(config_from(&base_without(&[name])).is_err(), "{name}");
        }
        let cli = format!("{DASHBOARD},{AZURE_CLI_CLIENT_ID}");
        let err = config_from(
            &[("ENTRA_ALLOWED_CLIENT_IDS", cli.as_str())]
                .into_iter()
                .chain(base_without(&["ENTRA_ALLOWED_CLIENT_IDS"]))
                .collect::<Vec<_>>(),
        )
        .expect_err("the Azure CLI is dev-only");
        assert!(err.contains("Azure CLI"), "{err}");
        assert!(complete(&[("DASHBOARD_ORIGIN", "http://localhost:5173")]).is_err());
        let err = complete(&[("DEV_TOKEN_KEY", "dev/keys/entra-signing-key.pem")])
            .expect_err("no dev token key in release builds");
        assert!(err.contains("DEV_TOKEN_KEY"), "{err}");
    }

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
            ("TRANSPORT", "https"),
        ])
        .expect("valid config");
        assert_eq!(config.addr, "[::1]:9443".parse().unwrap());
        assert_eq!(
            config.transport,
            Transport::Https {
                hostname: "api.pilot.example".into()
            }
        );
    }

    #[test]
    fn server_config_rejects_certificate_files_and_bad_values() {
        let err = complete(&[("TLS_CERT_PATH", "cert.pem")]).unwrap_err();
        assert!(err.contains("tls-key"), "{err}");
        assert!(complete(&[("TLS_KEY_PATH", "key.pem")]).is_err());
        assert!(complete(&[("TRANSPORT", "quic")]).is_err());
        assert!(complete(&[
            ("TRANSPORT", "https"),
            ("API_HOSTNAME", "https://api.example")
        ])
        .is_err());
        assert!(complete(&[("PORT", "http")]).is_err());
        assert!(complete(&[("BIND_ADDR", "localhost")]).is_err());
        assert!(complete(&[("RATE_LIMIT_IP_BURST", "0")]).is_err());
        assert!(complete(&[("RATE_LIMIT_IP_PER_SECOND", "lots")]).is_err());
    }

    #[test]
    fn rate_limits_have_defaults_and_can_be_tuned() {
        let config = complete(&[]).unwrap();
        assert_eq!(
            config.rate_limits,
            RateLimits {
                ip_per_second: 20,
                ip_burst: 40,
                user_mutations_per_second: 10,
            }
        );
        let config = complete(&[("RATE_LIMIT_USER_MUTATIONS_PER_SECOND", "3")]).unwrap();
        assert_eq!(config.rate_limits.user_mutations_per_second, 3);
    }

    #[cfg(feature = "dev")]
    #[test]
    fn dev_build_defaults_to_plain_http_on_loopback() {
        let config = config_from(&[]).expect("dev defaults");
        assert_eq!(config.addr, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(config.transport, Transport::PlainHttp);
        let config = config_from(&[("TRANSPORT", "https")]).unwrap();
        assert_eq!(
            config.transport,
            Transport::Https {
                hostname: "localhost".into()
            }
        );
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn release_build_serves_only_https_for_its_hostname() {
        assert!(config_from(&base_without(&["API_HOSTNAME"])).is_err());
        let err = complete(&[("TRANSPORT", "http")]).unwrap_err();
        assert!(err.contains("only HTTPS"), "{err}");
        let config = complete(&[]).expect("release config");
        assert_eq!(config.addr, "0.0.0.0:8443".parse().unwrap());
        assert!(matches!(config.transport, Transport::Https { .. }));
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
