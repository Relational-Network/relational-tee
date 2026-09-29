// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Configuration for the relational-tee worker.
//!
//! Non-sensitive values are hardcoded here. Only values that **must** differ
//! between environments use `env::var` with a default fallback.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

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

/// Default storage directory.
#[cfg(feature = "dev")]
pub const DEFAULT_DATA_DIR: &str = "data";
#[cfg(not(feature = "dev"))]
pub const DEFAULT_DATA_DIR: &str = "/data";

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

/// Process configuration read once from the environment at startup.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub data_dir: PathBuf,
    pub transport: Transport,
}

impl ServerConfig {
    /// Read `BIND_ADDR`, `PORT`, `DATA_DIR`, `TLS_CERT_PATH` and `TLS_KEY_PATH`.
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
        let data_dir = PathBuf::from(lookup("DATA_DIR").unwrap_or_else(|| DEFAULT_DATA_DIR.into()));

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
            data_dir,
            transport,
        })
    }
}

// ============================================================================
// Solana
// ============================================================================

// TODO: Solana's public devnet RPC is rate-limited and has no SLA. Switch to a
// paid provider before production, keeping its API key out of the CCE policy,
// which is public.
/// Solana RPC endpoint. Hardcoded to devnet.
/// To switch to mainnet, change this constant and rebuild.
pub const SOLANA_RPC_URL: &str = "https://api.devnet.solana.com";

/// Solana's public RPC endpoints. They are rate-limited and have no SLA, so the
/// server warns at startup when `SOLANA_RPC_URL` is one of them.
pub const PUBLIC_SOLANA_RPC_URLS: &[&str] = &[
    "https://api.devnet.solana.com",
    "https://api.testnet.solana.com",
    "https://api.mainnet-beta.solana.com",
];

/// Solana network name. Hardcoded to devnet.
pub const SOLANA_NETWORK: &str = "devnet";

// ============================================================================
// Background Indexer
// ============================================================================

/// Whether the background tx indexer runs continuously.
///
/// Hardcoded to `false` — transaction updates are pulled on-demand by API
/// handlers.  Flip to `true` and rebuild to enable continuous polling.
pub const INDEXER_ENABLED: bool = false;

/// Tx indexer poll interval in seconds (when enabled).
pub const INDEXER_POLL_INTERVAL_SECS: u64 = 60;

/// Minimum seconds between on-demand Solana RPC syncs for the same address.
///
/// Prevents expensive repeated RPC calls on rapid page loads.
/// After syncing an address, subsequent requests within this window
/// skip the RPC call and return cached data from redb.
pub const SYNC_COOLDOWN_SECS: u64 = 10;

/// LRU cache capacity (number of wallet first-pages cached).
pub const TX_CACHE_CAPACITY: usize = 128;

/// LRU cache entry TTL (seconds).
pub const TX_CACHE_TTL_SECS: u64 = 30;

// ============================================================================
// Nonce Replay Protection
// ============================================================================

/// Maximum age of a nonce entry in seconds before it is purged (24 hours).
pub const NONCE_MAX_AGE_SECS: i64 = 86_400;

/// How often the background nonce purge task runs (in seconds, every 15 min).
pub const NONCE_PURGE_INTERVAL_SECS: u64 = 900;

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
/// Used to gate the "plain HTTP JWKS" warning and the production hard-block.
/// Substring matching (e.g. `url.contains("localhost")`) is unsafe — a host
/// like `attacker.example.com/localhost/...` would have falsely passed.
/// This parser extracts the authority and matches the host exactly.
pub fn is_loopback_http_jwks(url: &str) -> bool {
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
    fn loopback_http_jwks_accepts_loopback_hosts() {
        assert!(is_loopback_http_jwks("http://localhost:9100/jwks"));
        assert!(is_loopback_http_jwks(
            "http://127.0.0.1:9100/.well-known/jwks.json"
        ));
        assert!(is_loopback_http_jwks("http://[::1]:9100/jwks"));
        assert!(is_loopback_http_jwks("http://localhost"));
    }

    #[test]
    fn loopback_http_jwks_rejects_substring_bypass() {
        // The old `url.contains("localhost")` check would have accepted these.
        assert!(!is_loopback_http_jwks(
            "http://attacker.example.com/localhost"
        ));
        assert!(!is_loopback_http_jwks("http://localhost.evil.com/jwks"));
        assert!(!is_loopback_http_jwks("http://user@evil.com/127.0.0.1"));
        assert!(!is_loopback_http_jwks(
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

    #[test]
    fn server_config_reads_overrides() {
        let config = config_from(&[
            ("BIND_ADDR", "::1"),
            ("PORT", "9443"),
            ("DATA_DIR", "/var/lib/rt"),
            ("TLS_CERT_PATH", "cert.pem"),
            ("TLS_KEY_PATH", "key.pem"),
        ])
        .expect("valid config");
        assert_eq!(config.addr, "[::1]:9443".parse().unwrap());
        assert_eq!(config.data_dir, PathBuf::from("/var/lib/rt"));
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
        let tls = [("TLS_CERT_PATH", "c"), ("TLS_KEY_PATH", "k")];
        assert!(config_from(&[tls[0], tls[1], ("PORT", "http")]).is_err());
        assert!(config_from(&[tls[0], tls[1], ("BIND_ADDR", "localhost")]).is_err());
    }

    #[cfg(feature = "dev")]
    #[test]
    fn dev_build_defaults_to_plain_http_on_loopback() {
        let config = config_from(&[]).expect("dev defaults");
        assert_eq!(config.addr, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(config.data_dir, PathBuf::from("data"));
        assert_eq!(config.transport, Transport::PlainHttp);
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn release_build_requires_tls() {
        assert!(config_from(&[]).is_err());
        let config = config_from(&[("TLS_CERT_PATH", "c"), ("TLS_KEY_PATH", "k")])
            .expect("release config with TLS");
        assert_eq!(config.addr, "0.0.0.0:8443".parse().unwrap());
        assert_eq!(config.data_dir, PathBuf::from("/data"));
    }

    #[test]
    fn loopback_http_jwks_rejects_https_and_other_schemes() {
        assert!(!is_loopback_http_jwks("https://localhost/jwks"));
        assert!(!is_loopback_http_jwks("file:///tmp/jwks"));
    }
}
