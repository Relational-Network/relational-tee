// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Configuration constants for the relational-sdk enclave service.
//!
//! Non-sensitive values are hardcoded here. Only values that **must** differ
//! between environments use `env::var` with a default fallback.

use std::env;

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
// TLS (RA-TLS)
// ============================================================================

/// Fixed RA-TLS certificate location written by gramine-ratls (tmpfs).
pub const DEFAULT_TLS_CERT_PATH: &str = "/tmp/ra-tls.crt.pem";

/// Fixed RA-TLS key location written by gramine-ratls (tmpfs).
pub const DEFAULT_TLS_KEY_PATH: &str = "/tmp/ra-tls.key.pem";

// ============================================================================
// Server
// ============================================================================

/// Bind address for the HTTPS server.
///
/// Defaults to loopback. The enclave must only be reached via the Caddy
/// reverse proxy in production. Any deployment that binds the enclave to a
/// public interface bypasses the edge security controls (TLS termination,
/// CORS, future rate limiting). Override would require a code change
/// (intentional — the manifest also pins this).
pub const SERVER_HOST: [u8; 4] = [127, 0, 0, 1];

/// Port for the HTTPS server.
pub const SERVER_PORT: u16 = 8080;

/// Maximum request body size (50 MiB).
pub const MAX_BODY_SIZE: usize = 50 * 1024 * 1024;

// ============================================================================
// Storage
// ============================================================================

/// Encrypted data directory (Gramine mounts /data as encrypted FS).
/// Hardcoded — the manifest always mounts encrypted FS at /data.
pub const DATA_DIR: &str = "/data";

// ============================================================================
// Solana
// ============================================================================

/// Solana RPC endpoint. Hardcoded to devnet.
/// To switch to mainnet, change this constant and rebuild.
pub const SOLANA_RPC_URL: &str = "https://api.devnet.solana.com";

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
/// `relational-sdk/idl/digital_rights_tokens.json`.
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
/// Hardcoded to `true` because the enclave and the AVS are co-located on
/// localhost. In production the Caddy proxy terminates TLS externally.
/// If a future deployment separates AVS onto a remote host, flip to `false`
/// and rebuild.
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

    #[test]
    fn loopback_http_jwks_rejects_https_and_other_schemes() {
        assert!(!is_loopback_http_jwks("https://localhost/jwks"));
        assert!(!is_loopback_http_jwks("file:///tmp/jwks"));
    }
}
