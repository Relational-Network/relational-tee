// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! JWT validation and role-based access control (RBAC).
//!
//! This module provides:
//! - JWT validation against AVS JWKS
//! - Token data extraction
//! - Role-based Axum extractors (AdminToken, UserToken, ReadOnlyToken)
//!
//! # Role Hierarchy
//!
//! Roles follow a hierarchy where higher roles include lower permissions:
//! - `admin` - Full access (includes user, analyst, and read_only)
//! - `user` - Read/write access (includes analyst and read_only)
//! - `analyst` - Marketplace access: buy/redeem DRTs, view pools (includes read_only)
//! - `read_only` - Read-only access
//!
//! # Usage
//!
//! ```rust,ignore
//! // Any authenticated user
//! async fn public_endpoint(token: TokenData) -> impl IntoResponse { ... }
//!
//! // Admin only
//! async fn admin_endpoint(AdminToken(token): AdminToken) -> impl IntoResponse { ... }
//!
//! // User or admin
//! async fn user_endpoint(UserToken(token): UserToken) -> impl IntoResponse { ... }
//!
//! // Analyst, user, or admin
//! async fn analyst_endpoint(AnalystToken(token): AnalystToken) -> impl IntoResponse { ... }
//!
//! // Any role (read_only, user, analyst, or admin)
//! async fn read_endpoint(ReadOnlyToken(token): ReadOnlyToken) -> impl IntoResponse { ... }
//! ```

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
    Json,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::time::Instant;
use tracing::{debug, warn};

use crate::config::{avs_jwks_url, is_loopback_http_jwks, AVS_ISSUER, JWKS_CACHE_TTL_SECS};
use crate::crypto::{enclave_key, Jwk, JwksResponse};
use crate::http_client::HttpClient;
use crate::state::AppState;

/// Claims from AVS-issued attestation tokens.
///
/// These claims are validated by `jsonwebtoken` (exp, aud) and extracted
/// for use in request handlers.
///
/// **Note:** Some fields like `iss`, `aud`, `iat`, `nonce` are deserialized but not
/// directly accessed after validation. They are needed for JWT parsing and future
/// features (e.g., nonce-based replay protection, multi-issuer support).
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields needed for JWT deserialization; some used by jsonwebtoken validation
pub struct AttestationClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Option<String>,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    /// Enclave's public encryption key — used for token-binding validation.
    #[serde(default)]
    pub enclave_public_key: Option<Jwk>,
}

/// Validated token data extracted for request handlers.
#[derive(Debug, Clone)]
pub struct TokenData {
    /// User/client identifier from the `sub` claim.
    pub sub: String,
    /// User role for RBAC (admin, user, analyst, read_only).
    pub role: String,
}

impl TokenData {
    /// Check if the user has the required role.
    ///
    /// Role hierarchy: admin > user > analyst > read_only
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let token = TokenData { role: "admin".to_string(), ... };
    /// assert!(token.has_role("admin"));
    /// assert!(token.has_role("user"));
    /// assert!(token.has_role("analyst"));
    /// assert!(token.has_role("read_only"));
    ///
    /// let token = TokenData { role: "analyst".to_string(), ... };
    /// assert!(!token.has_role("admin"));
    /// assert!(!token.has_role("user"));
    /// assert!(token.has_role("analyst"));
    /// assert!(token.has_role("read_only"));
    /// ```
    pub fn has_role(&self, required: &str) -> bool {
        match required {
            "read_only" => matches!(
                self.role.as_str(),
                "admin" | "user" | "analyst" | "read_only"
            ),
            "analyst" => matches!(self.role.as_str(), "admin" | "user" | "analyst"),
            "user" => matches!(self.role.as_str(), "admin" | "user"),
            "admin" => self.role == "admin",
            _ => false,
        }
    }
}

/// Cached JWKS for token verification.
pub struct JwksCache {
    pub keys: Vec<(String, DecodingKey)>,
    pub fetched_at: Instant,
}

/// Fetch JWKS from AVS and parse the decoding keys.
pub async fn fetch_jwks(url: &str) -> Result<Vec<(String, DecodingKey)>, String> {
    // Build HTTP client — use AVS_CA_CERT_PATH as an extra trusted root when
    // set, otherwise use the webpki bundle (no blanket cert bypass).
    let client = if let Ok(ca_path) = std::env::var("AVS_CA_CERT_PATH") {
        let pem = std::fs::read(&ca_path)
            .map_err(|e| format!("failed to read AVS_CA_CERT_PATH ({ca_path}): {e}"))?;
        let c = HttpClient::with_extra_ca_pem(&pem)
            .map_err(|e| format!("invalid PEM in AVS_CA_CERT_PATH ({ca_path}): {e}"))?;
        tracing::info!(path = %ca_path, "Loaded custom CA certificate for JWKS fetch");
        c
    } else {
        HttpClient::new()
    }
    .with_timeout(std::time::Duration::from_secs(10));

    let response = client
        .get(url)
        .await
        .map_err(|e| format!("failed to fetch JWKS: {e}"))?;
    if !response.is_success() {
        return Err(format!("JWKS fetch returned HTTP {}", response.status()));
    }
    let jwks: JwksResponse = response
        .into_json()
        .map_err(|e| format!("failed to parse JWKS: {e}"))?;

    let mut keys = Vec::new();
    for jwk in jwks.keys {
        let kid = jwk.kid.clone().unwrap_or_default();
        // Only accept EC P-256 keys — AVS signs with ES256 only.
        // RSA is explicitly rejected to avoid the Marvin Attack (RUSTSEC-2023-0071)
        // and to enforce the algorithm policy.
        if jwk.kty == "EC" {
            if let (Some(x), Some(y)) = (&jwk.x, &jwk.y) {
                match DecodingKey::from_ec_components(x, y) {
                    Ok(key) => keys.push((kid.clone(), key)),
                    Err(e) => warn!(kid = %kid, error = %e, "Skipping EC key — failed to parse"),
                }
            }
        } else {
            warn!(kid = %kid, kty = %jwk.kty, "Ignoring non-EC JWKS key — only EC P-256 (ES256) is accepted");
        }
    }
    Ok(keys)
}

/// Get or refresh JWKS cache.
pub async fn get_decoding_keys(state: &AppState) -> Result<Vec<(String, DecodingKey)>, String> {
    // Check cache validity.
    {
        let cache = state.jwks_cache.read().await;
        if let Some(ref c) = *cache {
            if c.fetched_at.elapsed().as_secs() < JWKS_CACHE_TTL_SECS {
                return Ok(c.keys.clone());
            }
        }
    }

    // Fetch and update cache.
    let url = avs_jwks_url();
    // Warn if using HTTP for a non-loopback host (insecure in production).
    // Uses parsed-host check; substring matching would let `evil.com/localhost`
    // through.
    if url.starts_with("http://") && !is_loopback_http_jwks(&url) {
        tracing::warn!(
            "JWKS URL uses HTTP - this is insecure in production: {}",
            url
        );
    }
    let keys = fetch_jwks(&url).await?;
    {
        let mut cache = state.jwks_cache.write().await;
        *cache = Some(JwksCache {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
    }
    Ok(keys)
}

/// Validate an AVS-issued JWT and extract claims.
///
/// Validates:
/// - Token signature using AVS JWKS
/// - Expiration time (`exp` claim)
/// - Audience (`aud` claim matches configured audience)
/// - Issuer (`iss` claim matches expected AVS issuer)
pub async fn validate_token(state: &AppState, token: &str) -> Result<TokenData, String> {
    let keys = get_decoding_keys(state).await?;
    if keys.is_empty() {
        warn!("JWKS contains no valid keys");
        return Err("no valid keys in JWKS".to_string());
    }

    // Decode header to find kid.
    let header = decode_header(token).map_err(|e| {
        warn!(error = %e, "Invalid token header");
        format!("invalid token header: {e}")
    })?;
    // Require non-empty `kid`. AVS sets `AVS_SIGNING_KEY_ID` on every token,
    // and rejecting missing/empty `kid` here removes the JWKS-ordering
    // dependency (no silent fallback to `keys[0]`) and surfaces key rotation
    // misconfiguration loudly.
    let kid = header
        .kid
        .as_deref()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            warn!("Token header missing or empty `kid`");
            "token header missing kid".to_string()
        })?;
    debug!(kid = %kid, "Validating token");

    // Find matching key — exact `kid` match required, no fallback.
    let decoding_key = keys
        .iter()
        .find(|(k, _)| k == kid)
        .map(|(_, key)| key)
        .ok_or_else(|| {
            warn!(kid = %kid, "No matching key found in JWKS");
            format!("no key found for kid: {kid}")
        })?;

    // Configure validation.
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[&state.audience]);
    validation.set_issuer(&[AVS_ISSUER]);
    validation.validate_exp = true;

    let token_data =
        decode::<AttestationClaims>(token, decoding_key, &validation).map_err(|e| {
            warn!(error = %e, "Token validation failed");
            format!("token validation failed: {e}")
        })?;

    // Verify token is bound to THIS enclave by comparing public key coordinates.
    // Prevents token-swap attacks where a legitimate AVS token issued for a
    // different enclave instance is replayed against this one.
    // This claim is MANDATORY — tokens without it are rejected.
    let token_key = token_data
        .claims
        .enclave_public_key
        .as_ref()
        .ok_or_else(|| {
            warn!(sub = %token_data.claims.sub, "Token missing enclave_public_key claim");
            "token missing required enclave_public_key claim".to_string()
        })?;
    {
        let actual = enclave_key().public_jwk();
        let key_matches = token_key.x.as_deref() == actual.x.as_deref()
            && token_key.y.as_deref() == actual.y.as_deref()
            && token_key.x.is_some()
            && token_key.y.is_some();
        if !key_matches {
            warn!(
                sub = %token_data.claims.sub,
                "Token enclave_public_key does not match this enclave — possible token-swap attack"
            );
            return Err("token is not bound to this enclave".to_string());
        }
        debug!("Token enclave_public_key verified — matches this enclave");
    }

    // Missing role defaults to least privilege rather than elevated access.
    // Tokens without a role claim are treated as read_only.
    if token_data.claims.role.is_none() {
        warn!(sub = %token_data.claims.sub, "Token missing role claim — defaulting to read_only");
    }
    let result = TokenData {
        sub: token_data.claims.sub.clone(),
        role: token_data
            .claims
            .role
            .clone()
            .unwrap_or_else(|| "read_only".to_string()),
    };

    debug!(
        sub = %result.sub,
        role = %result.role,
        "Token validated successfully"
    );

    Ok(result)
}

// ============================================================================
// Axum Extractors
// ============================================================================

/// Axum extractor for validated tokens from Authorization header.
///
/// Extracts and validates a Bearer token, returning the decoded `TokenData`.
/// Returns 401 Unauthorized if the token is missing or invalid.
impl FromRequestParts<AppState> for TokenData {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "missing authorization header"})),
                )
            })?;

        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid authorization header format"})),
            )
        })?;

        validate_token(state, token).await.map_err(|_| {
            // Detailed errors already logged inside validate_token.
            // Return generic message to prevent information leakage.
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid or expired token"})),
            )
        })
    }
}

// ============================================================================
// Role-based Extractors
// ============================================================================

/// Extractor that requires "admin" role.
///
/// Returns 403 Forbidden if the user does not have admin role.
#[derive(Debug, Clone)]
pub struct AdminToken(pub TokenData);

impl FromRequestParts<AppState> for AdminToken {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = TokenData::from_request_parts(parts, state).await?;
        if !token.has_role("admin") {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "admin role required"})),
            ));
        }
        Ok(AdminToken(token))
    }
}

/// Extractor that requires "user" role (or higher).
///
/// Returns 403 Forbidden if the user has only read_only role.
#[derive(Debug, Clone)]
pub struct UserToken(pub TokenData);

impl FromRequestParts<AppState> for UserToken {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = TokenData::from_request_parts(parts, state).await?;
        if !token.has_role("user") {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "user role required"})),
            ));
        }
        Ok(UserToken(token))
    }
}

/// Extractor that requires "analyst" role (or higher).
///
/// Returns 403 Forbidden if the user has only read_only role.
///
/// Used by `/v1/data/query` and the pool-detail / summary / audit read paths.
#[derive(Debug, Clone)]
pub struct AnalystToken(pub TokenData);

impl FromRequestParts<AppState> for AnalystToken {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = TokenData::from_request_parts(parts, state).await?;
        if !token.has_role("analyst") {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "analyst role required"})),
            ));
        }
        Ok(AnalystToken(token))
    }
}

/// Extractor that requires "read_only" role (or higher).
///
/// Any authenticated user with a valid role (admin, user, analyst, read_only) passes.
#[derive(Debug, Clone)]
pub struct ReadOnlyToken(pub TokenData);

impl FromRequestParts<AppState> for ReadOnlyToken {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = TokenData::from_request_parts(parts, state).await?;
        if !token.has_role("read_only") {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "read_only role required"})),
            ));
        }
        Ok(ReadOnlyToken(token))
    }
}
