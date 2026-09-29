// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! TLS utilities for the enclave server.
//!
//! Handles loading and normalization of Gramine RA-TLS certificates which use
//! non-standard PEM labels.

/// Load TLS configuration from PEM or DER format.
///
/// This handles both Gramine RA-TLS PEM output (with "TRUSTED CERTIFICATE" labels)
/// and DER-only scenarios.
pub async fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> std::io::Result<axum_server::tls_rustls::RustlsConfig> {
    let cert = tokio::fs::read(cert_path).await?;
    let key = tokio::fs::read(key_path).await?;

    // Normalize RA-TLS PEM labels.
    let cert = normalize_ratls_pem(cert);

    // Try PEM first, fall back to DER.
    match axum_server::tls_rustls::RustlsConfig::from_pem(cert.clone(), key.clone()).await {
        Ok(config) => Ok(config),
        Err(pem_err) => {
            match axum_server::tls_rustls::RustlsConfig::from_der(vec![cert], key).await {
                Ok(config) => Ok(config),
                Err(der_err) => Err(std::io::Error::other(format!(
                    "failed to parse TLS cert/key as PEM ({pem_err}) or DER ({der_err})"
                ))),
            }
        }
    }
}

/// Normalize RA-TLS PEM certificates.
///
/// Gramine RA-TLS emits "TRUSTED CERTIFICATE" PEM labels, but rustls expects
/// standard "CERTIFICATE" labels. This function rewrites the headers.
///
/// Returns the original bytes unchanged if not valid UTF-8 or doesn't contain
/// the non-standard labels.
fn normalize_ratls_pem(cert: Vec<u8>) -> Vec<u8> {
    const TRUSTED_BEGIN: &str = "-----BEGIN TRUSTED CERTIFICATE-----";
    const TRUSTED_END: &str = "-----END TRUSTED CERTIFICATE-----";
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let Ok(text) = std::str::from_utf8(&cert) else {
        return cert;
    };
    if !text.contains(TRUSTED_BEGIN) {
        return cert;
    }
    text.replace(TRUSTED_BEGIN, BEGIN)
        .replace(TRUSTED_END, END)
        .into_bytes()
}
