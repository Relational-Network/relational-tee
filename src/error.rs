// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Unified error type for wallet API responses.
//!
//! Every error path in the wallet service returns a consistent JSON body:
//!
//! ```json
//! { "error": "human-readable message" }
//! ```
//!
//! Use the named constructors (`not_found`, `bad_request`, etc.) so the HTTP
//! status code is always semantically correct.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Unified API error that serializes to `{ "error": "<message>" }`.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    /// Create an error with the given status and message.
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            message: msg.into(),
        }
    }

    /// 400 Bad Request — invalid input, missing fields, etc.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }

    /// 403 Forbidden — user lacks permission for this resource.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }

    /// 404 Not Found — resource does not exist.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }

    /// 409 Conflict — resource already exists.
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, msg)
    }

    /// 422 Unprocessable Entity — semantically invalid (e.g., bad Solana address).
    pub fn unprocessable(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, msg)
    }

    /// 500 Internal Server Error — unexpected failure.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }

    /// 503 Service Unavailable — Solana RPC unreachable, storage not ready, etc.
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, msg)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status.as_u16(), self.message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, Json(body)).into_response()
    }
}

// ── Convenient From impls ──────────────────────────────────────────

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        tracing::error!(error = %e, "I/O error");
        Self::internal("internal storage error")
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!(error = %e, "JSON serialization error");
        Self::internal("internal serialization error")
    }
}
