// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The error body every endpoint returns.
//!
//! ```json
//! { "error": "human-readable message", "code": "snake_case_code", "request_id": "<X-Request-Id>" }
//! ```
//!
//! `code` is stable and meant for clients to branch on; `error` is for
//! people. Use the named constructors (`not_found`, `bad_request`, etc.) so
//! the status and code always agree, and [`ApiError::with_code`] for a more
//! specific code. The request ID is filled in by
//! [`crate::request_id::request_context`], which also rewrites errors that
//! don't come from [`ApiError`] (axum's own rejections, unknown routes) into
//! this shape.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;

/// The JSON error body.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Human-readable message.
    pub error: String,
    /// Stable snake_case code, for clients to branch on.
    pub code: String,
    /// The request's `X-Request-Id`, also logged and recorded in audit events.
    pub request_id: String,
}

/// An error's message and code, carried in the response's extensions until
/// the request ID is known.
#[derive(Debug, Clone)]
pub struct ErrorInfo {
    pub code: &'static str,
    pub message: String,
}

/// Unified API error.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    /// Create an error with the given status, code and message.
    fn new(status: StatusCode, code: &'static str, msg: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: msg.into(),
        }
    }

    /// Replace the default code with a more specific one.
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }

    /// 400 `bad_request` — invalid input, missing fields, etc.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", msg)
    }

    /// 401 `unauthorized` — missing, invalid or expired credentials.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", msg)
    }

    /// 403 `forbidden` — the caller lacks permission for this resource.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", msg)
    }

    /// 404 `not_found` — resource does not exist.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", msg)
    }

    /// 409 `conflict` — the resource exists, or changed concurrently.
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", msg)
    }

    /// 422 `unprocessable_entity` — semantically invalid (e.g., bad Solana address).
    pub fn unprocessable(msg: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unprocessable_entity",
            msg,
        )
    }

    /// 500 `internal_error` — unexpected failure.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg)
    }

    /// 503 `service_unavailable` — the worker can't serve this yet.
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", msg)
    }

    /// 503 `rpc_unavailable` — the Solana RPC failed or timed out.
    pub fn rpc_unavailable(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "rpc_unavailable", msg)
    }
}

/// The code for an error response that didn't come from [`ApiError`].
pub fn code_for_status(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        StatusCode::REQUEST_TIMEOUT => "request_timeout",
        StatusCode::CONFLICT => "conflict",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
        StatusCode::UNPROCESSABLE_ENTITY => "unprocessable_entity",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::SERVICE_UNAVAILABLE => "service_unavailable",
        s if s.is_server_error() => "internal_error",
        _ => "bad_request",
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.status.as_u16(),
            self.code,
            self.message
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message, "code": self.code });
        let mut response = (self.status, Json(body)).into_response();
        response.extensions_mut().insert(ErrorInfo {
            code: self.code,
            message: self.message,
        });
        response
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

impl From<crate::storage::StoreError> for ApiError {
    fn from(e: crate::storage::StoreError) -> Self {
        use crate::storage::StoreError;
        match e {
            StoreError::NotFound => Self::not_found("not found"),
            StoreError::PreconditionFailed => {
                Self::conflict("the resource changed while it was being updated; retry")
            }
            StoreError::Conflict => Self::conflict("the resource already exists or can't change"),
            StoreError::Integrity(m) => {
                tracing::error!(alert = "storage_integrity", error = %m, "Stored data failed an integrity check");
                Self::internal("stored data failed an integrity check").with_code("integrity_error")
            }
            StoreError::Unavailable(m) => {
                tracing::error!(error = %m, "Storage unavailable");
                Self::service_unavailable("storage unavailable").with_code("storage_unavailable")
            }
            StoreError::Invalid(m) => {
                tracing::error!(error = %m, "Storage request failed");
                Self::internal("internal storage error")
            }
        }
    }
}
