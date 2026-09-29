// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Request IDs and the error body.
//!
//! Every request gets an ID: the client's `X-Request-Id` if it's a valid
//! UUID, otherwise a new UUIDv4. The ID is returned in `X-Request-Id`,
//! recorded on the request's log span, set as the `correlation_id` of every
//! audit event the request causes, and added to every error body.

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::{code_for_status, ErrorBody, ErrorInfo};

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Error bodies from outside [`crate::error::ApiError`] longer than this are
/// replaced by the status text.
const MAX_FOREIGN_ERROR_BODY: usize = 4096;

tokio::task_local! {
    /// The ID of the request this task is serving.
    static REQUEST_ID: String;
}

/// The ID of the request the current task is serving, if any.
pub fn current() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// The request's ID, available to handlers and the trace span.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// The client's ID if it's a UUID, in canonical form; otherwise a new one.
fn request_id(request: &Request) -> String {
    request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| uuid::Uuid::parse_str(v.trim()).ok())
        .unwrap_or_else(uuid::Uuid::new_v4)
        .hyphenated()
        .to_string()
}

/// Middleware: assign the request ID, run the request with it in scope, and
/// finish the response with the header and, for errors, the error body.
pub async fn request_context(mut request: Request, next: Next) -> Response {
    let id = request_id(&request);
    request.extensions_mut().insert(RequestId(id.clone()));
    let response = REQUEST_ID.scope(id.clone(), next.run(request)).await;
    let mut response = with_error_body(response, &id).await;
    response.headers_mut().insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_str(&id).expect("a UUID is a valid header value"),
    );
    response
}

/// Rewrite an error response into the error body. [`ApiError`] responses
/// carry their code and message; other errors that aren't JSON (axum's
/// rejections, unknown routes) take a code from their status. JSON error
/// responses from elsewhere, such as a failed readiness probe, stay as
/// they are.
///
/// [`ApiError`]: crate::error::ApiError
async fn with_error_body(response: Response, request_id: &str) -> Response {
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }
    let info = response.extensions().get::<ErrorInfo>().cloned();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));
    let (code, message, mut parts) = match info {
        Some(info) => {
            let (parts, _) = response.into_parts();
            (info.code, info.message, parts)
        }
        None if is_json => return response,
        None => {
            let (parts, body) = response.into_parts();
            let text = to_bytes(body, MAX_FOREIGN_ERROR_BODY)
                .await
                .ok()
                .map(|b| String::from_utf8_lossy(&b).trim().to_string())
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| {
                    status
                        .canonical_reason()
                        .unwrap_or("request failed")
                        .to_string()
                });
            (code_for_status(status), text, parts)
        }
    };
    let body = serde_json::to_vec(&ErrorBody {
        error: message,
        code: code.to_string(),
        request_id: request_id.to_string(),
    })
    .expect("the error body serializes");
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(body))
}

/// The fallback for unknown routes.
pub async fn not_found() -> crate::error::ApiError {
    crate::error::ApiError::not_found("no such endpoint")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use tower::ServiceExt;

    async fn fails() -> crate::error::ApiError {
        crate::error::ApiError::conflict("already there").with_code("wallet_exists")
    }

    async fn audits() -> String {
        current().unwrap_or_default()
    }

    fn app() -> Router {
        Router::new()
            .route("/fails", get(fails))
            .route("/id", get(audits))
            .route(
                "/json",
                post(|Json(v): Json<serde_json::Value>| async move { Json(v) }),
            )
            .route(
                "/probe",
                get(|| async {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({"status": "not_ready"})),
                    )
                }),
            )
            .fallback(not_found)
            .layer(axum::middleware::from_fn(request_context))
    }

    async fn call(request: Request) -> (StatusCode, String, serde_json::Value) {
        let response = app().oneshot(request).await.unwrap();
        let status = response.status();
        let id = response.headers()[&REQUEST_ID_HEADER]
            .to_str()
            .unwrap()
            .to_string();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
        (status, id, body)
    }

    fn get_request(path: &str, id: Option<&str>) -> Request {
        let mut builder = Request::builder().uri(path);
        if let Some(id) = id {
            builder = builder.header("x-request-id", id);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn api_errors_carry_their_code_and_the_request_id() {
        let client_id = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let (status, id, body) = call(get_request("/fails", Some(client_id))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(id, client_id);
        assert_eq!(body["code"], "wallet_exists");
        assert_eq!(body["error"], "already there");
        assert_eq!(body["request_id"], client_id);
    }

    #[tokio::test]
    async fn invalid_client_ids_are_replaced_and_uuids_normalised() {
        let (_, id, _) = call(get_request("/id", Some("not-a-uuid"))).await;
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        let upper = "0F8FAD5B-D9CB-469F-A165-70867728950E";
        let (_, id, body) = call(get_request("/id", Some(upper))).await;
        assert_eq!(id, upper.to_lowercase());
        assert_eq!(
            body,
            serde_json::Value::String(id),
            "handlers see the same ID"
        );
    }

    #[tokio::test]
    async fn framework_errors_get_the_same_body() {
        let (status, id, body) = call(get_request("/nowhere", None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            (body["code"].as_str(), body["request_id"].as_str()),
            (Some("not_found"), Some(id.as_str()))
        );

        let bad_json = Request::builder()
            .method("POST")
            .uri("/json")
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .unwrap();
        let (status, _, body) = call(bad_json).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "bad_request");
        assert!(body["error"].as_str().unwrap().len() > 3);

        let (status, _, body) = call(
            Request::builder()
                .method("DELETE")
                .uri("/fails")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(body["code"], "method_not_allowed");
    }

    #[tokio::test]
    async fn json_probe_bodies_are_left_alone() {
        let (status, _, body) = call(get_request("/probe", None)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, serde_json::json!({"status": "not_ready"}));
    }
}
