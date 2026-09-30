// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Log output: one JSON object per line in release builds, human-readable
//! text in dev builds (`LOG_FORMAT` chooses).
//!
//! A request's lines carry its span: `method`, `path`, `request_id`, and
//! once known the `route` template and the caller's `user_id`. In JSON the
//! span's fields sit under `span`, and the event's own fields at the top
//! level beside `timestamp`, `level`, `target` and `message`. The line at
//! the end of a request adds `status` and `latency_ms`, which log-based
//! metrics count by route. People appear only as `user_id`.

use std::time::Duration;

use axum::body::Body;
use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use tracing::{field, info, Span, Subscriber};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

/// Send log lines to stdout, filtered by `RUST_LOG` (default `info`).
pub fn init(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Json => tracing::subscriber::set_global_default(json(filter, std::io::stdout)),
        LogFormat::Text => tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .finish(),
        ),
    }
    .expect("logging is set up once");
}

fn json<W>(filter: EnvFilter, writer: W) -> impl Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(writer)
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .finish()
}

/// The span every request's log lines carry. `route` and `user_id` are
/// recorded once routing and authentication know them.
pub fn request_span(request: &axum::http::Request<Body>) -> Span {
    let id = request
        .extensions()
        .get::<crate::request_id::RequestId>()
        .map(|id| id.0.as_str())
        .unwrap_or("-");
    tracing::info_span!(
        "request",
        method = %request.method(),
        path = %request.uri().path(),
        request_id = %id,
        route = field::Empty,
        user_id = field::Empty,
    )
}

/// The line at the end of a request.
pub fn finished(response: &Response, latency: Duration, _span: &Span) {
    info!(
        status = response.status().as_u16(),
        latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX),
        "Finished the request"
    );
}

/// Middleware: name the request's route template on its span.
pub async fn name_route(request: Request, next: Next) -> Response {
    if let Some(route) = request.extensions().get::<MatchedPath>() {
        Span::current().record("route", route.as_str());
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::http::header;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::entra::mint::Spec;
    use crate::auth::entra::tests::{config, entra_key};
    use crate::state::AppState;

    /// A log writer into memory.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'w> MakeWriter<'w> for Captured {
        type Writer = Self;

        fn make_writer(&'w self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn a_request_logs_its_id_route_user_status_and_latency_as_json() {
        let captured = Captured::default();
        let _logs =
            tracing::subscriber::set_default(json(EnvFilter::new("info"), captured.clone()));
        let mut spec = Spec::valid(&config());
        spec.email = Some("ada@example.com".into());
        let oid = spec.oid.clone();
        let token = spec.sign(entra_key()).unwrap();

        let response = crate::router(AppState::for_tests())
            .oneshot(
                axum::http::Request::get("/v1/users/me")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let me: Value = serde_json::from_slice(&body).unwrap();

        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        for secret in [token.as_str(), "ada@example.com", oid.as_str()] {
            assert!(!text.contains(secret), "{text}");
        }
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("a JSON line"))
            .collect();
        let end = lines
            .iter()
            .find(|line| line["message"] == "Finished the request")
            .expect("the request's last line");
        assert_eq!(end["status"], 200);
        assert!(end["latency_ms"].is_u64(), "{end}");
        assert_eq!(end["level"], "INFO");
        assert!(end["timestamp"].is_string());
        let span = &end["span"];
        assert_eq!(span["route"], "/v1/users/me");
        assert_eq!(span["user_id"], me["user_id"]);
        let request_id = span["request_id"].as_str().unwrap();
        assert!(uuid::Uuid::parse_str(request_id).is_ok());
        assert!(lines
            .iter()
            .filter(|line| line.get("span").is_some())
            .all(|line| line["span"]["request_id"] == request_id));
    }
}
