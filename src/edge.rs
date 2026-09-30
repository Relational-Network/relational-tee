// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Edge controls: CORS for the dashboard origin, and rate limits.
//!
//! There is no WAF or proxy in front of the worker, so it limits requests
//! itself, in memory: per client IP on every request, and per `user_id` on
//! mutations once the caller is known. The limits are per worker, so the
//! effective limits scale with the worker count. Excess requests get `429`
//! `rate_limited` with `Retry-After`.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::warn;

use crate::config::RateLimits;
use crate::error::ApiError;

/// How often limiter state for idle keys is dropped.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// The CORS layer: only `origin`, which may call with a bearer token (not
/// cookies) and read the headers clients act on.
pub fn cors(origin: &str) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            HeaderValue::from_str(origin).expect("the dashboard origin is a valid header value")
        ]))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
        ])
        .expose_headers([
            HeaderName::from_static("idempotent-replayed"),
            header::RETRY_AFTER,
            crate::request_id::REQUEST_ID_HEADER,
        ])
        .max_age(Duration::from_secs(86_400))
}

/// The per-IP and per-user rate limiters.
pub struct Limiter {
    per_ip: DefaultKeyedRateLimiter<IpAddr>,
    per_user: DefaultKeyedRateLimiter<String>,
    clock: DefaultClock,
}

fn quota(per_second: u32, burst: u32) -> Quota {
    let nonzero = |n: u32| NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN);
    Quota::per_second(nonzero(per_second)).allow_burst(nonzero(burst))
}

impl Limiter {
    pub fn new(limits: &RateLimits) -> Self {
        Self {
            per_ip: RateLimiter::keyed(quota(limits.ip_per_second, limits.ip_burst)),
            per_user: RateLimiter::keyed(quota(
                limits.user_mutations_per_second,
                limits.user_mutations_per_second,
            )),
            clock: DefaultClock::default(),
        }
    }

    /// 429 once `ip` is over its limit.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), ApiError> {
        self.per_ip.check_key(&ip).map_err(|not_until| {
            let wait = not_until.wait_time_from(self.clock.now());
            warn!(%ip, "Rate-limited a client IP");
            ApiError::rate_limited(wait)
        })
    }

    /// 429 once `user_id` is over its limit, if `method` changes anything.
    pub fn check_user(&self, method: &Method, user_id: &str) -> Result<(), ApiError> {
        if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
            return Ok(());
        }
        self.per_user
            .check_key(&user_id.to_string())
            .map_err(|not_until| {
                let wait = not_until.wait_time_from(self.clock.now());
                warn!(user_id, "Rate-limited a user's mutations");
                ApiError::rate_limited(wait)
            })
    }

    /// Drop the state of keys that are back to a full burst, now and then,
    /// so memory follows recent callers rather than every caller ever seen.
    pub fn spawn_cleanup(self: &Arc<Self>) {
        let limiter = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                tick.tick().await;
                limiter.per_ip.retain_recent();
                limiter.per_ip.shrink_to_fit();
                limiter.per_user.retain_recent();
                limiter.per_user.shrink_to_fit();
            }
        });
    }
}

/// Middleware: the per-IP limit. The peer address is the client's: the load
/// balancer passes connections through without rewriting the source.
/// Requests without one (in-process tests) aren't limited.
pub async fn limit_ip(
    State(limiter): State<Arc<Limiter>>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        if let Err(e) = limiter.check_ip(peer.ip()) {
            return e.into_response();
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn limits(ip_per_second: u32, ip_burst: u32, user: u32) -> RateLimits {
        RateLimits {
            ip_per_second,
            ip_burst,
            user_mutations_per_second: user,
        }
    }

    fn app(limiter: Arc<Limiter>) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(limiter, limit_ip))
            .layer(cors("http://localhost:5173"))
            .layer(axum::middleware::from_fn(
                crate::request_id::request_context,
            ))
    }

    fn from(ip: [u8; 4]) -> Request {
        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 40000))));
        request
    }

    #[tokio::test]
    async fn each_ip_gets_its_burst_then_429_with_retry_after() {
        let app = app(Arc::new(Limiter::new(&limits(1, 2, 1))));
        for _ in 0..2 {
            let response = app.clone().oneshot(from([10, 0, 0, 1])).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = app.clone().oneshot(from([10, 0, 0, 1])).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "rate_limited");
        assert!(body["request_id"].is_string());

        let other = app.clone().oneshot(from([10, 0, 0, 2])).await.unwrap();
        assert_eq!(other.status(), StatusCode::OK, "limits are per IP");
    }

    #[test]
    fn users_are_limited_on_mutations_only() {
        let limiter = Limiter::new(&limits(100, 100, 2));
        for _ in 0..5 {
            assert!(limiter.check_user(&Method::GET, "u1").is_ok());
        }
        assert!(limiter.check_user(&Method::POST, "u1").is_ok());
        assert!(limiter.check_user(&Method::DELETE, "u1").is_ok());
        let err = limiter.check_user(&Method::PUT, "u1").unwrap_err();
        assert_eq!(err.code, "rate_limited");
        assert!(limiter.check_user(&Method::POST, "u2").is_ok());
    }

    #[tokio::test]
    async fn cors_allows_only_the_dashboard_origin() {
        let app = app(Arc::new(Limiter::new(&limits(100, 100, 100))));
        let preflight = |origin: &str| {
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/")
                .header(header::ORIGIN, origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization,content-type,idempotency-key",
                )
                .body(Body::empty())
                .unwrap()
        };

        let ok = app
            .clone()
            .oneshot(preflight("http://localhost:5173"))
            .await
            .unwrap();
        let h = ok.headers();
        assert_eq!(
            h[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "http://localhost:5173"
        );
        assert_eq!(h[header::ACCESS_CONTROL_MAX_AGE], "86400");
        let methods = h[header::ACCESS_CONTROL_ALLOW_METHODS].to_str().unwrap();
        for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            assert!(methods.contains(m), "{methods}");
        }
        let allowed = h[header::ACCESS_CONTROL_ALLOW_HEADERS].to_str().unwrap();
        assert!(allowed.contains("idempotency-key"), "{allowed}");
        assert!(!h.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));

        let refused = app
            .clone()
            .oneshot(preflight("https://evil.example"))
            .await
            .unwrap();
        assert!(!refused
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));

        let simple = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ORIGIN, "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let exposed = simple.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS]
            .to_str()
            .unwrap();
        for name in ["idempotent-replayed", "retry-after", "x-request-id"] {
            assert!(exposed.contains(name), "{exposed}");
        }
    }
}
