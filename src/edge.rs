// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Edge controls: CORS for the dashboard origin, rate limits, and limits on
//! what one request or connection can hold.
//!
//! There is no WAF or proxy in front of the worker, so it limits requests
//! itself, in memory: per client IP on every request, and per `user_id` on
//! mutations once the caller is known. The limits are per worker, so the
//! effective limits scale with the worker count. Excess requests get `429`
//! `rate_limited` with `Retry-After`.
//!
//! Each request also has a body size and a time limit, larger on the upload
//! routes ([`REQUESTS`], [`UPLOADS`]); request headers are bounded in size
//! and must arrive in time ([`http_settings`]); and a worker serves at most
//! [`MAX_CONNECTIONS`] connections at once ([`ConnectionLimit`]).

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum_server::accept::Accept;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::warn;

use crate::config::{RateLimits, MAX_BODY_SIZE};
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

/// How much a request may send, and how long it may run.
#[derive(Debug, Clone, Copy)]
pub struct RequestLimits {
    /// Larger bodies get `413 payload_too_large`.
    pub body: usize,
    /// A request still running after this gets `408 request_timeout`, and
    /// stops where it is, as if the worker had died there: a retry with the
    /// same `Idempotency-Key` resumes it.
    pub time: Duration,
}

/// Every route but the uploads.
pub const REQUESTS: RequestLimits = RequestLimits {
    body: 1024 * 1024,
    time: Duration::from_secs(60),
};

/// The routes that take a dataset: a pool's initial upload, and issuance.
pub const UPLOADS: RequestLimits = RequestLimits {
    body: MAX_BODY_SIZE,
    time: Duration::from_secs(300),
};

impl RequestLimits {
    /// `routes`, held to these limits.
    pub fn apply<S: Clone + Send + Sync + 'static>(self, routes: Router<S>) -> Router<S> {
        routes
            .layer(axum::middleware::from_fn(
                move |request: Request, next: Next| self.in_time(request, next),
            ))
            .layer(DefaultBodyLimit::max(self.body))
    }

    async fn in_time(self, request: Request, next: Next) -> Response {
        match tokio::time::timeout(self.time, next.run(request)).await {
            Ok(response) => response,
            Err(_) => {
                let seconds = self.time.as_secs();
                warn!(seconds, "A request ran out of time");
                ApiError::request_timeout(format!(
                    "the request didn't finish within {seconds} seconds"
                ))
                .into_response()
            }
        }
    }
}

/// A request head, or an HTTP/2 header list, larger than this gets `431`.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// How long an HTTP/1.1 connection that's ready for a request has to send
/// the request's headers before it's closed. It applies between keep-alive
/// requests too, so idle connections close after it.
pub const HEADER_READ_TIME: Duration = Duration::from_secs(10);

/// hyper's settings for client connections. hyper already refuses more than
/// 100 HTTP/1.1 header fields with `431`, and setting that limit explicitly
/// would cost a heap allocation per request. TLS handshakes get the TLS
/// acceptor's own limit, 10 seconds.
pub fn http_settings(builder: &mut auto::Builder<TokioExecutor>) {
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIME)
        .max_buf_size(MAX_HEADER_BYTES);
    builder
        .http2()
        .max_header_list_size(MAX_HEADER_BYTES as u32);
}

/// How many connections one worker serves at once.
pub const MAX_CONNECTIONS: usize = 1024;

/// An acceptor that serves at most `limit` connections at once. Past it, a
/// new connection is closed as it arrives, before any TLS handshake.
#[derive(Clone)]
pub struct ConnectionLimit<A> {
    inner: A,
    limit: usize,
    open: Arc<AtomicUsize>,
    /// When a refusal was last logged: seconds since `started`, plus one.
    logged: Arc<AtomicU64>,
    started: Instant,
}

impl<A> ConnectionLimit<A> {
    pub fn new(inner: A, limit: usize) -> Self {
        Self {
            inner,
            limit,
            open: Arc::default(),
            logged: Arc::default(),
            started: Instant::now(),
        }
    }

    /// Log refusals at most once a minute, so that a flood of connections
    /// isn't also a flood of log lines.
    fn log_refusal(&self) {
        let now = self.started.elapsed().as_secs() + 1;
        let last = self.logged.load(Ordering::Relaxed);
        if (last == 0 || now >= last + 60)
            && self
                .logged
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            warn!(
                limit = self.limit,
                "Refusing connections: the worker is at its connection limit"
            );
        }
    }
}

impl<A, I, S> Accept<I, S> for ConnectionLimit<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = Held<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let Some(slot) = Slot::take(&self.open, self.limit) else {
            self.log_refusal();
            return Box::pin(std::future::ready(Err(io::Error::other(
                "the worker is at its connection limit",
            ))));
        };
        let accepted = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = accepted.await?;
            Ok((
                Held {
                    stream,
                    _slot: slot,
                },
                service,
            ))
        })
    }
}

/// One open connection's place in the count, given back when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(open: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        open.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < limit).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(open.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A connection's stream, which keeps its place in the count while open.
pub struct Held<T> {
    stream: T,
    _slot: Slot,
}

impl<T: AsyncRead + Unpin> AsyncRead for Held<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Held<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum_server::accept::DefaultAcceptor;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
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

    async fn error_body(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn requests_send_a_mebibyte_and_uploads_fifty() {
        let length = || post(|body: Bytes| async move { body.len().to_string() });
        let app = REQUESTS
            .apply(Router::new().route("/", length()))
            .merge(UPLOADS.apply(Router::new().route("/upload", length())))
            .layer(axum::middleware::from_fn(
                crate::request_id::request_context,
            ));
        let send = |path: &str, length: usize| {
            let request = Request::post(path).body(Body::from(vec![0; length]));
            app.clone().oneshot(request.unwrap())
        };

        let at_the_limit = send("/", REQUESTS.body).await.unwrap();
        assert_eq!(at_the_limit.status(), StatusCode::OK);
        let over = send("/", REQUESTS.body + 1).await.unwrap();
        assert_eq!(over.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error_body(over).await["code"], "payload_too_large");

        let upload = send("/upload", REQUESTS.body + 1).await.unwrap();
        assert_eq!(upload.status(), StatusCode::OK);
        let over = send("/upload", UPLOADS.body + 1).await.unwrap();
        assert_eq!(over.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test(start_paused = true)]
    async fn requests_have_a_minute_and_uploads_five() {
        let sleeping = |seconds: u64| {
            get(move || async move {
                tokio::time::sleep(Duration::from_secs(seconds)).await;
                "done"
            })
        };
        let app = REQUESTS
            .apply(
                Router::new()
                    .route("/59", sleeping(59))
                    .route("/61", sleeping(61)),
            )
            .merge(UPLOADS.apply(Router::new().route("/299", sleeping(299))))
            .layer(axum::middleware::from_fn(
                crate::request_id::request_context,
            ));
        let call = |path: &str| {
            app.clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
        };

        assert_eq!(call("/59").await.unwrap().status(), StatusCode::OK);
        assert_eq!(call("/299").await.unwrap().status(), StatusCode::OK);
        let late = call("/61").await.unwrap();
        assert_eq!(late.status(), StatusCode::REQUEST_TIMEOUT);
        let body = error_body(late).await;
        assert_eq!(body["code"], "request_timeout");
        assert!(body["request_id"].is_string());
    }

    /// The client's end of one in-memory connection, served with the
    /// worker's HTTP settings: `GET /` answers `ok`.
    fn connection() -> DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut builder = auto::Builder::new(TokioExecutor::new());
        http_settings(&mut builder);
        let app = Router::new().route("/", get(|| async { "ok" }));
        tokio::spawn(async move {
            let _ = builder
                .serve_connection(TokioIo::new(server), TowerToHyperService::new(app))
                .await;
        });
        client
    }

    /// Send `request` on a new connection, and read until the server
    /// closes it.
    async fn exchange(request: &[u8]) -> String {
        let mut client = connection();
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// `GET /` with `host`, `connection: close`, and `extra` more fields
    /// with `size`-byte values.
    fn request(extra: usize, size: usize) -> Vec<u8> {
        let mut head = String::from("GET / HTTP/1.1\r\nhost: worker\r\nconnection: close\r\n");
        for i in 0..extra {
            head.push_str(&format!("x-{i}: {}\r\n", "a".repeat(size)));
        }
        head.push_str("\r\n");
        head.into_bytes()
    }

    #[tokio::test]
    async fn heads_over_16_kib_or_100_fields_get_431() {
        let served = exchange(&request(98, 100)).await;
        assert!(served.starts_with("HTTP/1.1 200"), "{served}");
        for (extra, size) in [(99, 1), (1, MAX_HEADER_BYTES)] {
            let refused = exchange(&request(extra, size)).await;
            assert!(
                refused.starts_with("HTTP/1.1 431"),
                "{extra} more fields of {size} bytes: {refused}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn headers_have_ten_seconds_to_arrive_even_between_requests() {
        let closes_after_the_header_time = |since: tokio::time::Instant| {
            let waited = since.elapsed();
            assert!(
                waited >= HEADER_READ_TIME && waited < HEADER_READ_TIME + Duration::from_secs(1),
                "{waited:?}"
            );
        };

        let mut client = connection();
        let start = tokio::time::Instant::now();
        client
            .write_all(b"GET / HTTP/1.1\r\nhost: worker\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty(), "closed without a response");
        closes_after_the_header_time(start);

        let mut client = connection();
        client
            .write_all(b"GET / HTTP/1.1\r\nhost: worker\r\n\r\n")
            .await
            .unwrap();
        let mut served = Vec::new();
        while !served.ends_with(b"ok") {
            let mut chunk = [0; 1024];
            let n = client.read(&mut chunk).await.unwrap();
            assert!(n > 0, "closed before the response");
            served.extend_from_slice(&chunk[..n]);
        }
        let idle = tokio::time::Instant::now();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        closes_after_the_header_time(idle);
    }

    #[tokio::test]
    async fn connections_past_the_limit_are_refused_until_one_closes() {
        let limit = ConnectionLimit::new(DefaultAcceptor::new(), 2);
        let open = || limit.accept(tokio::io::duplex(64).0, ());
        let first = open().await.expect("a first connection");
        let _second = open().await.expect("a second");
        assert!(open().await.is_err(), "a third at once is refused");
        drop(first);
        assert!(open().await.is_ok(), "a place came free");
    }
}
