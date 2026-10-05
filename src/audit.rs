// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Operator audit events.
//!
//! Every mutation, failed mutation and admin read produces exactly one
//! structured event, logged with target `audit` when the request completes,
//! so Azure Monitor collects it from the container's output. An event carries
//! only these fields: `event`, `outcome`, `code` (on failure), `request_id`,
//! `user_id`, and where relevant `pool`, `record_id`, `wallet_id`, `rows` and
//! `signature`. Nothing else can be added to it, so it never carries CSV
//! content, emails, Entra object IDs, free-text reasons, keys or client IP
//! addresses.
//!
//! The output leaves the TEE through the host, so these events are operator
//! diagnostics. The record users rely on is the pool document and the chain.

use std::sync::{Arc, Mutex};

use axum::extract::{FromRequestParts, MatchedPath, RawPathParams, Request};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::{code_for_status, ErrorInfo};

/// The event an audited route emits.
fn event_for(method: &Method, route: &str) -> Option<&'static str> {
    Some(match (method.as_str(), route) {
        ("POST", "/v1/drt/pools/malta") => "pool_created",
        ("POST", "/v1/drt/pools/{pool_pda}/initialize") => "dataset_initialized",
        ("POST", "/v1/drt/pools/{pool_pda}/issue") => "credential_issued",
        ("POST", "/v1/drt/pools/{pool_pda}/revoke") => "credential_revoked",
        ("POST", "/v1/drt/pools/{pool_pda}/grant") => "grant_created",
        ("POST", "/v1/drt/pools/{pool_pda}/revoke-grant") => "grant_revoked",
        ("POST", "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/query") => "analysis_queried",
        ("GET", "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/options") => {
            "analysis_options_read"
        }
        ("GET", "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/options/{filter}") => {
            "analysis_values_searched"
        }
        ("POST", "/v1/wallets") => "wallet_created",
        ("DELETE", "/v1/wallets/{wallet_id}") => "wallet_deleted",
        ("POST", "/v1/wallets/{wallet_id}/send") => "transaction_sent",
        ("POST", "/v1/admin/wallets/{wallet_id}/suspend") => "wallet_suspended",
        ("POST", "/v1/admin/wallets/{wallet_id}/activate") => "wallet_activated",
        ("PUT", "/v1/admin/employer-scopes") => "employer_scopes_replaced",
        ("GET", "/v1/admin/employer-scopes") => "admin_employer_scopes_read",
        ("GET", "/v1/admin/analysis-log") => "admin_analysis_log_read",
        ("GET", "/v1/admin/status") => "admin_status_read",
        ("GET", "/v1/admin/wallet-stats") => "admin_wallet_stats_read",
        ("GET", "/v1/admin/wallets") => "admin_wallets_listed",
        ("GET", "/v1/users") => "admin_users_listed",
        _ => return None,
    })
}

/// What handlers and the auth extractor add to the request's event.
#[derive(Debug, Default)]
struct Fields {
    user_id: Option<String>,
    pool: Option<String>,
    record_id: Option<String>,
    wallet_id: Option<String>,
    rows: Option<u64>,
    signature: Option<String>,
}

tokio::task_local! {
    static FIELDS: Arc<Mutex<Fields>>;
}

fn set(f: impl FnOnce(&mut Fields)) {
    let _ = FIELDS.try_with(|fields| {
        if let Ok(mut fields) = fields.lock() {
            f(&mut fields);
        }
    });
}

/// The authenticated caller.
pub fn caller(user_id: &str) {
    set(|f| f.user_id = Some(user_id.to_string()));
}

/// The pool a request created.
pub fn pool(pool_pda: &str) {
    set(|f| f.pool = Some(pool_pda.to_string()));
}

/// The wallet a request created.
pub fn wallet(wallet_id: &str) {
    set(|f| f.wallet_id = Some(wallet_id.to_string()));
}

/// The upload a request stored, and its CSV rows.
pub fn upload(record_id: &str, rows: u64) {
    set(|f| {
        f.record_id = Some(record_id.to_string());
        f.rows = Some(rows);
    });
}

/// The rows an analysis query returned.
pub fn rows(rows: u64) {
    set(|f| f.rows = Some(rows));
}

/// The grant a request made or revoked, as its `record_id`.
pub fn grant(grant_id: &str) {
    set(|f| f.record_id = Some(grant_id.to_string()));
}

/// The transaction a request sent.
pub fn signature(signature: &str) {
    set(|f| f.signature = Some(signature.to_string()));
}

/// Middleware: emit the audit event of an audited route once it completes,
/// with the pool or wallet from the path and whatever the request added.
pub async fn record(request: Request, next: Next) -> Response {
    let event = request
        .extensions()
        .get::<MatchedPath>()
        .and_then(|route| event_for(request.method(), route.as_str()));
    let Some(event) = event else {
        return next.run(request).await;
    };

    let (mut parts, body) = request.into_parts();
    let mut fields = Fields::default();
    if let Ok(params) = RawPathParams::from_request_parts(&mut parts, &()).await {
        for (name, value) in &params {
            match name {
                "pool_pda" => fields.pool = Some(value.to_string()),
                "wallet_id" => fields.wallet_id = Some(value.to_string()),
                _ => {}
            }
        }
    }
    let fields = Arc::new(Mutex::new(fields));
    let response = FIELDS
        .scope(fields.clone(), next.run(Request::from_parts(parts, body)))
        .await;

    let status = response.status();
    let code = (!status.is_success()).then(|| {
        response
            .extensions()
            .get::<ErrorInfo>()
            .map_or_else(|| code_for_status(status), |info| info.code)
    });
    let f = fields
        .lock()
        .map(|mut f| std::mem::take(&mut *f))
        .unwrap_or_default();
    tracing::info!(
        target: "audit",
        event,
        outcome = if status.is_success() { "success" } else { "failure" },
        code,
        request_id = crate::request_id::current().as_deref(),
        user_id = f.user_id.as_deref(),
        pool = f.pool.as_deref(),
        record_id = f.record_id.as_deref(),
        wallet_id = f.wallet_id.as_deref(),
        rows = f.rows,
        signature = f.signature.as_deref(),
        "audit event"
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::Router;
    use std::collections::BTreeMap;
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt;

    type Captured = Arc<Mutex<Vec<BTreeMap<String, String>>>>;

    /// Collects the fields of every `audit` event.
    struct Capture(Captured);

    struct Visitor<'a>(&'a mut BTreeMap<String, String>);

    impl tracing::field::Visit for Visitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().into(), value.into());
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() == "audit" {
                let mut fields = BTreeMap::new();
                event.record(&mut Visitor(&mut fields));
                self.0.lock().unwrap().push(fields);
            }
        }
    }

    async fn issue() -> StatusCode {
        caller("user-1");
        upload("record-1", 3);
        signature("sig-1");
        StatusCode::OK
    }

    async fn suspend() -> crate::error::ApiError {
        caller("admin-1");
        crate::error::ApiError::conflict("the wallet changed; retry")
    }

    fn app() -> Router {
        Router::new()
            .route("/v1/drt/pools/{pool_pda}/issue", post(issue))
            .route("/v1/admin/wallets/{wallet_id}/suspend", post(suspend))
            .route("/v1/drt/pools/list", get(|| async { "not audited" }))
            .layer(axum::middleware::from_fn(record))
            .layer(axum::middleware::from_fn(
                crate::request_id::request_context,
            ))
    }

    async fn call(method: &str, uri: &str) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        app().oneshot(request).await.unwrap();
    }

    #[tokio::test]
    async fn one_event_per_audited_request_with_only_allowlisted_fields() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry().with(Capture(captured.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        call("POST", "/v1/drt/pools/Pool1/issue").await;
        call("POST", "/v1/admin/wallets/w-9/suspend").await;
        call("GET", "/v1/drt/pools/list").await;

        let events = captured.lock().unwrap().clone();
        assert_eq!(events.len(), 2, "the pool list isn't audited: {events:?}");
        let allowed = [
            "message",
            "event",
            "outcome",
            "code",
            "request_id",
            "user_id",
            "pool",
            "record_id",
            "wallet_id",
            "rows",
            "signature",
        ];
        for event in &events {
            assert!(
                event.keys().all(|k| allowed.contains(&k.as_str())),
                "{event:?}"
            );
            assert!(uuid::Uuid::parse_str(&event["request_id"]).is_ok());
        }

        let issued = &events[0];
        assert_eq!(issued["event"], "credential_issued");
        assert_eq!(issued["outcome"], "success");
        assert!(!issued.contains_key("code"));
        assert_eq!(
            (issued["user_id"].as_str(), issued["pool"].as_str()),
            ("user-1", "Pool1")
        );
        assert_eq!(
            (issued["record_id"].as_str(), issued["rows"].as_str()),
            ("record-1", "3")
        );
        assert_eq!(issued["signature"], "sig-1");

        let suspended = &events[1];
        assert_eq!(suspended["event"], "wallet_suspended");
        assert_eq!(
            (suspended["outcome"].as_str(), suspended["code"].as_str()),
            ("failure", "conflict")
        );
        assert_eq!(suspended["wallet_id"], "w-9");
        assert!(!suspended.contains_key("record_id"));
    }
}
