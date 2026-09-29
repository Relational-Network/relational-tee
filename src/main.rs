// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! relational-tee: the IOB MicRes worker.
//!
//! An Axum server for Use Case 1 credential pools and custodial Solana
//! wallets, being migrated to Azure Confidential Containers. It provides:
//! - JWT validation using AVS-issued tokens
//! - Role-based access control (admin, user, read_only)
//! - Sealed CSV uploads decrypted inside the worker
//!
//! # Building & Running
//!
//! ```bash
//! just dev    # dev build: plain HTTP on 127.0.0.1:8443
//! ```

mod api;
mod attestation;
mod auth;
mod blockchain;
mod config;
mod crypto;
mod data_validation;
mod error;
mod handlers;
mod health;
mod http_client;
mod indexer;
mod request_id;
mod state;
mod storage;
mod tee;
mod tls;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderValue},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Instant;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{info, warn, Level};
use tracing_subscriber::EnvFilter;
use utoipa::{openapi::security::SecurityScheme, Modify, OpenApi};
#[cfg(feature = "swagger-ui")]
use utoipa_swagger_ui::SwaggerUi;

use config::{
    avs_jwks_url, KeyProviderConfig, ServerConfig, StorageConfig, Transport, AVS_AUDIENCE,
    MAX_BODY_SIZE,
};

use handlers::{admin_status, get_public_key, AdminStatusResponse};
use health::{
    health, liveness, readiness, CanaryDetails, Certificate, CertificateDetails, HealthDetails,
    HealthResponse, ReadinessResponse, RpcDetails,
};
use state::AppState;
use tee::{AttestationProvider, KeyName, KeyProvider, WorkerKeys};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Start time captured once for uptime reporting.
static STARTED_AT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

// ============================================================================
// OpenAPI Documentation
// ============================================================================

#[derive(OpenApi)]
#[openapi(
    info(
        title = "relational-tee API",
        version = "0.1.0",
        description = r#"IOB MicRes worker: Use Case 1 credential pools and custodial wallets, with JWT validation and RBAC.

## Authentication

Protected endpoints require a JWT issued by the Attestation Verification Service (AVS), until Entra ID replaces it.

### How to use in Swagger UI:

1. Click the **Authorize** button at the top right
2. Paste your JWT token (without "Bearer " prefix)
3. Click **Authorize**, then **Close**
4. Now you can test protected endpoints

### Roles:

- **admin**: Full access to all endpoints
- **user**: Can upload and query data
- **read_only**: Can only query data
"#
    ),
    paths(
        health::health,
        health::liveness,
        health::readiness,
        attestation::get_attestation,
        handlers::get_public_key,
        handlers::admin_status,
        // Wallet API
        api::users::get_me,
        api::wallets::create_wallet,
        api::wallets::list_wallets,
        api::wallets::get_wallet,
        api::wallets::delete_wallet,
        api::balance::get_balance,
        api::transactions::estimate_fee,
        api::transactions::send_transaction,
        api::transactions::list_transactions,
        api::transactions::get_transaction_status,
        api::admin::get_wallet_stats,
        api::admin::list_all_wallets,
        api::admin::query_audit_logs,
        api::admin::suspend_wallet,
        api::admin::activate_wallet,
        // DRT Pool API (new contract)
        api::pools::create_malta_pool,
        api::pools::get_pool,
        api::pools::get_drt,
        // Credential / Pool discovery API
        api::credentials::upload_schema,
        api::credentials::get_schema,
        api::credentials::initialize_pool,
        api::credentials::issue_credentials,
        api::credentials::revoke_credentials,
        api::credentials::list_revocations,
        api::credentials::pool_audit,
        api::credentials::pool_summary,
        api::credentials::get_issuance_log,
        api::credentials::list_pools_by_wallet,
        api::credentials::list_all_pools,
    ),
    components(schemas(
        HealthResponse,
        ReadinessResponse,
        HealthDetails,
        CertificateDetails,
        CanaryDetails,
        RpcDetails,
        AdminStatusResponse,
        error::ErrorBody,
        attestation::AttestationResponse,
        data_validation::ValidationError,
        data_validation::ValidationMode,
        crypto::Jwk,
        // Wallet schemas
        api::users::UserMeResponse,
        api::wallets::CreateWalletRequest,
        api::wallets::CreateWalletResponse,
        api::wallets::ListWalletsResponse,
        api::wallets::GetWalletResponse,
        api::wallets::DeleteWalletResponse,
        api::balance::BalanceResponse,
        api::transactions::EstimateFeeRequest,
        api::transactions::EstimateFeeResponse,
        api::transactions::SendTransactionRequest,
        api::transactions::SendTransactionResponse,
        api::transactions::TransactionEntry,
        api::transactions::ListTransactionsResponse,
        api::transactions::TransactionStatusResponse,
        api::admin::WalletStatsResponse,
        api::admin::AdminListWalletsResponse,
        api::admin::AdminWalletEntry,
        api::admin::AuditEventsResponse,
        api::admin::WalletStatusChangeResponse,
        // Shared domain types
        storage::wallets::WalletResponse,
        storage::transactions::StoredTransaction,
        storage::transactions::TokenType,
        storage::transactions::TxStatus,
        blockchain::types::TokenBalance,
        blockchain::types::SendResult,
        // DRT schemas (new contract)
        blockchain::drt::types::DrtRequest,
        blockchain::drt::types::SchemaFieldRequest,
        blockchain::drt::types::InlineSchemaRequest,
        blockchain::drt::types::CreateMaltaPoolRequest,
        blockchain::drt::types::CreatePoolResponse,
        blockchain::drt::types::DrtConfigResponse,
        blockchain::drt::types::PoolInfoResponse,
        // Credential schemas
        api::credentials::UploadSchemaRequest,
        api::credentials::UploadSchemaResponse,
        api::credentials::GetSchemaResponse,
        data_validation::FieldSchema,
        data_validation::FieldType,
        api::credentials::InitializePoolResponse,
        api::credentials::IssueCredentialsResponse,
        api::credentials::RevokeCredentialsRequest,
        api::credentials::RevokeCredentialsResponse,
        api::credentials::RevocationEntry,
        api::credentials::RevocationsResponse,
        api::credentials::PoolAuditResponse,
        api::credentials::PoolSummaryResponse,
        api::credentials::DrtConfigResponseCompact,
        api::credentials::PoolListEntry,
        api::credentials::PoolsByWalletResponse,
        api::credentials::MarketplaceDrtEntry,
        api::credentials::MarketplacePoolEntry,
        api::credentials::AllPoolsResponse,
        api::credentials::IssuanceRecord,
        api::credentials::IssuanceLogResponse,
        // Audit schemas
        storage::audit::AuditEvent,
        storage::audit::AuditEventView,
        storage::audit::AuditEventType,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Attestation", description = "Enclave attestation and public key"),
        (name = "Protected", description = "JWT-protected endpoints"),
        (name = "Admin", description = "Admin-only endpoints"),
        (name = "Users", description = "User identity endpoints"),
        (name = "Wallets", description = "Wallet CRUD endpoints"),
        (name = "Balance", description = "Balance query endpoints"),
        (name = "Transactions", description = "Transaction endpoints"),
        (name = "DRT Pools", description = "Data Rights Token pool endpoints"),
        (name = "Credentials", description = "Credential issuance, revocation, and pool discovery"),
    )
)]
struct ApiDoc;

/// Add bearer auth security scheme to OpenAPI.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(utoipa::openapi::security::Http::new(
                    utoipa::openapi::security::HttpAuthScheme::Bearer,
                )),
            );
        }
    }
}

#[cfg(not(feature = "swagger-ui"))]
async fn openapi_json() -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(ApiDoc::openapi())
}

// ============================================================================
// Application Entry Point
// ============================================================================

/// Dev-only commands: `relational-tee dev-keys [DIR]` creates any missing dev
/// key files, and `relational-tee fake-skr` runs the fake SKR sidecar.
/// Returns the exit code when the arguments name a command.
#[cfg(feature = "dev")]
async fn run_dev_command(args: &[String]) -> Option<i32> {
    let command = args.get(1)?;
    match command.as_str() {
        "fake-skr" => {
            let result = match tee::fake_skr::FakeSkrConfig::from_env() {
                Ok(config) => tee::fake_skr::serve(config).await,
                Err(e) => Err(e),
            };
            Some(match result {
                Ok(()) => 0,
                Err(e) => {
                    tracing::error!("{e}");
                    1
                }
            })
        }
        "dev-keys" => {
            let dir = std::path::PathBuf::from(
                args.get(2)
                    .map(String::as_str)
                    .unwrap_or(tee::dev_keys::DEFAULT_DIR),
            );
            match tee::dev_keys::generate_missing(&dir) {
                Ok(created) => {
                    for path in &created {
                        println!("created {}", path.display());
                    }
                    if created.is_empty() {
                        println!("dev keys in {} are complete", dir.display());
                    }
                    Some(0)
                }
                Err(e) => {
                    eprintln!("error: creating dev keys in {}: {e}", dir.display());
                    Some(1)
                }
            }
        }
        other => {
            eprintln!("error: unknown command {other:?} (dev commands: dev-keys, fake-skr)");
            Some(2)
        }
    }
}

/// Build the configured key and attestation providers; one implementation
/// serves both.
fn providers(config: &KeyProviderConfig) -> (Arc<dyn KeyProvider>, Arc<dyn AttestationProvider>) {
    match config {
        KeyProviderConfig::Skr(skr) => {
            info!(endpoint = %skr.endpoint, vault = %skr.akv_endpoint, maa = %skr.maa_endpoint,
                "Releasing keys and attesting through the SKR sidecar");
            let sidecar = Arc::new(tee::skr::SkrSidecar::new(skr.clone()));
            (sidecar.clone(), sidecar)
        }
        #[cfg(feature = "dev")]
        KeyProviderConfig::Local { dir } => {
            warn!(dir = %dir.display(), "KEY_PROVIDER=local: using dev keys (dev builds only)");
            let local = Arc::new(tee::local::LocalDev::new(dir.clone()));
            (local.clone(), local)
        }
    }
}

/// Open the configured stores. Azure storage gets any missing container or
/// table created.
async fn open_storage(
    config: &StorageConfig,
    keys: storage::StorageKeys,
    worker_id: String,
) -> Result<storage::Storage, String> {
    match config {
        StorageConfig::Azure(azure) => {
            let store = Arc::new(storage::azure::AzureStore::new(azure)?);
            store
                .ensure_layout()
                .await
                .map_err(|e| format!("preparing storage at {}: {e}", azure.blob_url))?;
            info!(blob = %azure.blob_url, table = %azure.table_url, "Storage ready");
            Ok(storage::Storage::new(store.clone(), store, keys, worker_id))
        }
        #[cfg(feature = "dev")]
        StorageConfig::Memory => {
            warn!("STORAGE_BACKEND=memory: state is lost when the worker stops (dev builds only)");
            Ok(storage::Storage::in_memory(keys, worker_id))
        }
    }
}

/// Service entrypoint: read configuration, build the router, and serve.
#[tokio::main]
async fn main() {
    // Initialize tracing with environment filter (RUST_LOG).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    #[cfg(feature = "dev")]
    if let Some(code) = run_dev_command(&std::env::args().collect::<Vec<_>>()).await {
        std::process::exit(code);
    }

    // Capture process start for uptime reporting.
    let _ = STARTED_AT.set(Instant::now());

    let server_config = ServerConfig::from_env().unwrap_or_else(|e| {
        tracing::error!("Invalid configuration: {e}");
        std::process::exit(2);
    });

    // Install rustls crypto provider early — both axum-server and our
    // http_client (hyper-rustls) pick this up via process-global default.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Release the four keys before anything else; without them the worker
    // can't serve. Exiting lets the platform restart it.
    let (key_provider, attestation_provider) = providers(&server_config.keys);
    let keys = WorkerKeys::release_all(key_provider.as_ref())
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "Key release failed");
            std::process::exit(1);
        });

    // Attest the transport key for clients, and keep the token fresh.
    let attestation = Arc::new(attestation::Attestation::new(
        &keys.get(KeyName::Transport).current,
    ));
    attestation.spawn_refresher(attestation_provider);

    // Encrypted Blob and Table storage, with keys derived from storage-root.
    let worker_id = uuid::Uuid::new_v4().to_string();
    info!(worker_id = %worker_id, "Worker identity for this process");
    let storage = open_storage(
        &server_config.storage,
        storage::StorageKeys::derive(&keys.get(KeyName::StorageRoot).current),
        worker_id,
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!("Storage unavailable: {e}");
        std::process::exit(1);
    });

    info!(jwks_url = %avs_jwks_url(), "JWT validation enabled");

    // Log DRT program ID at startup.
    info!(drt_program_id = %config::DRT_PROGRAM_ID_STR, "DRT program ID");

    // Warn if JWKS URL is plain HTTP pointing at a remote host (not loopback/localhost).
    // In production the AVS must be behind TLS; accepting plain HTTP leaks attestation tokens.
    {
        let url = avs_jwks_url();
        if url.starts_with("http://") {
            let is_local = config::is_loopback_http_url(&url);
            if !is_local {
                tracing::error!(
                    jwks_url = %url,
                    "JWKS URL uses plain HTTP for a remote host — \
                     attestation tokens will travel unencrypted. \
                     Set AVS_JWKS_URL to an https:// endpoint in production."
                );
            } else {
                tracing::warn!(
                    jwks_url = %url,
                    "JWKS URL is plain HTTP (loopback) — acceptable for local dev only"
                );
            }
        }
    }

    // Hard-block: refuse to start when non-local HTTP JWKS unless ALLOW_HTTP_JWKS is true.
    {
        let url = avs_jwks_url();
        if url.starts_with("http://") {
            let is_local = config::is_loopback_http_url(&url);
            if !is_local && !config::ALLOW_HTTP_JWKS {
                panic!(
                    "AVS_JWKS_URL is plain HTTP for a remote host: {url}. \
                     Set AVS_JWKS_URL to an https:// endpoint, or flip config::ALLOW_HTTP_JWKS \
                     and rebuild."
                );
            }
        }
    }

    // Initialize Solana client.
    let network_config = blockchain::types::network_config_from_env();
    info!(network = %network_config.name, rpc = %network_config.rpc_url, "Solana client initialized");
    if config::PUBLIC_SOLANA_RPC_URLS.contains(&network_config.rpc_url.as_str()) {
        warn!(
            rpc = %network_config.rpc_url,
            "Using a public Solana RPC endpoint: rate-limited with no SLA; switch to a paid provider before production"
        );
    }
    let solana_client =
        blockchain::SolanaClient::new(&network_config.rpc_url.clone(), network_config);

    // Initialize transaction cache.
    let tx_cache = Arc::new(storage::tx_cache::TxCache::new(
        config::TX_CACHE_CAPACITY,
        std::time::Duration::from_secs(config::TX_CACHE_TTL_SECS),
    ));

    // What readiness reports, kept current in the background.
    let certificate = match &server_config.transport {
        Transport::Tls { cert_path, .. } => Certificate::File {
            not_after: std::fs::read(cert_path)
                .ok()
                .and_then(|pem| tls::leaf_not_after(&pem)),
        },
        #[cfg(feature = "dev")]
        Transport::PlainHttp => Certificate::PlainHttp,
    };
    let health = Arc::new(health::Health::new(&keys, certificate));

    // Create shared application state.
    let state = AppState {
        keys: Arc::new(keys),
        attestation,
        health,
        audience: AVS_AUDIENCE.to_string(),
        jwks_cache: Arc::new(tokio::sync::RwLock::new(None)),
        storage: Arc::new(storage),
        solana_client: Arc::new(solana_client),
        tx_cache,
    };

    // Spawn background transaction indexer only when explicitly enabled.
    let indexer_enabled = config::INDEXER_ENABLED;
    let indexer_interval_secs = config::INDEXER_POLL_INTERVAL_SECS;
    if indexer_enabled {
        indexer::poller::spawn_indexer(
            state.solana_client.clone(),
            state.storage.clone(),
            state.tx_cache.clone(),
            std::time::Duration::from_secs(indexer_interval_secs),
        );
    } else {
        info!("Transaction indexer disabled; using on-demand API sync");
    }

    state.health.spawn_canary(state.storage.clone());
    state.health.spawn_rpc_check(state.solana_client.clone());
    let health = state.health.clone();
    let app = router(state);

    let addr = server_config.addr;

    // Drain on SIGTERM or SIGINT, then finish in-flight requests.
    let handle = axum_server::Handle::new();
    health::spawn_drain(health, handle.clone());

    match server_config.transport {
        Transport::Tls {
            cert_path,
            key_path,
        } => {
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "failed to load TLS certificate {} and key {}: {e}",
                            cert_path.display(),
                            key_path.display()
                        )
                    });
            info!(%addr, cert = %cert_path.display(), "Serving HTTPS");
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .expect("server error");
        }
        #[cfg(feature = "dev")]
        Transport::PlainHttp => {
            if addr.ip().is_loopback() {
                warn!(%addr, "Serving plain HTTP (dev build)");
            } else {
                warn!(%addr, "Serving plain HTTP on a non-loopback address (dev build)");
            }
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .expect("server error");
        }
    }
}

/// Every route, with the middleware every response passes through. The
/// request context is outermost, so every response, the fallback's
/// included, carries `X-Request-Id` and the error body.
fn router(state: AppState) -> Router {
    let app = Router::new()
        // Health endpoints (unversioned for k8s probes).
        .route("/health", get(health))
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        // v1 API endpoints.
        .route("/v1/attestation", get(attestation::get_attestation))
        .route("/v1/attestation/public-key", get(get_public_key))
        .route("/v1/admin/status", get(admin_status))
        // Wallet service routes.
        .merge(api::wallet_router())
        // DRT pool routes.
        .merge(api::drt_router())
        .fallback(request_id::not_found)
        .with_state(state);

    // SwaggerUi serves the OpenAPI document itself.
    #[cfg(feature = "swagger-ui")]
    let app = app.merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()));
    #[cfg(not(feature = "swagger-ui"))]
    let app = app.route("/api-doc/openapi.json", get(openapi_json));

    // Body limit: 50MB max for upload endpoints, prevents unbounded memory usage.
    app.layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<axum::body::Body>| {
                    let id = request
                        .extensions()
                        .get::<request_id::RequestId>()
                        .map(|id| id.0.as_str())
                        .unwrap_or("-");
                    tracing::info_span!("request", method = %request.method(),
                        path = %request.uri().path(), request_id = %id)
                })
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(axum::middleware::from_fn(request_id::request_context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get(app: &Router, path: &str) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    #[tokio::test]
    async fn readiness_follows_the_canary_and_the_drain_not_the_rpc() {
        let state = AppState::for_tests();
        let health = state.health.clone();
        let storage = state.storage.clone();
        let app = router(state);

        assert_eq!(get(&app, "/health/live").await.0, StatusCode::OK);
        let (status, body) = get(&app, "/health/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["storage_canary"], false);

        // The Solana RPC here is unreachable; readiness doesn't care.
        health.record_canary(storage.canary().await.map_err(|e| e.to_string()));
        let (status, body) = get(&app, "/health/ready").await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, details) = get(&app, "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(details["status"], "ready");
        assert_eq!(details["keys_held"].as_array().unwrap().len(), 4);
        assert_eq!(details["worker_id"], "worker-a");

        health.start_draining();
        assert_eq!(
            get(&app, "/health/ready").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(get(&app, "/health").await.1["status"], "draining");
    }

    #[tokio::test]
    async fn public_endpoints_answer_and_protected_ones_use_the_error_body() {
        let app = router(AppState::for_tests());
        let (status, body) = get(&app, "/v1/attestation").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "no token yet");
        assert_eq!(body["code"], "attestation_unavailable");

        let (status, body) = get(&app, "/v1/attestation/public-key").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["crv"], "P-256");

        let (status, body) = get(&app, "/v1/wallets").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "unauthorized");
        assert!(uuid::Uuid::parse_str(body["request_id"].as_str().unwrap()).is_ok());
    }
}
