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
mod state;
mod storage;
mod tee;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderValue},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Instant;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{info, warn, Level};
use tracing_subscriber::EnvFilter;
use utoipa::{openapi::security::SecurityScheme, Modify, OpenApi};
#[cfg(feature = "swagger-ui")]
use utoipa_swagger_ui::SwaggerUi;

use config::{
    avs_jwks_url, KeyProviderConfig, ServerConfig, Transport, AVS_AUDIENCE, MAX_BODY_SIZE,
};

use handlers::{admin_status, get_public_key, AdminStatusResponse};
use health::{health, liveness, readiness, HealthChecks, HealthResponse, ReadyResponse};
use state::AppState;
use tee::{KeyProvider, WorkerKeys};

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
        ReadyResponse,
        HealthChecks,
        AdminStatusResponse,
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
        storage::repository::wallets::WalletResponse,
        storage::repository::transactions::StoredTransaction,
        storage::repository::transactions::TokenType,
        storage::repository::transactions::TxStatus,
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
/// key files. Returns the exit code when the arguments name a command.
#[cfg(feature = "dev")]
fn run_dev_command(args: &[String]) -> Option<i32> {
    let command = args.get(1)?;
    match command.as_str() {
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
            eprintln!("error: unknown command {other:?} (dev commands: dev-keys)");
            Some(2)
        }
    }
}

/// Build the configured key provider.
fn key_provider(config: &KeyProviderConfig) -> Box<dyn KeyProvider> {
    match config {
        KeyProviderConfig::Skr(skr) => {
            info!(endpoint = %skr.endpoint, vault = %skr.akv_endpoint, maa = %skr.maa_endpoint,
                "Releasing keys through the SKR sidecar");
            Box::new(tee::skr::SkrSidecar::new(skr.clone()))
        }
        #[cfg(feature = "dev")]
        KeyProviderConfig::Local { dir } => {
            warn!(dir = %dir.display(), "KEY_PROVIDER=local: using dev keys (dev builds only)");
            Box::new(tee::local::LocalDev::new(dir.clone()))
        }
    }
}

/// Service entrypoint: read configuration, build the router, and serve.
#[tokio::main]
async fn main() {
    #[cfg(feature = "dev")]
    if let Some(code) = run_dev_command(&std::env::args().collect::<Vec<_>>()) {
        std::process::exit(code);
    }

    // Initialize tracing with environment filter (RUST_LOG).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

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
    let keys = WorkerKeys::release_all(key_provider(&server_config.keys).as_ref())
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "Key release failed");
            std::process::exit(1);
        });

    // Initialize local storage.
    let data_dir = server_config.data_dir.as_path();
    let mut encrypted_storage = storage::EncryptedStorage::new(data_dir);
    match encrypted_storage.initialize() {
        Ok(()) => warn!(
            data_dir = %data_dir.display(),
            "Local storage is plaintext on disk: synthetic data only until encrypted Azure Storage replaces it"
        ),
        Err(e) => {
            tracing::warn!(error = %e, data_dir = %data_dir.display(),
                "Failed to initialize local storage — wallet endpoints will be unavailable");
        }
    }

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

    // Initialize transaction database (redb). Required — fail fast if it cannot open.
    let tx_db = Arc::new(
        storage::tx_database::TxDatabase::open(&storage::StoragePaths::new(data_dir).tx_db_path())
            .expect("Failed to open transaction database — cannot start without DB"),
    );
    info!("Transaction database opened");

    // Initialize transaction cache.
    let tx_cache = Arc::new(storage::tx_cache::TxCache::new(
        config::TX_CACHE_CAPACITY,
        std::time::Duration::from_secs(config::TX_CACHE_TTL_SECS),
    ));

    // Create shared application state.
    let state = AppState {
        keys: Arc::new(keys),
        audience: AVS_AUDIENCE.to_string(),
        jwks_cache: Arc::new(tokio::sync::RwLock::new(None)),
        storage: Arc::new(encrypted_storage),
        solana_client: Arc::new(solana_client),
        tx_db,
        tx_cache,
        pool_locks: Arc::new(dashmap::DashMap::new()),
    };

    // Spawn background transaction indexer only when explicitly enabled.
    let indexer_enabled = config::INDEXER_ENABLED;
    let indexer_interval_secs = config::INDEXER_POLL_INTERVAL_SECS;
    if indexer_enabled {
        indexer::poller::spawn_indexer(
            state.solana_client.clone(),
            state.tx_db.clone(),
            state.tx_cache.clone(),
            std::time::Duration::from_secs(indexer_interval_secs),
        );
    } else {
        info!("Transaction indexer disabled; using on-demand API sync");
    }

    // Spawn background nonce purge task to prevent unbounded growth of the
    // replay-protection table.  Runs every NONCE_PURGE_INTERVAL_SECS.
    {
        let tx_db = state.tx_db.clone();
        let interval = std::time::Duration::from_secs(config::NONCE_PURGE_INTERVAL_SECS);
        let max_age = config::NONCE_MAX_AGE_SECS;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // first tick is immediate — skip it
            loop {
                ticker.tick().await;
                match tx_db.purge_expired_nonces(max_age) {
                    Ok(n) if n > 0 => info!(removed = n, "Purged expired nonces"),
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "Nonce purge failed"),
                }
            }
        });
        info!(
            interval_secs = config::NONCE_PURGE_INTERVAL_SECS,
            max_age_secs = config::NONCE_MAX_AGE_SECS,
            "Nonce purge background task started"
        );
    }

    // Build the router with all endpoints.
    // Body limit: 50MB max for upload endpoints, prevents unbounded memory usage.
    let app = Router::new()
        // Health endpoints (unversioned for k8s probes).
        .route("/health", get(health))
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        // v1 API endpoints.
        .route("/v1/attestation/public-key", get(get_public_key))
        .route("/v1/admin/status", get(admin_status))
        // Wallet service routes.
        .merge(api::wallet_router())
        // DRT pool routes.
        .merge(api::drt_router())
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
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
        .with_state(state);

    // SwaggerUi serves the OpenAPI document itself.
    #[cfg(feature = "swagger-ui")]
    let app = app.merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()));
    #[cfg(not(feature = "swagger-ui"))]
    let app = app.route("/api-doc/openapi.json", get(openapi_json));

    let addr = server_config.addr;

    // Graceful shutdown: drain in-flight requests on SIGTERM/SIGINT.
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        info!("Shutdown signal received, draining connections (10s)...");
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });

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

/// Wait for SIGINT (Ctrl-C) or SIGTERM for clean shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
