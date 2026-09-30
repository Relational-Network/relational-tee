// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! relational-tee: the IOB MicRes worker.
//!
//! An Axum server for Use Case 1 credential pools and custodial Solana
//! wallets, being migrated to Azure Confidential Containers. It provides:
//! - Entra ID access token validation, and permissions from app roles
//! - Sealed CSV uploads decrypted inside the worker
//!
//! # Building & Running
//!
//! ```bash
//! just dev    # dev build: plain HTTP on 127.0.0.1:8443
//! ```

mod api;
mod attestation;
mod audit;
mod auth;
mod blockchain;
mod chain;
mod config;
mod crypto;
mod data_validation;
mod edge;
mod error;
mod handlers;
mod health;
mod history;
mod http_client;
mod idempotency;
mod ids;
mod reconciler;
mod reference_values;
mod request_id;
mod state;
mod storage;
mod store;
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

use config::{KeyProviderConfig, ServerConfig, StorageConfig, Transport, MAX_BODY_SIZE};

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
        description = r#"IOB MicRes worker: Use Case 1 credential pools and custodial wallets.

## Authentication

Protected endpoints need an Entra ID access token for this API, with the `access_as_user` scope, from an allowed client.

### How to use in Swagger UI:

1. Get a token, for example with `az account get-access-token --scope api://<API client ID>/access_as_user --query accessToken -o tsv`
2. Click **Authorize** at the top right and paste it (without "Bearer ")
3. Click **Authorize**, then **Close**

### Permissions:

The `Admin` app role grants `pools:read`, `pools:create`, `pools:write`, `wallets:read` and `users:read`, and is itself required for wallet creation, deletion and sends and for `/v1/admin/…`. A caller with no role can call only `/v1/users/me` and the pool list. `GET /v1/users/me` lists the caller's permissions.
"#
    ),
    paths(
        health::health,
        health::liveness,
        health::readiness,
        attestation::get_attestation,
        reference_values::get_reference_values,
        handlers::get_public_key,
        handlers::admin_status,
        // Wallet API
        api::users::get_me,
        api::users::list_users,
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
        api::admin::suspend_wallet,
        api::admin::activate_wallet,
        // DRT Pool API (new contract)
        api::pools::create_malta_pool,
        api::pools::get_pool,
        api::pools::get_drt,
        // Credential / Pool discovery API
        api::credentials::schema::upload_schema,
        api::credentials::schema::get_schema,
        api::credentials::initialize::initialize_pool,
        api::credentials::issue::issue_credentials,
        api::credentials::revoke::revoke_credentials,
        api::credentials::reads::list_revocations,
        api::credentials::reads::pool_summary,
        api::credentials::reads::get_issuance_log,
        api::credentials::reads::list_pools_by_wallet,
        api::credentials::reads::list_all_pools,
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
        api::users::UsersResponse,
        api::users::UserEntry,
        api::users::UserLookupResponse,
        auth::Permission,
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
        api::transactions::ListTransactionsResponse,
        api::transactions::TransactionStatusResponse,
        api::admin::WalletStatsResponse,
        api::admin::AdminListWalletsResponse,
        api::admin::AdminWalletEntry,
        api::admin::WalletStatusChangeResponse,
        // Shared domain types
        storage::wallets::WalletResponse,
        history::WalletTransaction,
        history::TokenType,
        history::TxStatus,
        blockchain::types::TokenBalance,
        // DRT schemas (new contract)
        blockchain::drt::types::DrtRequest,
        blockchain::drt::types::SchemaFieldRequest,
        blockchain::drt::types::InlineSchemaRequest,
        blockchain::drt::types::CreateMaltaPoolRequest,
        blockchain::drt::types::CreatePoolResponse,
        blockchain::drt::types::DrtConfigResponse,
        blockchain::drt::types::PoolInfoResponse,
        // Credential schemas
        api::credentials::schema::UploadSchemaRequest,
        api::credentials::schema::UploadSchemaResponse,
        api::credentials::schema::GetSchemaResponse,
        data_validation::FieldSchema,
        data_validation::FieldType,
        api::credentials::initialize::InitializePoolResponse,
        api::credentials::issue::IssueCredentialsResponse,
        api::credentials::revoke::RevokeCredentialsRequest,
        api::credentials::revoke::RevokeCredentialsResponse,
        api::credentials::reads::RevocationEntry,
        api::credentials::reads::RevocationsResponse,
        api::credentials::reads::PoolSummaryResponse,
        api::credentials::reads::DrtConfigResponseCompact,
        api::credentials::reads::PoolListEntry,
        api::credentials::reads::PoolsByWalletResponse,
        api::credentials::reads::MarketplaceDrtEntry,
        api::credentials::reads::MarketplacePoolEntry,
        api::credentials::reads::AllPoolsResponse,
        api::credentials::reads::IssuanceRecord,
        api::credentials::reads::IssuanceLogResponse,
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
/// key files, `relational-tee dev-token …` prints a token signed with the dev
/// token signing key, and `relational-tee fake-skr` runs the fake SKR sidecar.
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
        "dev-token" => Some(auth::dev_token::run(&args[2..])),
        other => {
            eprintln!(
                "error: unknown command {other:?} (dev commands: dev-keys, dev-token, fake-skr)"
            );
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

/// The access token verifier: Entra ID's keys for the pinned tenant, and in
/// dev builds also the dev token signing key, if `just dev-keys` created it.
fn token_verifier(config: &ServerConfig) -> auth::entra::Verifier {
    let entra = &config.entra;
    info!(tenant = %entra.tenant_id, api = %entra.api_client_id,
        clients = ?entra.allowed_client_ids, "Validating Entra ID access tokens");
    let verifier = auth::entra::Verifier::for_entra(entra.clone());
    #[cfg(feature = "dev")]
    let verifier = match tee::dev_rsa::RsaSigner::load(&config.dev_token_key) {
        Ok(key) => {
            warn!(key = %config.dev_token_key.display(), kid = %key.kid,
                "Also trusting the dev token signing key (dev builds only)");
            verifier
                .trust_dev_key(key.kid.clone(), &key.n, &key.e)
                .unwrap_or_else(|e| {
                    tracing::error!("The dev token signing key is unusable: {e}");
                    std::process::exit(2);
                })
        }
        Err(e) => {
            info!("No dev token signing key, so only Entra ID tokens are accepted: {e}");
            verifier
        }
    };
    verifier
}

/// The public containers beside the sealed `state`.
struct PublicStores {
    tls: Arc<dyn store::ObjectStore>,
    reference_values: Arc<dyn store::ObjectStore>,
}

/// Open the sealed `state` container, and the public `tls` and
/// `reference-values` containers. On Azure, any missing container is
/// created first.
async fn open_storage(
    config: &StorageConfig,
    keys: storage::StorageKeys,
    worker_id: String,
) -> Result<(storage::Storage, PublicStores), String> {
    let (state, public): (Arc<dyn store::ObjectStore>, PublicStores) = match config {
        StorageConfig::Azure(azure) => {
            let state = store::azure::AzureBlob::new(azure, store::STATE)?;
            for name in store::CONTAINERS {
                state
                    .container(name)
                    .ensure_container()
                    .await
                    .map_err(|e| format!("preparing storage at {}: {e}", azure.blob_url))?;
            }
            info!(blob = %azure.blob_url, "Storage ready");
            let public = PublicStores {
                tls: Arc::new(state.container(store::TLS)),
                reference_values: Arc::new(state.container(store::REFERENCE_VALUES)),
            };
            (Arc::new(state), public)
        }
        #[cfg(feature = "dev")]
        StorageConfig::Files { dir } => {
            warn!(dir = %dir.display(), "STORAGE_BACKEND=files: sealed objects in local files (dev builds only)");
            let files = |name: &str| Arc::new(store::files::LocalFiles::new(dir.join(name)));
            let public = PublicStores {
                tls: files(store::TLS),
                reference_values: files(store::REFERENCE_VALUES),
            };
            (files(store::STATE), public)
        }
    };
    Ok((storage::Storage::new(state, keys, worker_id), public))
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

    // Sealed Blob storage, with keys derived from storage-root.
    let worker_id = uuid::Uuid::new_v4().to_string();
    info!(worker_id = %worker_id, "Worker identity for this process");
    let (storage, public_stores) = open_storage(
        &server_config.storage,
        storage::StorageKeys::derive(&keys.get(KeyName::StorageRoot).current),
        worker_id,
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!("Storage unavailable: {e}");
        std::process::exit(1);
    });

    // The environment's signed manifest, served as it is.
    let reference_values = Arc::new(reference_values::ReferenceValues::new(
        public_stores.reference_values,
        &server_config.environment,
        keys.get(KeyName::Transport).current.thumbprint(),
    ));
    reference_values.spawn();

    let verifier = token_verifier(&server_config);

    // Log DRT program ID at startup.
    info!(drt_program_id = %config::DRT_PROGRAM_ID_STR, "DRT program ID");

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

    let history = Arc::new(history::History::new(
        config::TX_CACHE_CAPACITY,
        std::time::Duration::from_secs(config::TX_CACHE_TTL_SECS),
        config::TX_DETAIL_CACHE_CAPACITY,
    ));

    // What readiness reports, kept current in the background.
    let certificate = match &server_config.transport {
        Transport::Https { hostname } => {
            let certificates = tls::Certificates::new(
                &keys.get(KeyName::Tls).current,
                hostname,
                public_stores.tls,
            )
            .unwrap_or_else(|e| {
                tracing::error!("TLS setup failed: {e}");
                std::process::exit(1);
            });
            info!(
                hostname,
                spki_sha256 = certificates.spki_sha256(),
                "Serving tls-key"
            );
            let certificates = Arc::new(certificates);
            certificates.spawn();
            Certificate::TlsKey(certificates)
        }
        #[cfg(feature = "dev")]
        Transport::PlainHttp => {
            drop(public_stores.tls);
            Certificate::PlainHttp
        }
    };
    let health = Arc::new(health::Health::new(&keys, certificate.clone()));

    // Create shared application state.
    let state = AppState {
        keys: Arc::new(keys),
        attestation,
        reference_values,
        health,
        auth: Arc::new(verifier),
        dashboard_origin: server_config.dashboard_origin.as_str().into(),
        limiter: Arc::new(edge::Limiter::new(&server_config.rate_limits)),
        storage: Arc::new(storage),
        solana_client: Arc::new(solana_client),
        history,
    };

    state.health.spawn_canary(state.storage.clone());
    state.health.spawn_rpc_check(state.solana_client.clone());
    reconciler::spawn(state.storage.clone(), state.solana_client.clone());
    state.limiter.spawn_cleanup();
    let health = state.health.clone();
    let app = router(state);

    let addr = server_config.addr;

    // Drain on SIGTERM or SIGINT, then finish in-flight requests.
    let handle = axum_server::Handle::new();
    health::spawn_drain(health, handle.clone());

    match certificate {
        Certificate::TlsKey(certificates) => {
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_config(certificates.server_config());
            info!(%addr, "Serving HTTPS");
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .expect("server error");
        }
        #[cfg(feature = "dev")]
        Certificate::PlainHttp => {
            if addr.ip().is_loopback() {
                warn!(%addr, "Serving plain HTTP (dev build)");
            } else {
                warn!(%addr, "Serving plain HTTP on a non-loopback address (dev build)");
            }
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .expect("server error");
        }
    }
}

/// Every route, with the middleware every response passes through. The
/// request context is outermost, so every response, the fallback's and
/// CORS preflights included, carries `X-Request-Id` and the error body;
/// CORS comes next, so rate-limited responses carry its headers too.
fn router(state: AppState) -> Router {
    let cors = edge::cors(&state.dashboard_origin);
    let limiter = state.limiter.clone();
    let app = Router::new()
        // Health endpoints (unversioned for k8s probes).
        .route("/health", get(health))
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        // v1 API endpoints.
        .route("/v1/attestation", get(attestation::get_attestation))
        .route(
            "/v1/reference-values",
            get(reference_values::get_reference_values),
        )
        .route("/v1/attestation/public-key", get(get_public_key))
        .route("/v1/admin/status", get(admin_status))
        // Wallet service routes.
        .merge(api::wallet_router())
        // DRT pool routes.
        .merge(api::drt_router())
        .fallback(request_id::not_found)
        .layer(axum::middleware::from_fn(audit::record))
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
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(axum::middleware::from_fn_with_state(
            limiter,
            edge::limit_ip,
        ))
        .layer(cors)
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
        let (status, body) = get(&app, "/v1/reference-values").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "no manifest yet");
        assert_eq!(body["code"], "reference_values_unavailable");

        let (status, body) = get(&app, "/v1/attestation/public-key").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["crv"], "P-256");

        let (status, body) = get(&app, "/v1/wallets").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "unauthorized");
        assert!(uuid::Uuid::parse_str(body["request_id"].as_str().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn every_response_carries_the_security_and_cors_headers() {
        let app = router(AppState::for_tests());
        for path in ["/health/live", "/v1/wallets", "/nowhere"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::ORIGIN, "http://localhost:5173")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let h = response.headers();
            for (name, value) in [
                (
                    "strict-transport-security",
                    "max-age=63072000; includeSubDomains",
                ),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
                ("referrer-policy", "strict-origin-when-cross-origin"),
                ("cache-control", "no-store"),
                ("access-control-allow-origin", "http://localhost:5173"),
            ] {
                assert_eq!(h[name], value, "{path}: {name}");
            }
            assert!(h.contains_key("x-request-id"), "{path}");
            assert!(!h.contains_key(header::SERVER), "{path}");
        }
    }

    async fn get_as(app: &Router, token: &str, path: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    #[tokio::test]
    async fn callers_get_what_their_roles_permit() {
        use auth::entra::mint::Spec;
        use auth::entra::tests::{config, entra_key};

        let app = router(AppState::for_tests());
        let token = |roles: &[&str], email: &str| {
            let mut spec = Spec::valid(&config());
            spec.roles = roles.iter().map(|r| r.to_string()).collect();
            spec.email = Some(email.into());
            spec.name = Some(email.split('@').next().unwrap().into());
            spec.sign(entra_key()).unwrap()
        };
        let admin = token(&["Admin"], "Ada@Example.com");
        let nobody = token(&[], "bo@example.com");

        // Before anyone signs in, nobody is found by email.
        let (status, _) = get_as(&app, &admin, "/v1/users?email=bo@example.com").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, me) = get_as(&app, &admin, "/v1/users/me").await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["roles"], serde_json::json!(["Admin"]));
        assert_eq!(
            me["permissions"],
            serde_json::json!([
                "pools:read",
                "pools:create",
                "pools:write",
                "wallets:read",
                "users:read"
            ])
        );
        assert_eq!(me["email"], "Ada@Example.com");
        assert_eq!(me["display_name"], "Ada");

        // A caller with no role sees only themselves and the pool list.
        let (status, them) = get_as(&app, &nobody, "/v1/users/me").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(them["permissions"], serde_json::json!([]));
        assert_eq!(
            get_as(&app, &nobody, "/v1/drt/pools/list").await.0,
            StatusCode::OK
        );
        for path in ["/v1/users", "/v1/wallets", "/v1/admin/wallets"] {
            let (status, body) = get_as(&app, &nobody, path).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(body["code"], "forbidden");
        }

        // Admins list and look up users once they've signed in.
        let (status, found) = get_as(&app, &admin, "/v1/users?email=BO@example.com").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(found["user_id"], them["user_id"]);
        let (status, page) = get_as(&app, &admin, "/v1/users?limit=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["users"][0]["email"], "Ada@Example.com");
        let cursor = page["next_cursor"].as_str().unwrap();
        let (_, next) = get_as(&app, &admin, &format!("/v1/users?limit=1&cursor={cursor}")).await;
        assert_eq!(next["users"][0]["user_id"], them["user_id"]);
        assert!(next.get("next_cursor").is_none());

        // Tokens that fail validation are 401.
        let mut expired = Spec::valid(&config());
        expired.expires_in = -3600;
        let (status, body) =
            get_as(&app, &expired.sign(entra_key()).unwrap(), "/v1/users/me").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid or expired token");
    }
}
