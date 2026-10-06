// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! relational-tee: a confidential worker.
//!
//! An Axum server for credential pools, their analyses and custodial Solana
//! wallets, being migrated to Azure Confidential Containers. It provides:
//! - Entra ID access token validation, and permissions from app roles
//! - Sealed CSV uploads decrypted inside the worker
//!
//! # Building & Running
//!
//! ```bash
//! just dev    # dev build: plain HTTP on 127.0.0.1:8443
//! ```

mod analysis;
mod api;
mod attestation;
mod audit;
mod auth;
mod blockchain;
mod chain;
mod config;
mod data_validation;
mod edge;
mod error;
mod fault;
#[cfg(feature = "dev")]
mod faults;
mod handlers;
mod health;
mod history;
mod http_client;
mod idempotency;
mod ids;
mod logs;
mod reconciler;
mod reference_values;
mod request_id;
mod seal;
mod state;
mod storage;
mod store;
mod tee;
mod tls;

use axum::{
    http::{header, HeaderValue},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Instant;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultOnRequest, TraceLayer};
use tracing::{info, warn, Level};
use utoipa::{openapi::security::SecurityScheme, Modify, OpenApi};
#[cfg(feature = "swagger-ui")]
use utoipa_swagger_ui::SwaggerUi;

use config::{KeyProviderConfig, ServerConfig, StorageConfig, Transport};

use handlers::{admin_status, AdminStatusResponse};
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
        description = r#"A confidential worker for credential pools, their analyses and custodial wallets.

## Authentication

Protected endpoints need an Entra ID access token for this API, with the `access_as_user` scope, from an allowed client.

### How to use in Swagger UI:

1. Get a token, for example with `az account get-access-token --scope api://<API client ID>/access_as_user --query accessToken -o tsv`
2. Click **Authorize** at the top right and paste it (without "Bearer ")
3. Click **Authorize**, then **Close**

### Permissions:

The `Admin` app role grants `pools:read`, `pools:create`, `pools:write`, `wallets:read`, `users:read` and `analyses:run`, and is itself required for wallet creation, deletion and sends and for `/v1/admin/…`. The `Analyst` app role grants only `analyses:run`. A caller with no role can call only `/v1/users/me` and the pool list. `GET /v1/users/me` lists the caller's permissions.

An analysis shows admins every row. An analyst sees only the rows `/v1/admin/employer-scopes` maps their Entra security groups (the token's `groups` claim) to; an analyst with no mapped group, or a token whose groups overflowed, sees nothing.
"#
    ),
    paths(
        health::health,
        health::liveness,
        health::readiness,
        attestation::get_attestation,
        reference_values::get_reference_values,
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
        api::admin::get_analysis_log,
        api::employer_scopes::get_employer_scopes,
        api::employer_scopes::replace_employer_scopes,
        api::employer_scopes::check_employer_scopes,
        api::employer_scopes::list_scope_versions,
        api::employer_scopes::get_scope_version,
        // DRT Pool API (new contract)
        api::pools::create_malta_pool,
        api::pools::get_pool,
        api::pools::get_drt,
        // Credential / Pool discovery API
        api::credentials::schema::get_schema,
        api::credentials::initialize::initialize_pool,
        api::credentials::issue::issue_credentials,
        api::credentials::revoke::revoke_credentials,
        api::credentials::reads::list_revocations,
        api::credentials::reads::pool_summary,
        api::credentials::reads::get_issuance_log,
        api::credentials::reads::list_pools_by_wallet,
        api::credentials::reads::list_all_pools,
        // Analyst grants
        api::grants::grant_analysis,
        api::grants::revoke_grant,
        api::grants::list_grants,
        api::grants::my_analyses,
        // Analyses
        api::analyses::get_analysis,
        api::analyses::get_options,
        api::analyses::filtered_options,
        api::analyses::search_values,
        api::analyses::filtered_search,
        api::analyses::run_query,
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
        api::admin::AnalysisLogResponse,
        api::employer_scopes::ReplaceEmployerScopesRequest,
        api::employer_scopes::CheckEmployerScopesRequest,
        api::employer_scopes::CheckEmployerScopesResponse,
        api::employer_scopes::PoolScopes,
        api::employer_scopes::ScopeKey,
        api::employer_scopes::ValueRows,
        api::employer_scopes::EntryRows,
        api::employer_scopes::GroupRows,
        api::employer_scopes::Coverage,
        api::employer_scopes::Grants,
        api::employer_scopes::ScopeWarning,
        api::employer_scopes::Suggestion,
        api::employer_scopes::ScopeVersion,
        api::employer_scopes::ScopeVersionsResponse,
        storage::scopes::EmployerScope,
        storage::scopes::EmployerScopes,
        storage::analysis_log::AnalysisRecord,
        // Shared domain types
        storage::wallets::WalletResponse,
        history::WalletTransaction,
        history::TokenType,
        history::TxStatus,
        blockchain::types::TokenBalance,
        // DRT schemas (new contract)
        blockchain::drt::types::AnalysisRequest,
        blockchain::drt::types::CreateMaltaPoolRequest,
        blockchain::drt::types::CreatePoolResponse,
        blockchain::drt::types::DrtConfigResponse,
        blockchain::drt::types::PoolInfoResponse,
        // Credential schemas
        api::credentials::schema::GetSchemaResponse,
        storage::pools::AnalysisRef,
        data_validation::FieldSchema,
        data_validation::FieldType,
        seal::SealedUploadForm,
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
        // Grant schemas
        api::grants::GrantRequest,
        api::grants::GrantEntry,
        api::grants::GrantsResponse,
        api::grants::MyAnalysis,
        api::grants::MyAnalysesResponse,
        // Analysis schemas
        api::analyses::AnalysisSummary,
        api::analyses::ColumnSummary,
        api::analyses::FilterSummary,
        api::analyses::PageSize,
        api::analyses::ScopeSummary,
        api::analyses::ScopeCondition,
        api::analyses::OptionsResponse,
        api::analyses::OptionsRequest,
        api::analyses::SearchRequest,
        api::analyses::SearchResponse,
        analysis::query::QueryRequest,
        analysis::query::FilterRequest,
        analysis::query::Mode,
        analysis::query::SortRequest,
        analysis::query::PageRequest,
        analysis::query::Page,
        analysis::query::FilterOptions,
        analysis::query::OptionValue,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Attestation", description = "Attestation and reference values"),
        (name = "Protected", description = "JWT-protected endpoints"),
        (name = "Admin", description = "Admin-only endpoints"),
        (name = "Users", description = "User identity endpoints"),
        (name = "Wallets", description = "Wallet CRUD endpoints"),
        (name = "Balance", description = "Balance query endpoints"),
        (name = "Transactions", description = "Transaction endpoints"),
        (name = "DRT Pools", description = "Data Rights Token pool endpoints"),
        (name = "Credentials", description = "Credential issuance, revocation, and pool discovery"),
        (name = "Grants", description = "Analyst access to pools' analyses"),
        (name = "Analyses", description = "Running a pool's analysis over the caller's rows"),
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

/// The OpenAPI document, which `relational-tee openapi` prints for CI to
/// publish. Only builds with the `swagger-ui` feature serve it.
fn openapi_document() -> String {
    ApiDoc::openapi()
        .to_pretty_json()
        .expect("the OpenAPI document serializes")
}

// ============================================================================
// Application Entry Point
// ============================================================================

/// Dev-only commands: `relational-tee dev-keys [DIR]` creates any missing dev
/// key files, `relational-tee dev-token …` prints a token signed with the dev
/// token signing key, `relational-tee dev-manifest …` signs and stores a dev
/// reference-values manifest, `relational-tee fake-skr` runs the fake SKR
/// sidecar, and `relational-tee faults` runs the fault-injection suite.
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
        "dev-manifest" => Some(reference_values::dev::run(&args[2..]).await),
        "faults" => Some(faults::run(&args[2..]).await),
        other => {
            eprintln!(
                "error: unknown command {other:?} (dev commands: dev-keys, dev-token, \
                 dev-manifest, fake-skr, faults)"
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
    if std::env::args().nth(1).as_deref() == Some("openapi") {
        println!("{}", openapi_document());
        return;
    }

    let log_format =
        config::log_format_from_lookup(&|key| std::env::var(key).ok().filter(|v| !v.is_empty()))
            .unwrap_or_else(|e| {
                eprintln!("Invalid configuration: {e}");
                std::process::exit(2);
            });
    logs::init(log_format);

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

    #[cfg(feature = "dev")]
    if server_config.fault_injection {
        warn!(
            "FAULT_INJECTION=on: an X-Fault-Exit header makes this worker exit (dev builds only)"
        );
        fault::enable();
    }

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

    // The environment's signed manifest, served as it is. It also lists the
    // transport key versions besides the current one that uploads open with.
    let transport = Arc::new(seal::TransportKeys::new(
        keys.get(KeyName::Transport).current.clone(),
        key_provider.clone(),
    ));
    let reference_values = Arc::new(reference_values::ReferenceValues::new(
        public_stores.reference_values,
        &server_config.environment,
        transport.clone(),
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
    let commitments = Arc::new(blockchain::drt::pda::Commitments::derive(
        &keys.get(KeyName::Commitment).current,
    ));

    // Create shared application state.
    let state = AppState {
        transport,
        attestation,
        reference_values,
        health,
        auth: Arc::new(verifier),
        dashboard_origin: server_config.dashboard_origin.as_str().into(),
        limiter: Arc::new(edge::Limiter::new(&server_config.rate_limits)),
        storage: Arc::new(storage),
        solana_client: Arc::new(solana_client),
        commitments,
        history,
        fetcher: Arc::new(analysis::fetch::GitHub::new()),
        analyses: Arc::default(),
    };

    state.health.spawn_canary(state.storage.clone());
    state.health.spawn_rpc_check(state.solana_client.clone());
    reconciler::spawn(
        state.storage.clone(),
        state.solana_client.clone(),
        server_config.reconciler,
    );
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
            let mut server = axum_server::bind_rustls(addr, tls_config)
                .map(|tls| edge::ConnectionLimit::new(tls, edge::MAX_CONNECTIONS))
                .handle(handle);
            edge::http_settings(server.http_builder());
            server
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
            let mut server = axum_server::bind(addr)
                .map(|plain| edge::ConnectionLimit::new(plain, edge::MAX_CONNECTIONS))
                .handle(handle);
            edge::http_settings(server.http_builder());
            server
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .expect("server error");
        }
    }
}

/// Every route, with the middleware every response passes through. The
/// request context is outermost, so every response, the fallback's and
/// CORS preflights included, carries `X-Request-Id` and the error body;
/// CORS comes next, so rate-limited responses carry its headers too. The
/// upload routes may send more, for longer, than the rest.
fn router(state: AppState) -> Router {
    let cors = edge::cors(&state.dashboard_origin);
    let limiter = state.limiter.clone();
    let routes = Router::new()
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
        .route("/v1/admin/status", get(admin_status))
        // Wallet service routes.
        .merge(api::wallet_router())
        // DRT pool routes.
        .merge(api::drt_router());
    let app = edge::REQUESTS
        .apply(routes)
        .merge(edge::UPLOADS.apply(api::upload_router()))
        .fallback(request_id::not_found)
        .layer(axum::middleware::from_fn(audit::record))
        .layer(axum::middleware::from_fn(logs::name_route));
    #[cfg(feature = "dev")]
    let app = app.layer(axum::middleware::from_fn(fault::middleware));
    let app = app.with_state(state);

    // Swagger UI and the OpenAPI document, in builds with the feature only.
    #[cfg(feature = "swagger-ui")]
    let app = app.merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()));

    let trace = TraceLayer::new_for_http()
        .make_span_with(logs::request_span)
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(logs::finished);
    app.layer(trace)
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
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "sealing uses /v1/attestation"
        );
        assert_eq!(body["code"], "not_found");

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
                "users:read",
                "analyses:run"
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

        // An analyst may run analyses, and nothing else.
        let analyst = token(&["Analyst"], "cy@example.com");
        let (_, cy) = get_as(&app, &analyst, "/v1/users/me").await;
        assert_eq!(cy["permissions"], serde_json::json!(["analyses:run"]));
        for path in ["/v1/users", "/v1/wallets", "/v1/admin/employer-scopes"] {
            assert_eq!(
                get_as(&app, &analyst, path).await.0,
                StatusCode::FORBIDDEN,
                "{path}"
            );
        }

        // Tokens that fail validation are 401.
        let mut expired = Spec::valid(&config());
        expired.expires_in = -3600;
        let (status, body) =
            get_as(&app, &expired.sign(entra_key()).unwrap(), "/v1/users/me").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid or expired token");
    }

    #[tokio::test]
    async fn admins_replace_the_employer_scopes_from_the_version_they_read() {
        use auth::entra::mint::Spec;
        use auth::entra::tests::{config, entra_key};
        use serde_json::json;

        let app = router(AppState::for_tests());
        let mut spec = Spec::valid(&config());
        spec.roles = vec!["Admin".into()];
        let admin = spec.sign(entra_key()).unwrap();
        let put = |key: String, body: serde_json::Value| {
            let request = Request::put("/v1/admin/employer-scopes")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header("idempotency-key", key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default(),
                )
            }
        };
        let new_key = || uuid::Uuid::new_v4().to_string();

        let (status, empty) = get_as(&app, &admin, "/v1/admin/employer-scopes").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(empty, json!({ "version": 0, "scopes": [] }));

        let scopes = json!([
            { "group_id": "g-a", "label": "GROUP_A_ANALYSTS", "employer_group": "Group A" },
            { "group_id": "g-network", "label": "NETWORK_ANALYSTS", "employer": "Bank A Network" },
        ]);
        let key = new_key();
        let (status, first) = put(key.clone(), json!({ "version": 0, "scopes": scopes })).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!((&first["version"], &first["scopes"]), (&json!(1), &scopes));

        // A retry replays, and the same edit under a new key converges.
        assert_eq!(
            put(key, json!({ "version": 0, "scopes": scopes })).await,
            (StatusCode::OK, first.clone())
        );
        let (status, again) = put(new_key(), json!({ "version": 0, "scopes": scopes })).await;
        assert_eq!((status, &again["version"]), (StatusCode::OK, &json!(1)));
        assert_eq!(
            get_as(&app, &admin, "/v1/admin/employer-scopes").await,
            (StatusCode::OK, first)
        );

        // A stale edit, an entry with no condition or one that names no
        // scope key, and an unknown field are refused.
        let (status, body) = put(new_key(), json!({ "version": 0, "scopes": [] })).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::CONFLICT, Some("version_conflict"))
        );
        for bad in [
            json!([{ "group_id": "g", "label": "G" }]),
            json!([{ "group_id": "g", "label": "G", "Employer Group": "Group A" }]),
        ] {
            let (status, _) = put(new_key(), json!({ "version": 1, "scopes": bad })).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }
        let (status, _) = put(
            new_key(),
            json!({ "version": 1, "scopes": [], "everyone": true }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // An entry's conditions apply together.
        let both = json!([{
            "group_id": "g", "label": "G", "employer_group": "Group A", "employer": "Bank A Network"
        }]);
        let (status, together) = put(new_key(), json!({ "version": 1, "scopes": both })).await;
        assert_eq!(status, StatusCode::OK, "{together}");
        assert_eq!(
            (&together["version"], &together["scopes"]),
            (&json!(2), &both)
        );

        let (status, cleared) = put(new_key(), json!({ "version": 2, "scopes": [] })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            (&cleared["version"], &cleared["scopes"]),
            (&json!(3), &json!([]))
        );
    }

    #[tokio::test]
    async fn the_openapi_document_names_every_route_and_each_is_served() {
        let doc: serde_json::Value = serde_json::from_str(&openapi_document()).unwrap();
        assert_eq!(
            doc["components"]["securitySchemes"]["bearer_auth"]["scheme"],
            "bearer"
        );
        let paths = doc["paths"].as_object().unwrap();
        let documented: std::collections::BTreeSet<&str> =
            paths.keys().map(String::as_str).collect();
        let served = std::collections::BTreeSet::from([
            "/health",
            "/health/live",
            "/health/ready",
            "/v1/attestation",
            "/v1/reference-values",
            "/v1/admin/status",
            "/v1/admin/analysis-log",
            "/v1/admin/employer-scopes",
            "/v1/admin/employer-scopes/check",
            "/v1/admin/employer-scopes/versions",
            "/v1/admin/employer-scopes/versions/{version}",
            "/v1/admin/wallet-stats",
            "/v1/admin/wallets",
            "/v1/admin/wallets/{wallet_id}/activate",
            "/v1/admin/wallets/{wallet_id}/suspend",
            "/v1/users",
            "/v1/users/me",
            "/v1/wallets",
            "/v1/wallets/{wallet_id}",
            "/v1/wallets/{wallet_id}/balance",
            "/v1/wallets/{wallet_id}/estimate",
            "/v1/wallets/{wallet_id}/send",
            "/v1/wallets/{wallet_id}/transactions",
            "/v1/wallets/{wallet_id}/transactions/{signature}",
            "/v1/drt/me/analyses",
            "/v1/drt/pools/by-wallet/{wallet_id}",
            "/v1/drt/pools/list",
            "/v1/drt/pools/malta",
            "/v1/drt/pools/{pool_pda}",
            "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}",
            "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/options",
            "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/options/{filter}",
            "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/query",
            "/v1/drt/pools/{pool_pda}/drt/{drt_name}",
            "/v1/drt/pools/{pool_pda}/grant",
            "/v1/drt/pools/{pool_pda}/grants",
            "/v1/drt/pools/{pool_pda}/initialize",
            "/v1/drt/pools/{pool_pda}/issuance-log",
            "/v1/drt/pools/{pool_pda}/issue",
            "/v1/drt/pools/{pool_pda}/revocations",
            "/v1/drt/pools/{pool_pda}/revoke",
            "/v1/drt/pools/{pool_pda}/revoke-grant",
            "/v1/drt/pools/{pool_pda}/schema",
            "/v1/drt/pools/{pool_pda}/summary",
        ]);
        assert_eq!(documented, served);

        // Without a token, protected operations get 401 and public ones
        // answer, but none is missing (404) or has another method (405).
        let app = router(AppState::for_tests());
        for (path, operations) in paths {
            let concrete = path.replace(['{', '}'], "");
            for method in operations.as_object().unwrap().keys() {
                let request = Request::builder()
                    .method(method.to_uppercase().as_str())
                    .uri(&concrete)
                    .body(Body::empty())
                    .unwrap();
                let status = app.clone().oneshot(request).await.unwrap().status();
                assert!(
                    status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path}: {status}"
                );
            }
        }
    }

    #[cfg(not(feature = "swagger-ui"))]
    #[tokio::test]
    async fn without_swagger_ui_the_openapi_document_is_not_served() {
        let app = router(AppState::for_tests());
        let (status, body) = get(&app, "/api-doc/openapi.json").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "not_found");
    }

    #[tokio::test]
    async fn only_the_upload_routes_take_bodies_over_a_mebibyte() {
        use auth::entra::mint::Spec;
        use auth::entra::tests::{config, entra_key};
        use seal::tests::{form, BOUNDARY};

        let app = router(AppState::for_tests());
        let mut spec = Spec::valid(&config());
        spec.roles = vec!["Admin".into()];
        let token = spec.sign(entra_key()).unwrap();
        let post = |path: &str, content_type: String, body: Vec<u8>| {
            let request = Request::post(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("idempotency-key", uuid::Uuid::new_v4().to_string())
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body))
                .unwrap();
            app.clone().oneshot(request)
        };
        let over = vec![b' '; edge::REQUESTS.body + 1];

        let json = post("/v1/wallets", "application/json".into(), over.clone())
            .await
            .unwrap();
        assert_eq!(json.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // An issuance reads it all, and refuses it for what it holds.
        let upload = form(&[
            ("v", &b"1"[..]),
            ("kid", &b"unknown"[..]),
            ("enc", &b"AAAA"[..]),
            ("ct", &over[..]),
        ]);
        let response = post(
            "/v1/drt/pools/P/issue",
            format!("multipart/form-data; boundary={BOUNDARY}"),
            upload,
        )
        .await
        .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "sealed_payload_invalid");
    }
}
