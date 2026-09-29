// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Admin endpoints for the wallet service.
//!
//! All endpoints require `AdminToken` (admin role).
//!
//! - `GET  /v1/admin/wallet-stats`              — aggregate stats
//! - `GET  /v1/admin/wallets`                   — list all wallets (any owner)
//! - `GET  /v1/admin/audit/events`              — query audit log
//! - `POST /v1/admin/wallets/{id}/suspend`      — suspend a wallet
//! - `POST /v1/admin/wallets/{id}/activate`     — reactivate a wallet

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::{IntoParams, ToSchema};

use crate::audit_log;
use crate::auth::AdminToken;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::audit::{AuditEvent, AuditEventType, AuditEventView};
use crate::storage::wallets::{WalletResponse, WalletStatus};

use super::{load_wallet, CursorQuery};

/// The cursor scope of the admin wallet list.
const WALLETS_SCOPE: &str = "wallets";

// ============================================================================
// Response types
// ============================================================================

/// Aggregate wallet statistics.
#[derive(Debug, Serialize, ToSchema)]
pub struct WalletStatsResponse {
    pub total_wallets: usize,
    pub active_wallets: usize,
    pub suspended_wallets: usize,
    pub deleted_wallets: usize,
}

/// One page of all wallets (admin view).
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminListWalletsResponse {
    pub wallets: Vec<AdminWalletEntry>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Extended wallet info visible to admins.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminWalletEntry {
    #[serde(flatten)]
    pub wallet: WalletResponse,
    /// Owner user ID (visible to admins).
    pub owner_user_id: String,
}

/// Audit event query params.
#[derive(Debug, Deserialize, IntoParams)]
pub struct AuditQuery {
    /// Date in `YYYY-MM-DD` format (default: today, UTC).
    pub date: Option<String>,
    /// Maximum number of events to return (default 50, max 200).
    #[serde(default = "super::default_page_limit")]
    pub limit: usize,
    /// `next_cursor` from the previous page.
    pub cursor: Option<String>,
}

/// One page of audit events, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventsResponse {
    pub events: Vec<AuditEventView>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Generic status response for suspend/activate.
#[derive(Debug, Serialize, ToSchema)]
pub struct WalletStatusChangeResponse {
    pub wallet_id: String,
    pub new_status: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Move a non-deleted wallet to `status` (compare-and-swap; already being
/// there counts as success).
async fn set_status(
    state: &AppState,
    wallet_id: &str,
    status: WalletStatus,
    action: &str,
) -> Result<(), ApiError> {
    let wallet = load_wallet(state, wallet_id).await?;
    if wallet.status == WalletStatus::Deleted {
        return Err(ApiError::bad_request(format!(
            "cannot {action} a deleted wallet"
        )));
    }
    state
        .storage
        .wallets()
        .set_status(wallet_id, status)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;
    Ok(())
}

/// Get aggregate wallet statistics.
#[utoipa::path(
    get,
    path = "/v1/admin/wallet-stats",
    tag = "Admin",
    summary = "Wallet statistics",
    description = "Returns aggregate counts of wallets by status. Admin only.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Stats", body = WalletStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn get_wallet_stats(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
) -> Result<Json<WalletStatsResponse>, ApiError> {
    let all = state.storage.wallets().all().await?;

    let active = all
        .iter()
        .filter(|w| w.status == WalletStatus::Active)
        .count();
    let suspended = all
        .iter()
        .filter(|w| w.status == WalletStatus::Suspended)
        .count();
    let deleted = all
        .iter()
        .filter(|w| w.status == WalletStatus::Deleted)
        .count();

    audit_log!(
        state,
        AuditEventType::AdminAccess,
        &token.sub,
        "system",
        "wallet-stats"
    );

    Ok(Json(WalletStatsResponse {
        total_wallets: all.len(),
        active_wallets: active,
        suspended_wallets: suspended,
        deleted_wallets: deleted,
    }))
}

/// List all wallets (all users, all statuses).
#[utoipa::path(
    get,
    path = "/v1/admin/wallets",
    tag = "Admin",
    summary = "List all wallets (admin)",
    description = "Returns all wallets across all users, one cursor page at a time. Admin only.",
    security(("bearer_auth" = [])),
    params(CursorQuery),
    responses(
        (status = 200, description = "All wallets", body = AdminListWalletsResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn list_all_wallets(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<AdminListWalletsResponse>, ApiError> {
    let page = state
        .storage
        .page_from(WALLETS_SCOPE, query.cursor.as_deref())?;
    let got = state
        .storage
        .wallets()
        .list(query.clamped_limit(), page)
        .await?;
    let entries: Vec<AdminWalletEntry> = got
        .items
        .into_iter()
        .map(|w| AdminWalletEntry {
            owner_user_id: w.owner_user_id.clone(),
            wallet: WalletResponse::from(w),
        })
        .collect();

    audit_log!(
        state,
        AuditEventType::AdminAccess,
        &token.sub,
        "system",
        "list-all-wallets"
    );

    Ok(Json(AdminListWalletsResponse {
        wallets: entries,
        next_cursor: got
            .next
            .map(|next| state.storage.sign_cursor(WALLETS_SCOPE, &next)),
    }))
}

/// Query audit log for a specific date.
#[utoipa::path(
    get,
    path = "/v1/admin/audit/events",
    tag = "Admin",
    summary = "Query audit log",
    description = "Returns audit events for a given date (default: today), newest first, one cursor page at a time. Every event is verified; `hmac_valid: false` marks one that failed. Admin only.",
    security(("bearer_auth" = [])),
    params(AuditQuery),
    responses(
        (status = 200, description = "Audit events", body = AuditEventsResponse),
        (status = 400, description = "Invalid date or cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn query_audit_logs(
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditEventsResponse>, ApiError> {
    let date = match query.date.as_deref() {
        Some(d) => chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
            .map_err(|_| ApiError::bad_request("date must be in YYYY-MM-DD format"))?,
        None => chrono::Utc::now().date_naive(),
    };

    let scope = format!("audit-day:{date}");
    let page = state.storage.page_from(&scope, query.cursor.as_deref())?;
    let got = state
        .storage
        .audit()
        .day_events(date, query.limit.clamp(1, 200), page)
        .await?;

    Ok(Json(AuditEventsResponse {
        events: got.items,
        next_cursor: got
            .next
            .map(|next| state.storage.sign_cursor(&scope, &next)),
    }))
}

/// Suspend a wallet (admin action).
#[utoipa::path(
    post,
    path = "/v1/admin/wallets/{wallet_id}/suspend",
    tag = "Admin",
    summary = "Suspend wallet",
    description = "Suspend a wallet, preventing the owner from transacting. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    responses(
        (status = 200, description = "Wallet suspended", body = WalletStatusChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn suspend_wallet(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<WalletStatusChangeResponse>, ApiError> {
    set_status(&state, &wallet_id, WalletStatus::Suspended, "suspend").await?;

    info!(
        wallet_id = %wallet_id,
        admin = %token.sub,
        "Wallet suspended by admin"
    );

    audit_log!(
        state,
        AuditEventType::AdminAccess,
        &token.sub,
        "wallet",
        &wallet_id
    );

    Ok(Json(WalletStatusChangeResponse {
        wallet_id,
        new_status: "suspended".to_string(),
    }))
}

/// Reactivate a suspended wallet (admin action).
#[utoipa::path(
    post,
    path = "/v1/admin/wallets/{wallet_id}/activate",
    tag = "Admin",
    summary = "Activate wallet",
    description = "Reactivate a suspended wallet. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    responses(
        (status = 200, description = "Wallet activated", body = WalletStatusChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn activate_wallet(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<WalletStatusChangeResponse>, ApiError> {
    set_status(&state, &wallet_id, WalletStatus::Active, "activate").await?;

    info!(
        wallet_id = %wallet_id,
        admin = %token.sub,
        "Wallet activated by admin"
    );

    audit_log!(
        state,
        AuditEventType::AdminAccess,
        &token.sub,
        "wallet",
        &wallet_id
    );

    Ok(Json(WalletStatusChangeResponse {
        wallet_id,
        new_status: "active".to_string(),
    }))
}

// ============================================================================
// Role change audit logging
// ============================================================================

/// Request body for logging a role change.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LogRoleChangeRequest {
    /// Clerk user ID of the target user.
    pub target_user_id: String,
    /// Previous role (before the change).
    pub old_role: String,
    /// New role (after the change).
    pub new_role: String,
}

/// Response for role change audit logging.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogRoleChangeResponse {
    pub logged: bool,
}

/// Log a role assignment change to the enclave audit trail.
///
/// Called by the dashboard after updating a user's role via Clerk API.
/// Emits a `RoleAssigned` audit event with structured details.
#[utoipa::path(
    post,
    path = "/v1/admin/log-role-change",
    tag = "Admin",
    summary = "Log role change",
    description = "Record a role assignment change in the enclave audit trail. Called after updating Clerk publicMetadata.",
    security(("bearer_auth" = [])),
    request_body = LogRoleChangeRequest,
    responses(
        (status = 200, description = "Event logged", body = LogRoleChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn log_role_change(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Json(payload): Json<LogRoleChangeRequest>,
) -> Json<LogRoleChangeResponse> {
    let audit_event = AuditEvent::new(AuditEventType::RoleAssigned)
        .with_user(&token.sub)
        .with_resource("user", &payload.target_user_id)
        .with_details(serde_json::json!({
            "target_user": payload.target_user_id,
            "old_role": payload.old_role,
            "new_role": payload.new_role,
            "assigned_by": token.sub
        }));
    state.storage.audit().log(audit_event).await;

    info!(
        admin = %token.sub,
        target = %payload.target_user_id,
        old_role = %payload.old_role,
        new_role = %payload.new_role,
        "Role assignment logged"
    );

    Json(LogRoleChangeResponse { logged: true })
}
