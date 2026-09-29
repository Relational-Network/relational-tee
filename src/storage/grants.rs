// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Local mirror of on-chain DRT grants.
//!
//! On-chain truth lives in Grant PDAs. This module maintains a redb-backed
//! index so the enclave can answer two questions in O(grants_for_key):
//!
//! - "Which analysts have which grants on pool X?" (admin view)
//! - "Which pools / DRTs am I granted on?"          (analyst view)
//!
//! Records are written from [`crate::api::admin::grant_right`] after the
//! on-chain `grant_right` instruction finalises, and mutated by
//! [`crate::api::admin::revoke_grant`] to flip `status` to `revoked`.
//! `GRANTS_BY_ANALYST` (the per-analyst index) deletes revoked entries so the
//! analyst's "my grants" view only contains active access.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Status of a grant in the local mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Active,
    Revoked,
}

/// Local record of an on-chain Grant PDA.
///
/// Identifiers stored as base58 / hex strings so the JSON payload is directly
/// usable by the dashboard without re-encoding.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GrantRecord {
    /// Pool PDA the grant applies to (base58).
    pub pool_pda: String,
    /// Analyst's stable identifier (Clerk `sub`, e.g. `user_...`).
    pub analyst_id: String,
    /// DRT name (e.g. `mean`).
    pub drt_name: String,
    /// Grant PDA address (base58).
    pub grant_pda: String,
    /// `sha256(analyst_id || pool_uuid || right_id)` (hex).
    pub commitment_hex: String,
    /// Wallet id of the admin that signed the grant tx.
    pub owner_wallet_id: String,
    /// Unix seconds when the grant was recorded locally.
    pub granted_at: i64,
    /// On-chain signature of the grant tx.
    pub granted_sig: String,
    /// Status of the grant.
    pub status: GrantStatus,
    /// Unix seconds when the grant was revoked, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    /// On-chain signature of the revoke tx, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_sig: Option<String>,
}
