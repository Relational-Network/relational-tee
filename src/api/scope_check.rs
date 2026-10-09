// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! What a grant's targets would give an analyst in one pool, before the
//! grant is made or changed:
//!
//! - `POST /v1/drt/pools/{pool_pda}/analyses/{analysis_id}/scope-check`
//!
//! It lists each scope key's values in the pool's data with their rows, so
//! targets are picked from the data rather than typed, and counts the rows
//! a draft's targets give together, each row once. A target no row holds
//! is flagged with the data's nearest spellings. It decides rows with the
//! same code that builds analysts' tables, so what it counts is what an
//! analyst with those targets gets.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::analysis::definition::Definition;
use crate::analysis::table::{check_targets, Combination, Scope, ScopeCounts, Target};
use crate::api::pools::load_pool;
use crate::auth::{Caller, Permission};
use crate::error::ApiError;
use crate::state::AppState;

/// The most values listed for one key.
const MAX_VALUES: usize = 1000;

/// The most near spellings suggested for one target.
const MAX_NEAR: usize = 3;

/// A draft of a grant's targets.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeCheckRequest {
    /// The targets to count; none lists only the values.
    #[serde(default)]
    pub scope: Vec<Target>,
}

/// A value of a scope key and the rows that hold it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ValueRows {
    pub value: String,
    pub rows: u64,
}

/// A scope key, the CSV header of the column it restricts, and its values
/// in the pool's data, empty cells left out, at most 1,000.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeKeyValues {
    pub key: String,
    pub header: String,
    pub values: Vec<ValueRows>,
}

/// A target that is probably a mistake.
#[derive(Debug, Serialize, ToSchema)]
pub struct TargetWarning {
    /// `no_rows`: no row of the pool holds the target's value.
    pub code: String,
    pub key: String,
    pub value: String,
    /// The pool's values nearest to it: the same but for case, or else the
    /// fewest edits away, at most two.
    pub near: Vec<String>,
}

/// What a draft's targets give in a pool.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeCheckResponse {
    /// Every row of the pool's current data.
    pub total_rows: u64,
    /// The rows the targets give together, each row once.
    pub rows: u64,
    /// Each target's rows, in the order sent.
    pub target_rows: Vec<u64>,
    pub keys: Vec<ScopeKeyValues>,
    pub warnings: Vec<TargetWarning>,
}

/// The CSV header of the column scope key `key` restricts.
fn header(def: &Definition, key: &str) -> String {
    def.scope
        .get(key)
        .and_then(|column| def.column(column))
        .map_or_else(|| key.to_string(), |c| c.header.clone())
}

/// Every value of `key` in `counts`, however many there are.
fn held<'a>(counts: &'a ScopeCounts, key: &str) -> impl Iterator<Item = &'a str> {
    let index = counts.keys.iter().position(|k| k == key);
    counts
        .combinations
        .iter()
        .filter_map(move |c| index.and_then(|i| c.values[i].as_deref()))
}

/// The rows of `combinations`.
fn rows(combinations: &[&Combination]) -> u64 {
    combinations.iter().map(|c| c.rows).sum()
}

/// Each value of `key` and its rows, in value order.
fn values(counts: &ScopeCounts, key: &str) -> Vec<ValueRows> {
    let index = counts.keys.iter().position(|k| k == key);
    let mut by_value: BTreeMap<&str, u64> = BTreeMap::new();
    for c in &counts.combinations {
        if let Some(value) = index.and_then(|i| c.values[i].as_deref()) {
            *by_value.entry(value).or_default() += c.rows;
        }
    }
    by_value
        .into_iter()
        .take(MAX_VALUES)
        .map(|(value, rows)| ValueRows {
            value: value.into(),
            rows,
        })
        .collect()
}

/// The edit distance between `a` and `b`, if it's at most `max`.
fn edits(a: &[char], b: &[char], max: usize) -> Option<usize> {
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, x) in a.iter().enumerate() {
        let mut current = vec![i + 1; b.len() + 1];
        for (j, y) in b.iter().enumerate() {
            current[j + 1] = (previous[j] + usize::from(x != y))
                .min(previous[j + 1] + 1)
                .min(current[j] + 1);
        }
        if current.iter().all(|&d| d > max) {
            return None;
        }
        previous = current;
    }
    Some(previous[b.len()]).filter(|&d| d <= max)
}

/// The values of `held` nearest to `value`: the same but for case, or else
/// the fewest edits away, at most two.
fn near(value: &str, held: &BTreeSet<&str>) -> Vec<String> {
    let wanted: Vec<char> = value.to_lowercase().chars().collect();
    let mut found: Vec<(usize, &str)> = held
        .iter()
        .filter_map(|&candidate| {
            let other: Vec<char> = candidate.to_lowercase().chars().collect();
            if other.len().abs_diff(wanted.len()) > 2 {
                return None;
            }
            edits(&wanted, &other, 2).map(|d| (d, candidate))
        })
        .collect();
    found.sort_unstable();
    let nearest = found.first().map(|&(d, _)| d);
    found
        .into_iter()
        .take_while(|&(d, _)| Some(d) == nearest)
        .take(MAX_NEAR)
        .map(|(_, v)| v.to_string())
        .collect()
}

/// What `targets` give of `counts`.
pub fn check(def: &Definition, counts: &ScopeCounts, targets: &[Target]) -> ScopeCheckResponse {
    let unique: BTreeSet<Target> = targets.iter().cloned().collect();
    let target_rows: Vec<u64> = targets
        .iter()
        .map(|t| rows(&counts.split(&Scope::of(&BTreeSet::from([t.clone()]))).0))
        .collect();
    let warnings = targets
        .iter()
        .zip(&target_rows)
        .filter(|(_, &rows)| rows == 0)
        .map(|(t, _)| TargetWarning {
            code: "no_rows".into(),
            key: t.key.clone(),
            value: t.value.clone(),
            near: near(&t.value, &held(counts, &t.key).collect()),
        })
        .collect();
    ScopeCheckResponse {
        total_rows: counts.rows(),
        rows: if unique.is_empty() {
            0
        } else {
            rows(&counts.split(&Scope::of(&unique)).0)
        },
        target_rows,
        keys: def
            .scope
            .keys()
            .map(|key| ScopeKeyValues {
                key: key.clone(),
                header: header(def, key),
                values: values(counts, key),
            })
            .collect(),
        warnings,
    }
}

/// Count what a draft of a grant's targets gives in the pool.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/scope-check",
    tag = "Grants",
    summary = "Check a grant's targets",
    description = "Each scope key of the analysis with its values in the pool's data and their rows, and the rows the draft's targets would give an analyst together, each row once, with each target's rows. A target no row holds is flagged with the data's nearest spellings. With no targets, it lists only the values. Read-only and saves nothing, so it needs no Idempotency-Key. Needs `pools:read`.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
    ),
    request_body = ScopeCheckRequest,
    responses(
        (status = 200, description = "What the targets give", body = ScopeCheckResponse),
        (status = 400, description = "Targets the analysis can't apply (`invalid_scope`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Needs pools:read"),
        (status = 404, description = "Pool or analysis not found, or the pool has no data yet"),
        (status = 503, description = "The worker is busy with analyses; retry after Retry-After"),
    )
)]
pub async fn check_scope(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id)): Path<(String, String)>,
    Json(request): Json<ScopeCheckRequest>,
) -> Result<Json<ScopeCheckResponse>, ApiError> {
    caller.require(Permission::PoolsRead)?;
    let doc = load_pool(&state, &pool_pda).await?;
    let analysis = doc
        .analysis
        .clone()
        .filter(|a| a.analysis_id == analysis_id)
        .ok_or_else(|| ApiError::not_found(format!("this pool has no analysis {analysis_id:?}")))?;
    if doc.initial.is_none() {
        return Err(ApiError::not_found("this pool has no data yet"));
    }
    let def = state
        .analyses
        .definition(&state.storage, &analysis.code_hash_hex)
        .await?;
    if !request.scope.is_empty() {
        check_targets(&def, &request.scope)
            .map_err(|e| ApiError::bad_request(e).with_code("invalid_scope"))?;
    }
    let counts = state
        .analyses
        .scope_counts(&state.storage, &doc, &def)
        .await?;
    Ok(Json(check(&def, &counts, &request.scope)))
}
