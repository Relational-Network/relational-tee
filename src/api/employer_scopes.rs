// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The employer-scope mapping, its versions, and what a change to it would
//! do. Admin only.
//!
//! - `GET  /v1/admin/employer-scopes`                    — the mapping
//! - `PUT  /v1/admin/employer-scopes`                    — replace it
//! - `POST /v1/admin/employer-scopes/check`              — a draft's dry run
//! - `GET  /v1/admin/employer-scopes/versions`           — every version, newest first
//! - `GET  /v1/admin/employer-scopes/versions/{version}` — one version
//!
//! The dry run decides a draft's entries on each pool's counts of scope
//! values, with the code that decides which rows go into an analyst's
//! table, so the rows it reports are the rows analysts would get.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;

use super::{page, CursorQuery};
use crate::analysis::definition::Definition;
use crate::analysis::table::{Combination, Scope, ScopeCounts};
use crate::auth::Caller;
use crate::error::ApiError;
use crate::idempotency::{Idempotent, JsonBody};
use crate::state::AppState;
use crate::storage::pools::PoolDoc;
use crate::storage::scopes::{self, EmployerScope, EmployerScopes};

/// The most groups a preview combines: as many as a token's `groups` claim
/// lists before it overflows.
const MAX_PREVIEW_GROUPS: usize = 200;

/// The most values listed for one key.
const MAX_VALUES: usize = 1000;

/// The most near spellings suggested for one value.
const MAX_NEAR: usize = 3;

// ============================================================================
// Request / Response types
// ============================================================================

/// A new employer-scope mapping, replacing the current one whole.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplaceEmployerScopesRequest {
    /// The `version` of the mapping this edit started from: 0 for the first.
    pub version: u64,
    pub scopes: Vec<EmployerScope>,
}

/// A draft mapping to try on the pools' rows.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckEmployerScopesRequest {
    pub scopes: Vec<EmployerScope>,
    /// Groups, as a token's `groups` claim names them, whose members'
    /// view to preview: what a member of all of them would see.
    #[serde(default)]
    pub groups: Option<Vec<String>>,
}

/// What a draft mapping does in every pool with an analysis and data.
#[derive(Debug, Serialize, ToSchema)]
pub struct CheckEmployerScopesResponse {
    pub pools: Vec<PoolScopes>,
    /// Entries that are probably mistakes. They never stop a replacement.
    pub warnings: Vec<ScopeWarning>,
}

/// A draft mapping in one pool.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolScopes {
    pub pool_pda: String,
    pub pool_name: String,
    pub analysis_id: String,
    pub display_name: String,
    /// Every row the pool's analysis reads.
    pub rows: u64,
    /// The scope keys the pool's definition declares.
    pub keys: Vec<ScopeKey>,
    /// Each key's values with their rows, in order, empty values left out.
    pub values: BTreeMap<String, Vec<ValueRows>>,
    /// One for each of the draft's entries, in order.
    pub entries: Vec<EntryRows>,
    /// One for each group the draft names, in order of first mention.
    pub groups: Vec<GroupRows>,
    /// The rows no entry grants.
    pub uncovered: Coverage,
    /// What a member of all the request's `groups` would see; absent
    /// without `groups`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Grants>,
}

/// A scope key, and the CSV header of the column it restricts.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeKey {
    pub key: String,
    pub header: String,
}

/// A value and the rows that hold it; `null` is an empty cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ValueRows {
    pub value: Option<String>,
    pub rows: u64,
}

/// The rows an entry grants in a pool.
#[derive(Debug, Serialize, ToSchema)]
pub struct EntryRows {
    /// Whether the pool's definition declares every key the entry names;
    /// an entry it doesn't apply grants nothing in this pool.
    pub applies: bool,
    pub rows: u64,
}

/// What a group's members see in a pool: the rows its entries grant
/// together.
#[derive(Debug, Serialize, ToSchema)]
pub struct GroupRows {
    pub group_id: String,
    /// Whether any of the group's entries applies here. If none does, its
    /// members get `403 no_employer_scope` in this pool.
    pub applies: bool,
    pub rows: u64,
    /// The rows' values, by scope key.
    pub values: BTreeMap<String, Vec<ValueRows>>,
}

/// Rows, and their values by scope key.
#[derive(Debug, Serialize, ToSchema)]
pub struct Coverage {
    pub rows: u64,
    pub values: BTreeMap<String, Vec<ValueRows>>,
}

/// What a scope grants in a pool.
#[derive(Debug, Serialize, ToSchema)]
pub struct Grants {
    /// Whether any entry applies here. If none does, the caller gets
    /// `403 no_employer_scope` in this pool.
    pub applies: bool,
    pub rows: u64,
    pub values: BTreeMap<String, Vec<ValueRows>>,
}

/// An entry that is probably a mistake.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeWarning {
    /// `no_rows`, `undeclared_key` or `label_mismatch`.
    pub code: String,
    /// The entry, as an index into the draft's `scopes`.
    pub entry: usize,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<Suggestion>,
}

/// The pools' values spelt nearly like one an entry names that no pool
/// holds.
#[derive(Debug, Serialize, ToSchema)]
pub struct Suggestion {
    pub key: String,
    /// The value the entry names.
    pub value: String,
    /// The nearest values: the same but for case, or else the fewest edits
    /// away, at most two.
    pub near: Vec<String>,
}

/// A version of the mapping.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeVersion {
    pub version: u64,
    pub updated_at: Option<DateTime<Utc>>,
    /// The `user_id` of the admin whose replacement made it.
    pub updated_by: Option<String>,
    /// How many entries it holds.
    pub entries: usize,
}

/// One page of the mapping's versions, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeVersionsResponse {
    pub versions: Vec<ScopeVersion>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ============================================================================
// The dry run
// ============================================================================

/// The rows of `combinations`, and their values by key.
fn tally(keys: &[String], combinations: &[&Combination]) -> Coverage {
    let mut by_key: Vec<BTreeMap<Option<&str>, u64>> = vec![BTreeMap::new(); keys.len()];
    let mut rows = 0;
    for combination in combinations {
        rows += combination.rows;
        for (counts, value) in by_key.iter_mut().zip(&combination.values) {
            *counts.entry(value.as_deref()).or_default() += combination.rows;
        }
    }
    let values = keys
        .iter()
        .zip(by_key)
        .map(|(key, counts)| {
            let mut values: Vec<ValueRows> = counts
                .into_iter()
                .map(|(value, rows)| ValueRows {
                    value: value.map(String::from),
                    rows,
                })
                .collect();
            // Empty cells sort first in the map; list them last.
            let empty_first = values.first().is_some_and(|v| v.value.is_none());
            values.rotate_left(usize::from(empty_first));
            values.truncate(MAX_VALUES);
            (key.clone(), values)
        })
        .collect();
    Coverage { rows, values }
}

/// What `scope`, if `def` can apply any of it, grants of `counts`.
fn grants(counts: &ScopeCounts, def: &Definition, scope: Option<Scope>) -> Grants {
    match scope.and_then(|s| s.for_definition(def)) {
        None => Grants {
            applies: false,
            rows: 0,
            values: BTreeMap::new(),
        },
        Some(scope) => {
            let Coverage { rows, values } = tally(&counts.keys, &counts.split(&scope).0);
            Grants {
                applies: true,
                rows,
                values,
            }
        }
    }
}

/// The CSV header of the column scope key `key` restricts.
fn header(def: &Definition, key: &str) -> String {
    def.scope
        .get(key)
        .and_then(|column| def.column(column))
        .map_or_else(|| key.to_string(), |c| c.header.clone())
}

fn pool_scopes(
    doc: &PoolDoc,
    def: &Definition,
    counts: &ScopeCounts,
    draft: &EmployerScopes,
    preview: Option<&[String]>,
) -> PoolScopes {
    let every: Vec<&Combination> = counts.combinations.iter().collect();
    let values = tally(&counts.keys, &every)
        .values
        .into_iter()
        .map(|(key, mut values)| {
            values.retain(|v| v.value.is_some());
            (key, values)
        })
        .collect();
    let entries = draft
        .scopes
        .iter()
        .map(|entry| {
            let scope = Scope::Only(BTreeSet::from([entry.conditions.clone()]));
            let Grants { applies, rows, .. } = grants(counts, def, Some(scope));
            EntryRows { applies, rows }
        })
        .collect();
    let mut named = BTreeSet::new();
    let groups = draft
        .scopes
        .iter()
        .filter(|entry| named.insert(entry.group_id.as_str()))
        .map(|entry| {
            let group = std::slice::from_ref(&entry.group_id);
            let Grants {
                applies,
                rows,
                values,
            } = grants(counts, def, draft.rows_for(group));
            GroupRows {
                group_id: entry.group_id.clone(),
                applies,
                rows,
                values,
            }
        })
        .collect();
    let every_entry = Scope::Only(draft.scopes.iter().map(|e| e.conditions.clone()).collect());
    let uncovered = match every_entry.for_definition(def) {
        Some(scope) => tally(&counts.keys, &counts.split(&scope).1),
        None => tally(&counts.keys, &every),
    };
    PoolScopes {
        pool_pda: doc.pool_pda.clone(),
        pool_name: doc.pool_name.clone(),
        analysis_id: doc
            .analysis
            .as_ref()
            .map_or_else(String::new, |a| a.analysis_id.clone()),
        display_name: def.display_name.clone(),
        rows: counts.rows(),
        keys: def
            .scope
            .keys()
            .map(|key| ScopeKey {
                key: key.clone(),
                header: header(def, key),
            })
            .collect(),
        values,
        entries,
        groups,
        uncovered,
        preview: preview.map(|groups| grants(counts, def, draft.rows_for(groups))),
    }
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

/// Every value of `key` in `counts`, however many there are.
fn held<'a>(counts: &'a ScopeCounts, key: &str) -> impl Iterator<Item = &'a str> {
    let index = counts.keys.iter().position(|k| k == key);
    counts
        .combinations
        .iter()
        .filter_map(move |c| index.and_then(|i| c.values[i].as_deref()))
}

fn warnings(draft: &EmployerScopes, pools: &[(PoolScopes, &ScopeCounts)]) -> Vec<ScopeWarning> {
    let mut warnings = Vec::new();
    let mut labels: BTreeMap<&str, &str> = BTreeMap::new();
    for (i, entry) in draft.scopes.iter().enumerate() {
        let warn = |code: &str, message: String, suggestions| ScopeWarning {
            code: code.into(),
            entry: i,
            message,
            suggestions,
        };
        match labels.get(entry.group_id.as_str()) {
            Some(&first) if first != entry.label => warnings.push(warn(
                "label_mismatch",
                format!(
                    "group {} is labelled both {first:?} and {:?}",
                    entry.group_id, entry.label
                ),
                Vec::new(),
            )),
            Some(_) => {}
            None => {
                labels.insert(&entry.group_id, &entry.label);
            }
        }
        if pools.is_empty() {
            continue;
        }
        let applying: Vec<&(PoolScopes, &ScopeCounts)> =
            pools.iter().filter(|(p, _)| p.entries[i].applies).collect();
        if applying.is_empty() {
            let undeclared: Vec<&str> = entry
                .conditions
                .keys()
                .filter(|key| {
                    !pools
                        .iter()
                        .any(|(p, _)| p.keys.iter().any(|k| &k.key == *key))
                })
                .map(String::as_str)
                .collect();
            let message = if undeclared.is_empty() {
                format!(
                    "{} names keys that no pool's analysis declares together, so it grants nothing",
                    entry.label
                )
            } else {
                format!(
                    "{} names {}, which no pool's analysis declares, so it grants nothing",
                    entry.label,
                    undeclared.join(" and ")
                )
            };
            warnings.push(warn("undeclared_key", message, Vec::new()));
        } else if applying.iter().all(|(p, _)| p.entries[i].rows == 0) {
            let suggestions: Vec<Suggestion> = entry
                .conditions
                .iter()
                .filter_map(|(key, value)| {
                    let held: BTreeSet<&str> = applying
                        .iter()
                        .flat_map(|(_, counts)| held(counts, key))
                        .collect();
                    (!held.contains(value.as_str())).then(|| Suggestion {
                        key: key.clone(),
                        value: value.clone(),
                        near: near(value, &held),
                    })
                })
                .collect();
            let message = if suggestions.is_empty() {
                format!(
                    "{} grants no rows: no row holds all of its values together",
                    entry.label
                )
            } else {
                let missing: Vec<String> = suggestions
                    .iter()
                    .map(|s| format!("{} {:?}", s.key, s.value))
                    .collect();
                format!(
                    "{} grants no rows: no row holds {}",
                    entry.label,
                    missing.join(" or ")
                )
            };
            warnings.push(warn("no_rows", message, suggestions));
        }
    }
    warnings
}

// ============================================================================
// Handlers
// ============================================================================

/// Read the employer-scope mapping.
#[utoipa::path(
    get,
    path = "/v1/admin/employer-scopes",
    tag = "Admin",
    summary = "Employer scopes",
    description = "Which rows of an analysis the members of each Entra security group may see. Each entry names a group, by the value its `groups` claim carries (the object ID), and conditions on the scope keys analyses declare, such as `\"employer_group\": \"Group A\"`; it grants the rows that meet them all. An analyst sees the rows of every entry for their groups; admins see every row. Before the first replacement the mapping is empty, at version 0. Admin only.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The mapping", body = EmployerScopes),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn get_employer_scopes(
    caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<EmployerScopes>, ApiError> {
    caller.require_admin()?;
    Ok(Json(state.storage.employer_scopes().get().await?))
}

/// Replace the employer-scope mapping.
#[utoipa::path(
    put,
    path = "/v1/admin/employer-scopes",
    tag = "Admin",
    summary = "Replace employer scopes",
    description = "Replace the whole mapping, and keep it as a new version. `version` is the version the edit started from; if another replacement came first, this one is refused with 409, so read the mapping again. Names are matched exactly as the data holds them. A mapping that already holds these entries is returned unchanged. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = ReplaceEmployerScopesRequest,
    responses(
        (status = 200, description = "The new mapping", body = EmployerScopes),
        (status = 400, description = "An invalid entry, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 409, description = "The mapping changed since `version`"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn replace_employer_scopes(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<ReplaceEmployerScopesRequest>,
) -> Result<Response, ApiError> {
    caller.require_admin()?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);
    scopes::check(&payload.scopes).map_err(ApiError::bad_request)?;

    op.begin().await?;
    let mapping = state
        .storage
        .employer_scopes()
        .replace(payload.version, payload.scopes, &caller.user_id)
        .await?
        .ok_or_else(|| {
            ApiError::conflict(format!(
                "the employer scopes changed since version {}; read them again",
                payload.version
            ))
            .with_code("version_conflict")
        })?;

    info!(
        version = mapping.version,
        entries = mapping.scopes.len(),
        admin = %caller.user_id,
        "Employer scopes replaced"
    );
    op.finish(StatusCode::OK, &mapping).await
}

/// Try a draft mapping on every pool's rows, without saving it.
#[utoipa::path(
    post,
    path = "/v1/admin/employer-scopes/check",
    tag = "Admin",
    summary = "Try employer scopes",
    description = "Apply a draft mapping to every pool with an analysis and data, as analysts' tables would, and save nothing. For each pool: its rows and each scope key's values; each entry's rows, or that the pool's definition doesn't apply it; each group's rows and their values; the rows no entry grants; and, given `groups`, what a member of all of them would see. Warnings name entries that are probably mistakes: one that grants no rows in any pool (with the data's near spellings of a value no pool holds), one whose keys no pool's analysis declares, and a group under two labels. Read-only, so it takes no Idempotency-Key. Admin only.",
    security(("bearer_auth" = [])),
    request_body = CheckEmployerScopesRequest,
    responses(
        (status = 200, description = "What the draft does", body = CheckEmployerScopesResponse),
        (status = 400, description = "An invalid entry, or too many groups"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 503, description = "The worker is busy with analyses; retry after Retry-After"),
    )
)]
pub async fn check_employer_scopes(
    caller: Caller,
    State(state): State<AppState>,
    Json(request): Json<CheckEmployerScopesRequest>,
) -> Result<Json<CheckEmployerScopesResponse>, ApiError> {
    caller.require_admin()?;
    scopes::check(&request.scopes).map_err(ApiError::bad_request)?;
    if request
        .groups
        .as_ref()
        .is_some_and(|groups| groups.len() > MAX_PREVIEW_GROUPS)
    {
        return Err(ApiError::bad_request(format!(
            "a preview combines at most {MAX_PREVIEW_GROUPS} groups"
        )));
    }
    let draft = EmployerScopes {
        scopes: request.scopes,
        ..Default::default()
    };
    let mut counted = Vec::new();
    for doc in state.storage.pools().all().await? {
        let Some(analysis) = doc.analysis.as_ref().filter(|_| doc.initial.is_some()) else {
            continue;
        };
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
        let counts = state
            .analyses
            .scope_counts(&state.storage, &doc, &def)
            .await?;
        counted.push((doc, def, counts));
    }
    let pools: Vec<(PoolScopes, &ScopeCounts)> = counted
        .iter()
        .map(|(doc, def, counts)| {
            let pool = pool_scopes(doc, def, counts, &draft, request.groups.as_deref());
            (pool, counts.as_ref())
        })
        .collect();
    let warnings = warnings(&draft, &pools);
    info!(
        entries = draft.scopes.len(),
        pools = pools.len(),
        warnings = warnings.len(),
        admin = %caller.user_id,
        "Employer scopes checked"
    );
    Ok(Json(CheckEmployerScopesResponse {
        pools: pools.into_iter().map(|(pool, _)| pool).collect(),
        warnings,
    }))
}

/// The mapping's versions.
#[utoipa::path(
    get,
    path = "/v1/admin/employer-scopes/versions",
    tag = "Admin",
    summary = "Employer-scope versions",
    description = "Every version of the mapping, newest first, one cursor page at a time: who made it, when, and how many entries it holds. Admin only.",
    security(("bearer_auth" = [])),
    params(CursorQuery),
    responses(
        (status = 200, description = "The versions", body = ScopeVersionsResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn list_scope_versions(
    caller: Caller,
    State(state): State<AppState>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<ScopeVersionsResponse>, ApiError> {
    caller.require_admin()?;
    let scopes = state.storage.employer_scopes();
    let numbers: Vec<String> = scopes
        .versions()
        .await?
        .iter()
        .map(u64::to_string)
        .collect();
    let (numbers, next_cursor) = page(
        numbers,
        String::as_str,
        query.cursor.as_deref(),
        query.clamped_limit(),
    )?;
    let mut versions = Vec::with_capacity(numbers.len());
    for number in numbers {
        let Some(mapping) = scopes.version(number.parse().unwrap_or(0)).await? else {
            continue;
        };
        versions.push(ScopeVersion {
            version: mapping.version,
            updated_at: mapping.updated_at,
            updated_by: mapping.updated_by,
            entries: mapping.scopes.len(),
        });
    }
    Ok(Json(ScopeVersionsResponse {
        versions,
        next_cursor,
    }))
}

/// One version of the mapping.
#[utoipa::path(
    get,
    path = "/v1/admin/employer-scopes/versions/{version}",
    tag = "Admin",
    summary = "Employer-scope version",
    description = "The mapping as a replacement made it. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("version" = u64, Path, minimum = 1, description = "The version, from 1"),
    ),
    responses(
        (status = 200, description = "The version", body = EmployerScopes),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "No such version"),
    )
)]
pub async fn get_scope_version(
    caller: Caller,
    State(state): State<AppState>,
    Path(version): Path<u64>,
) -> Result<Json<EmployerScopes>, ApiError> {
    caller.require_admin()?;
    state
        .storage
        .employer_scopes()
        .version(version)
        .await?
        .map(Json)
        .ok_or_else(|| {
            ApiError::not_found(format!("the employer scopes have no version {version}"))
        })
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{header, Request};
    use serde_json::{json, Value};

    use super::*;
    use crate::api::analyses::tests::{awards_pool, grant};
    use crate::api::credentials::tests::{send, worker};
    use crate::api::grants::tests::{analysis_pool, analyst, ANALYSIS};
    use crate::storage::scopes::tests::{fixture, GROUP_A_ANALYSTS, NETWORK_ANALYSTS};
    use crate::storage::Change;

    const CHECK: &str = "/v1/admin/employer-scopes/check";
    const VERSIONS: &str = "/v1/admin/employer-scopes/versions";

    fn post(path: &str, token: &str, body: &Value) -> Request<Body> {
        Request::post(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn get(path: &str, token: &str) -> Request<Body> {
        Request::get(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn rows(value: &str, rows: u64) -> Value {
        json!({ "value": value, "rows": rows })
    }

    #[tokio::test]
    async fn a_dry_run_shows_what_analysts_would_get_and_saves_nothing() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        // A pool with an analysis but no data yet is left out.
        let empty = analysis_pool(&worker, &owner, 1).await;
        worker
            .storage
            .pools()
            .update::<ApiError>(&empty.to_string(), |doc| {
                doc.initial = None;
                Ok(Change::Changed)
            })
            .await
            .unwrap();

        let draft = json!([
            { "group_id": GROUP_A_ANALYSTS, "label": "GROUP_A_ANALYSTS", "employer_group": "Group A" },
            { "group_id": NETWORK_ANALYSTS, "label": "NETWORK_ANALYSTS", "employer": "Bank A Network" },
            { "group_id": NETWORK_ANALYSTS, "label": "NETWORK", "employer": "Bank C" },
            { "group_id": "g-typo", "label": "TYPO", "employer_group": "group b" },
            { "group_id": "g-region", "label": "REGION", "region": "Region E" },
        ]);
        let request = json!({ "scopes": draft, "groups": [NETWORK_ANALYSTS, "unmapped"] });
        let (status, _, checked) = send(&worker.app, post(CHECK, &owner.token, &request)).await;
        assert_eq!(status, StatusCode::OK, "{checked}");
        assert_eq!(checked["pools"].as_array().unwrap().len(), 1, "{checked}");
        let pool = &checked["pools"][0];
        assert_eq!(
            (&pool["pool_pda"], &pool["analysis_id"], &pool["rows"]),
            (&json!(pool_pda.to_string()), &json!(ANALYSIS), &json!(5))
        );
        assert_eq!(
            pool["keys"],
            json!([
                { "key": "employer", "header": "Employer" },
                { "key": "employer_group", "header": "Employer Group" },
            ])
        );
        assert_eq!(
            pool["values"]["employer_group"],
            json!([rows("Group A", 3), rows("Group B", 1), rows("Group C", 1)])
        );
        assert_eq!(
            pool["entries"],
            json!([
                { "applies": true, "rows": 3 },
                { "applies": true, "rows": 1 },
                { "applies": true, "rows": 1 },
                { "applies": true, "rows": 0 },
                { "applies": false, "rows": 0 },
            ])
        );
        // One entry per group in first-mention order; a group's entries
        // count together.
        let groups: Vec<&Value> = pool["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| &g["group_id"])
            .collect();
        assert_eq!(
            groups,
            [GROUP_A_ANALYSTS, NETWORK_ANALYSTS, "g-typo", "g-region"]
        );
        assert_eq!(
            pool["groups"][1],
            json!({
                "group_id": NETWORK_ANALYSTS, "applies": true, "rows": 2,
                "values": {
                    "employer": [rows("Bank A Network", 1), rows("Bank C", 1)],
                    "employer_group": [rows("Group A", 1), rows("Group C", 1)],
                },
            })
        );
        assert_eq!(
            pool["groups"][3],
            json!({ "group_id": "g-region", "applies": false, "rows": 0, "values": {} })
        );
        assert_eq!(
            pool["uncovered"],
            json!({
                "rows": 1,
                "values": { "employer": [rows("Bank B", 1)], "employer_group": [rows("Group B", 1)] },
            })
        );
        assert_eq!(
            (&pool["preview"]["applies"], &pool["preview"]["rows"]),
            (&json!(true), &json!(2))
        );

        let warnings = checked["warnings"].as_array().unwrap();
        let found: Vec<(&str, u64)> = warnings
            .iter()
            .map(|w| (w["code"].as_str().unwrap(), w["entry"].as_u64().unwrap()))
            .collect();
        assert_eq!(
            found,
            [("label_mismatch", 2), ("no_rows", 3), ("undeclared_key", 4)]
        );
        assert_eq!(
            warnings[1]["suggestions"],
            json!([{ "key": "employer_group", "value": "group b", "near": ["Group B"] }])
        );
        assert!(warnings[2]["message"].as_str().unwrap().contains("region"));

        // Nothing was saved, and what it showed for a group is what the
        // group's analysts get.
        let scopes = worker.storage.employer_scopes();
        assert_eq!(scopes.get().await.unwrap().version, 0);
        let entries: Vec<EmployerScope> = serde_json::from_value(draft).unwrap();
        scopes.replace(0, entries, &owner.user_id).await.unwrap();
        let (network, network_id) = analyst(&worker.app, "oid-network", &[NETWORK_ANALYSTS]).await;
        grant(&worker, &pool_pda, &network_id).await;
        let query = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}/query");
        let (status, _, page) = send(&worker.app, post(&query, &network, &json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["total_matched"], pool["groups"][1]["rows"]);
    }

    #[tokio::test]
    async fn a_dry_run_is_for_admins_and_checks_its_draft() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let (analyst, _) = analyst(&worker.app, "oid-analyst", &[GROUP_A_ANALYSTS]).await;
        let nothing = json!({ "scopes": [] });
        assert_eq!(
            send(&worker.app, post(CHECK, &analyst, &nothing)).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, _, checked) = send(&worker.app, post(CHECK, &owner.token, &nothing)).await;
        assert_eq!(
            (status, checked),
            (StatusCode::OK, json!({ "pools": [], "warnings": [] }))
        );

        let spaced =
            json!({ "scopes": [{ "group_id": "g", "label": "G", "employer": " Bank A" }] });
        let crowd: Vec<String> = (0..=MAX_PREVIEW_GROUPS).map(|i| format!("g-{i}")).collect();
        for bad in [spaced, json!({ "scopes": [], "groups": crowd })] {
            assert_eq!(
                send(&worker.app, post(CHECK, &owner.token, &bad)).await.0,
                StatusCode::BAD_REQUEST
            );
        }
        let unknown = json!({ "scopes": [], "save": true });
        assert_eq!(
            send(&worker.app, post(CHECK, &owner.token, &unknown))
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn admins_read_every_version_newest_first() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let scopes = worker.storage.employer_scopes();
        scopes.replace(0, fixture(), &owner.user_id).await.unwrap();
        scopes
            .replace(1, fixture()[..1].to_vec(), "admin-2")
            .await
            .unwrap();

        let (status, _, page) = send(&worker.app, get(VERSIONS, &owner.token)).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let summaries: Vec<(Value, Value, Value)> = page["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    v["version"].clone(),
                    v["updated_by"].clone(),
                    v["entries"].clone(),
                )
            })
            .collect();
        assert_eq!(
            summaries,
            [
                (json!(2), json!("admin-2"), json!(1)),
                (json!(1), json!(owner.user_id), json!(2)),
            ]
        );
        assert!(page["versions"][0]["updated_at"].is_string());
        assert!(page.get("next_cursor").is_none());

        let (_, _, first) = send(
            &worker.app,
            get(&format!("{VERSIONS}?limit=1"), &owner.token),
        )
        .await;
        assert_eq!(
            (&first["versions"][0]["version"], &first["next_cursor"]),
            (&json!(2), &json!("2"))
        );
        let next = format!("{VERSIONS}?limit=1&cursor=2");
        let (_, _, second) = send(&worker.app, get(&next, &owner.token)).await;
        assert_eq!(second["versions"][0]["version"], 1);
        assert!(second.get("next_cursor").is_none());

        let (status, _, one) = send(&worker.app, get(&format!("{VERSIONS}/1"), &owner.token)).await;
        assert_eq!(status, StatusCode::OK, "{one}");
        assert_eq!(one["scopes"], serde_json::to_value(fixture()).unwrap());
        for (path, refused) in [
            (format!("{VERSIONS}/3"), StatusCode::NOT_FOUND),
            (format!("{VERSIONS}/latest"), StatusCode::BAD_REQUEST),
        ] {
            assert_eq!(
                send(&worker.app, get(&path, &owner.token)).await.0,
                refused,
                "{path}"
            );
        }
        let (analyst, _) = analyst(&worker.app, "oid-analyst", &[]).await;
        assert_eq!(
            send(&worker.app, get(VERSIONS, &analyst)).await.0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn near_spellings_prefer_case_then_the_fewest_edits() {
        let held = BTreeSet::from(["Group A", "Group B", "Group C", "Bank A Network"]);
        assert_eq!(near("group b", &held), ["Group B"]);
        assert_eq!(near("Grop A", &held), ["Group A"]);
        assert_eq!(near("Lender D", &held), Vec::<String>::new());
        assert_eq!(near("Bank A Netwrok", &held), ["Bank A Network"]);
        assert_eq!(near("Group D", &held), ["Group A", "Group B", "Group C"]);
        assert_eq!(edits(&['a', 'b'], &['b', 'a'], 2), Some(2));
        assert_eq!(edits(&['a'; 5], &['b'; 5], 2), None);
    }
}
