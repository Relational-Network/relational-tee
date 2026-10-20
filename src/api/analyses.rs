// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Running a pool's analysis: an admin over every row, an analyst with an
//! active grant over the rows their grant scope allows.
//!
//! - `GET  …/analyses/{analysis_id}`                  — the analysis, and the caller's rows
//! - `POST …/analyses/{analysis_id}/options`          — filter options, under the other filters
//! - `POST …/analyses/{analysis_id}/options/{filter}` — a search filter's values, likewise
//! - `POST …/analyses/{analysis_id}/query`            — a page of matching rows
//! - `POST …/analyses/{analysis_id}/export`           — every matching row, as a file
//!
//! under `/v1/drt/pools/{pool_pda}`. The SQL is the pool's definition, read
//! from storage by the hash its Execute DRT pins; requests only bind values
//! to it. Every options, search and query request is recorded in the
//! analysis log ([`crate::storage::analysis_log`]), and a success whose
//! record can't be stored returns nothing. An export is recorded before it
//! runs, and runs in a task of its own that records how it ended, even
//! once its client has gone away.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, Method};
use axum::response::Response;
use axum::Json;
use chrono::{DateTime, Utc};
use hyper::body::{Frame, SizeHint};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{error, warn, Instrument, Span};
use utoipa::ToSchema;

use crate::analysis::definition::{ColumnType, Definition, FilterKind};
use crate::analysis::export::Format;
use crate::analysis::query::{
    self, FilterOptions, FilterRequest, Page, QueryError, QueryRequest, SortRequest,
    DEFAULT_SEARCH_LIMIT,
};
use crate::analysis::runner::Exported;
use crate::analysis::table::{check_targets, Scope, Target};
use crate::api::pools::load_pool;
use crate::audit;
use crate::auth::{Caller, Permission};
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::analysis_log::{AnalysisRecord, ExportEvent};
use crate::storage::chain::Seen;
use crate::storage::pools::{AnalysisRef, PoolDoc};
use crate::work::{Cancel, Cancelled};

// ============================================================================
// Request / Response types
// ============================================================================

/// A column a page returns.
#[derive(Debug, Serialize, ToSchema)]
pub struct ColumnSummary {
    pub name: String,
    /// The CSV header it comes from.
    pub header: String,
    /// `text`, or `date` (DD/MM/YYYY).
    #[serde(rename = "type")]
    pub kind: ColumnType,
}

/// A filter a request may use.
#[derive(Debug, Serialize, ToSchema)]
pub struct FilterSummary {
    pub name: String,
    /// `date_range` (`from` and `to`), `multi_select` (values from the
    /// options) or `search_select` (values from a search).
    pub kind: FilterKind,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PageSize {
    pub default: u32,
    pub max: u32,
}

/// The rows the caller sees: every row, or those matching any entry of
/// `any_of`, each a list of conditions a row must meet together.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeSummary {
    pub all: bool,
    pub any_of: Vec<Vec<ScopeCondition>>,
}

/// A row's column for scope key `key` holds `value` exactly.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeCondition {
    pub key: String,
    /// The CSV header of the column the key restricts.
    pub header: String,
    pub value: String,
}

/// A pool's analysis, as the caller may run it.
#[derive(Debug, Serialize, ToSchema)]
pub struct AnalysisSummary {
    pub pool_pda: String,
    pub pool_name: String,
    pub analysis_id: String,
    pub display_name: String,
    /// The definition's URL and SHA-256, as its Execute DRT records them.
    pub code_repo_url: String,
    pub code_hash_hex: String,
    /// What a page returns, in order.
    pub columns: Vec<ColumnSummary>,
    pub filters: Vec<FilterSummary>,
    pub default_sort: SortRequest,
    pub page_size: PageSize,
    pub scope: ScopeSummary,
    /// How many output columns a query's `distinct` may name.
    pub max_distinct: usize,
    /// With `include=page`: each filter's options but the searches', from
    /// all the caller's rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<BTreeMap<String, FilterOptions>>,
    /// With `include=page`: the page a query with no filters returns, in the
    /// default sort, at the default page size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<Page>,
    /// With `include=page`: each search filter's first values, as a search
    /// with no prefix and no filters returns them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub searches: Option<BTreeMap<String, Vec<String>>>,
}

/// Each filter's options but the searches', from the caller's rows.
#[derive(Debug, Serialize, ToSchema)]
pub struct OptionsResponse {
    /// By filter: `{ min, max }` (DD/MM/YYYY) for a date range, and the
    /// values with their row counts for a multi-select.
    pub options: BTreeMap<String, FilterOptions>,
}

/// Filter options under the filters a request sets.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OptionsRequest {
    /// As a query names them. Each filter's options come from the rows the
    /// other filters match, so its other values stay on offer.
    #[serde(default)]
    pub filters: BTreeMap<String, FilterRequest>,
}

/// A search filter's values under the filters a request sets.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchRequest {
    /// The values' prefix, matched literally; empty for the first values.
    #[serde(default)]
    pub search: String,
    /// How many values (default 20, max 100).
    pub limit: Option<u32>,
    /// As a query names them. The search filter's own is left out.
    #[serde(default)]
    pub filters: BTreeMap<String, FilterRequest>,
}

/// A search filter's values that start with the search, in order.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResponse {
    pub values: Vec<String>,
}

/// An export: a file format, and a query's filters and sort. It holds every
/// matching row, so a page, `distinct` or anything else is refused.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    pub format: Format,
    /// As a query names them.
    #[serde(default)]
    pub filters: BTreeMap<String, FilterRequest>,
    /// The definition's default sort when omitted.
    #[serde(default)]
    pub sort: Option<SortRequest>,
}

/// The export ID an export's file comes with, as its analysis log records
/// name it.
pub const EXPORT_ID_HEADER: HeaderName = HeaderName::from_static("x-export-id");

// ============================================================================
// Helpers
// ============================================================================

/// The pool's document and its analysis `analysis_id`, or 404.
async fn load(
    state: &AppState,
    pool_pda: &str,
    analysis_id: &str,
) -> Result<(PoolDoc, AnalysisRef), ApiError> {
    let doc = load_pool(state, pool_pda).await?;
    let analysis = doc
        .analysis
        .clone()
        .filter(|a| a.analysis_id == analysis_id)
        .ok_or_else(|| ApiError::not_found(format!("this pool has no analysis {analysis_id:?}")))?;
    Ok((doc, analysis))
}

/// The grant a request runs through, and the chain reading that showed it.
struct Through {
    grant_id: String,
    seen: Seen,
}

/// The grant the caller runs the analysis through (none for an admin), and
/// the rows they see: those of any of the grant's targets. Fails closed: no
/// active grant, a grant with no targets or with targets the analysis can't
/// apply, or a grant the chain doesn't show, is 403.
async fn authorize(
    state: &AppState,
    caller: &Caller,
    doc: &PoolDoc,
    analysis: &AnalysisRef,
    def: &Definition,
) -> Result<(Option<Through>, Scope), ApiError> {
    if caller.is_admin() {
        return Ok((None, Scope::All));
    }
    let grant = doc
        .active_grant(&caller.user_id, &analysis.analysis_id)
        .ok_or_else(|| {
            ApiError::forbidden("you have no active grant to this analysis").with_code("no_grant")
        })?;
    let targets = grant.targets().ok_or_else(|| {
        ApiError::forbidden("your grant gives you no rows yet; ask the pool's owner")
            .with_code("no_employer_scope")
    })?;
    let targets: Vec<Target> = targets.iter().cloned().collect();
    let targets = check_targets(def, &targets).map_err(|e| {
        warn!(grant_id = %grant.grant_id, error = %e, "A grant's targets don't fit its analysis");
        ApiError::forbidden(
            "your grant's targets don't fit this analysis; ask the pool's owner to set them again",
        )
        .with_code("invalid_grant_scope")
    })?;
    let scope = Scope::of(&targets);
    let seen = state
        .grant_checks
        .verify(&state.storage, &state.solana_client, doc, grant)
        .await?;
    let through = Through {
        grant_id: grant.grant_id.clone(),
        seen,
    };
    Ok((Some(through), scope))
}

/// `answer`, unless the caller is an analyst and the pool has made a change
/// since the request read `doc`: then `503 pool_settling`, and the retry
/// runs on the latest document, so that a revocation recorded while the
/// request ran holds for its answer too.
async fn if_current<T>(
    state: &AppState,
    doc: &PoolDoc,
    analyst: bool,
    answer: T,
) -> Result<T, ApiError> {
    if analyst {
        crate::generation::still_current(&state.storage, doc).await?;
    }
    Ok(answer)
}

/// 415 unless the request's body is JSON.
fn require_json(headers: &HeaderMap) -> Result<(), ApiError> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));
    if is_json {
        Ok(())
    } else {
        Err(ApiError::unsupported_media_type(
            "the request is JSON: send Content-Type: application/json",
        ))
    }
}

/// The request in `body`, or `400 invalid_query`.
fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| {
        ApiError::bad_request(format!("the request isn't valid: {e}")).with_code("invalid_query")
    })
}

/// `filters`, checked as a query's are, with no sort or paging.
fn filters_only(
    def: &Definition,
    filters: BTreeMap<String, FilterRequest>,
) -> Result<query::Query, ApiError> {
    let request = QueryRequest {
        filters,
        ..Default::default()
    };
    query::Query::check(def, &request).map_err(query_error)
}

fn query_error(e: QueryError) -> ApiError {
    match e {
        QueryError::Invalid(message) => ApiError::bad_request(message).with_code("invalid_query"),
        QueryError::Timeout => ApiError::unprocessable(
            "the analysis ran out of time; narrow the filters and try again",
        )
        .with_code("analysis_timeout"),
        QueryError::Failed(message) => {
            error!(error = %message, "An analysis failed");
            ApiError::internal("the analysis failed")
        }
    }
}

/// A request's analysis log record, completed when it finishes.
struct Logged {
    record: AnalysisRecord,
}

impl Logged {
    fn new(
        caller: &Caller,
        doc: &PoolDoc,
        analysis: &AnalysisRef,
        action: &str,
        request: Value,
    ) -> Self {
        Self {
            record: AnalysisRecord {
                event_id: uuid::Uuid::new_v4().to_string(),
                request_id: crate::request_id::current().unwrap_or_default(),
                at: Utc::now(),
                user_id: caller.user_id.clone(),
                grant_id: None,
                chain_slot: None,
                chain_verified_at: None,
                pool_pda: doc.pool_pda.clone(),
                analysis_id: analysis.analysis_id.clone(),
                definition_sha256: analysis.code_hash_hex.clone(),
                action: action.into(),
                request,
                returned: None,
                total_matched: None,
                outcome: String::new(),
                export: None,
            },
        }
    }

    /// The grant the request runs through, and the chain reading of it.
    fn through(&mut self, through: Option<Through>) {
        if let Some(through) = through {
            self.record.grant_id = Some(through.grant_id);
            self.record.chain_slot = Some(through.seen.slot);
            self.record.chain_verified_at = Some(through.seen.at);
        }
    }

    /// Record how `result` went, then return it: a success only once its
    /// record is stored.
    async fn finish<T>(
        mut self,
        state: &AppState,
        result: Result<T, ApiError>,
        counts: impl Fn(&T) -> (u64, Option<u64>),
    ) -> Result<T, ApiError> {
        match &result {
            Ok(value) => {
                let (returned, total) = counts(value);
                self.record.returned = Some(returned);
                self.record.total_matched = total;
                self.record.outcome = "success".into();
            }
            Err(e) => self.record.outcome = e.code.into(),
        }
        let stored = state.storage.analysis_log().record(&self.record).await;
        match (result, stored) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(e)) => {
                error!(alert = "analysis_log", error = %e, "An analysis request couldn't be logged");
                Err(log_unavailable())
            }
            (Err(e), stored) => {
                if let Err(log) = stored {
                    warn!(error = %log, "A failed analysis request couldn't be logged");
                }
                Err(e)
            }
        }
    }
}

fn scope_summary(scope: &Scope, def: &Definition) -> ScopeSummary {
    match scope {
        Scope::All => ScopeSummary {
            all: true,
            any_of: Vec::new(),
        },
        Scope::Only(entries) => ScopeSummary {
            all: false,
            any_of: entries
                .iter()
                .map(|conditions| {
                    conditions
                        .iter()
                        .map(|(key, value)| ScopeCondition {
                            key: key.clone(),
                            header: def
                                .scope
                                .get(key)
                                .and_then(|column| def.column(column))
                                .map_or_else(|| key.clone(), |c| c.header.clone()),
                            value: value.clone(),
                        })
                        .collect()
                })
                .collect(),
        },
    }
}

fn summary(
    doc: &PoolDoc,
    analysis: &AnalysisRef,
    def: &Definition,
    scope: &Scope,
) -> AnalysisSummary {
    AnalysisSummary {
        pool_pda: doc.pool_pda.clone(),
        pool_name: doc.pool_name.clone(),
        analysis_id: analysis.analysis_id.clone(),
        display_name: def.display_name.clone(),
        code_repo_url: analysis.code_repo_url.clone(),
        code_hash_hex: analysis.code_hash_hex.clone(),
        columns: def
            .output
            .iter()
            .filter_map(|name| def.column(name))
            .map(|c| ColumnSummary {
                name: c.name.clone(),
                header: c.header.clone(),
                kind: c.kind,
            })
            .collect(),
        filters: def
            .filters
            .iter()
            .map(|f| FilterSummary {
                name: f.name.clone(),
                kind: f.kind,
            })
            .collect(),
        default_sort: SortRequest {
            field: def.default_sort.0.clone(),
            direction: def.default_sort.1,
        },
        page_size: PageSize {
            default: def.page_default,
            max: def.page_max,
        },
        scope: scope_summary(scope, def),
        max_distinct: query::MAX_DISTINCT,
        options: None,
        page: None,
        searches: None,
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// A pool's analysis: its columns, filters, sort and paging, and the rows
/// the caller sees.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}",
    tag = "Analyses",
    summary = "Get an analysis",
    description = "The pool's analysis as the caller may run it: the columns a page returns, the filters a query may use, the default sort and page sizes, the definition's URL and hash, and the rows the caller sees (every row for an admin; for an analyst, their grant scope). With `include=page` it opens the analysis: it also returns each filter's options but the searches' from all the caller's rows, the page a query with no filters returns in the default sort at the default page size, with the distinct counts `distinct` asks for, and each search filter's first values, as a search with no prefix returns them. An open counts against the per-user limit on non-`GET` requests and is recorded in the analysis log as one `open`; a description alone isn't. Needs `analyses:run`, and for an analyst an active grant.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
        ("include" = Option<String>, Query, description = "`page` opens the analysis with its options and first page"),
        ("distinct" = Option<Vec<String>>, Query, description = "With `include=page`, repeated: output columns to count the distinct values of in every row, at most `max_distinct`"),
    ),
    responses(
        (status = 200, description = "The analysis", body = AnalysisSummary),
        (status = 400, description = "A parameter other than `include=page` and its `distinct`, or a `distinct` that doesn't fit the analysis (`invalid_query`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "No active grant (`no_grant`), a grant the chain doesn't show (`grant_not_live`), or no row scope (`no_employer_scope`)"),
        (status = 404, description = "Pool or analysis not found"),
        (status = 422, description = "The open ran out of time (`analysis_timeout`)"),
        (status = 429, description = "An open over the per-user limit (`rate_limited`, with Retry-After)"),
        (status = 503, description = "The worker is busy (`analysis_busy`, with Retry-After), an open couldn't be recorded in the analysis log (`analysis_log_unavailable`), the chain can't be read to check the grant (`rpc_unavailable`), the pool's last change is still being anchored or was made while the request ran (`pool_settling`, with Retry-After), or the pool's records are older than its on-chain generation (`pool_records_stale`)"),
    )
)]
pub async fn get_analysis(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id)): Path<(String, String)>,
    params: Result<Query<Vec<(String, String)>>, QueryRejection>,
) -> Result<Json<AnalysisSummary>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    let params = params
        .map(|Query(p)| p)
        .map_err(|e| invalid_query(e.body_text()))?;
    if let Some(distinct) = open_request(&params)? {
        audit::emit();
        // It runs a page, as a query does, so it counts as one does.
        state.limiter.check_user(&Method::POST, &caller.user_id)?;
        let (doc, analysis) = load(&state, &pool_pda, &analysis_id).await?;
        return open(&caller, &state, &doc, &analysis, distinct)
            .await
            .map(Json);
    }
    let (doc, analysis) = load(&state, &pool_pda, &analysis_id).await?;
    let def = state
        .analyses
        .definition(&state.storage, &analysis.code_hash_hex)
        .await?;
    let (through, scope) = authorize(&state, &caller, &doc, &analysis, &def).await?;
    let answer = summary(&doc, &analysis, &def, &scope);
    if_current(&state, &doc, through.is_some(), answer)
        .await
        .map(Json)
}

fn invalid_query(message: impl Into<String>) -> ApiError {
    ApiError::bad_request(message).with_code("invalid_query")
}

/// The open a description `GET` asks for: none without parameters, or the
/// `distinct` columns with `include=page`. Anything else is refused.
fn open_request(params: &[(String, String)]) -> Result<Option<Vec<String>>, ApiError> {
    if params.is_empty() {
        return Ok(None);
    }
    let mut include = false;
    let mut distinct = Vec::new();
    for (key, value) in params {
        match key.as_str() {
            "include" if !include && value == "page" => include = true,
            "include" => return Err(invalid_query("include takes page, once")),
            "distinct" => distinct.push(value.clone()),
            _ => {
                return Err(invalid_query(format!(
                    "the analysis takes no parameter {key}"
                )))
            }
        }
    }
    if !include {
        return Err(invalid_query("distinct needs include=page"));
    }
    Ok(Some(distinct))
}

/// Open the analysis: its description, the options of all the caller's
/// rows, the page a query with no filters returns and each search filter's
/// first values, all from one table, recorded in the analysis log once.
async fn open(
    caller: &Caller,
    state: &AppState,
    doc: &PoolDoc,
    analysis: &AnalysisRef,
    distinct: Vec<String>,
) -> Result<AnalysisSummary, ApiError> {
    let asked = json!({ "include": "page", "distinct": distinct });
    let mut logged = Logged::new(caller, doc, analysis, "open", asked);
    let result = async {
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
        let (grant, scope) = authorize(state, caller, doc, analysis, &def).await?;
        let analyst = grant.is_some();
        logged.through(grant);
        let request = QueryRequest {
            distinct,
            ..Default::default()
        };
        let query = query::Query::check(&def, &request).map_err(query_error)?;
        // The record holds the query that ran, as a query's does.
        let mut ran = json!({
            "filters": {},
            "sort": { "field": query.sort, "direction": query.direction },
            "pagination": { "limit": query.limit, "offset": query.offset },
        });
        if !query.distinct.is_empty() {
            ran["distinct"] = json!(query.distinct);
        }
        logged.record.request = ran;
        let mut answer = summary(doc, analysis, &def, &scope);
        let table = state
            .analyses
            .table(&state.storage, doc, &def, &scope)
            .await?;
        answer.options = Some(table.options().clone());
        let (page, searches) = state
            .analyses
            .on_table(table, move |table, stop| {
                let page = table.page(&def, &query, stop).map_err(query_error)?;
                let mut searches = BTreeMap::new();
                for filter in def
                    .filters
                    .iter()
                    .filter(|f| f.kind == FilterKind::SearchSelect)
                {
                    let values = table
                        .search(&def, &filter.name, "", DEFAULT_SEARCH_LIMIT, &query, stop)
                        .map_err(query_error)?;
                    searches.insert(filter.name.clone(), values);
                }
                Ok((page, searches))
            })
            .await?;
        answer.page = Some(page);
        answer.searches = Some(searches);
        if_current(state, doc, analyst, answer).await
    }
    .await;
    let opened = logged
        .finish(state, result, |answer| match &answer.page {
            Some(page) => (page.rows.len() as u64, Some(page.total_matched)),
            None => (0, None),
        })
        .await?;
    if let Some(page) = &opened.page {
        audit::rows(page.rows.len() as u64);
    }
    Ok(opened)
}

/// Each filter's options, from the caller's rows the other filters match.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/options",
    tag = "Analyses",
    summary = "Filter options",
    description = "The options of each filter but the searches, from the rows the caller sees only: the earliest and latest date of a date range, and each value of a multi-select with its row count. Each filter's options come from the rows that the request's other filters match, so they follow what a page shows: setting an award narrows the date range's bounds and the other filters' values, while the award filter's own values stay on offer. With no filters, they're the options of all the caller's rows. The filters are checked as a query's are. Read-only, so it needs no Idempotency-Key. Recorded in the analysis log. Needs `analyses:run`, and for an analyst an active grant.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
    ),
    request_body = OptionsRequest,
    responses(
        (status = 200, description = "The options", body = OptionsResponse),
        (status = 400, description = "The filters don't fit the analysis (`invalid_query`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "No active grant (`no_grant`), a grant the chain doesn't show (`grant_not_live`), or no row scope"),
        (status = 404, description = "Pool or analysis not found"),
        (status = 415, description = "The body isn't JSON"),
        (status = 422, description = "The options ran out of time (`analysis_timeout`)"),
        (status = 503, description = "The worker is busy (`analysis_busy`, with Retry-After), the analysis log is unavailable, the chain can't be read to check the grant (`rpc_unavailable`), the pool's last change is still being anchored or was made while the request ran (`pool_settling`, with Retry-After), or the pool's records are older than its on-chain generation (`pool_records_stale`)"),
    )
)]
pub async fn filtered_options(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<OptionsResponse>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    require_json(&headers)?;
    options_for(&caller, &state, &pool_pda, &analysis_id, &body)
        .await
        .map(Json)
}

/// The options route's work. A request that sets no filter gets the
/// options the table was built with.
async fn options_for(
    caller: &Caller,
    state: &AppState,
    pool_pda: &str,
    analysis_id: &str,
    body: &Bytes,
) -> Result<OptionsResponse, ApiError> {
    let (doc, analysis) = load(state, pool_pda, analysis_id).await?;
    let asked = serde_json::from_slice(body).unwrap_or(Value::Null);
    let mut logged = Logged::new(caller, &doc, &analysis, "options", asked);
    let result = async {
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
        let (grant, scope) = authorize(state, caller, &doc, &analysis, &def).await?;
        let analyst = grant.is_some();
        logged.through(grant);
        let request: OptionsRequest = parse(body)?;
        let query = filters_only(&def, request.filters)?;
        let table = state
            .analyses
            .table(&state.storage, &doc, &def, &scope)
            .await?;
        if query.is_unfiltered() {
            let options = table.options().clone();
            return if_current(state, &doc, analyst, OptionsResponse { options }).await;
        }
        let options = state
            .analyses
            .on_table(table, move |table, stop| {
                table.facets(&def, &query, stop).map_err(query_error)
            })
            .await?;
        if_current(state, &doc, analyst, OptionsResponse { options }).await
    }
    .await;
    logged
        .finish(state, result, |r| {
            let values = r.options.values().map(|o| match o {
                FilterOptions::Values(values) => values.len() as u64,
                FilterOptions::DateRange { .. } => 0,
            });
            (values.sum(), None)
        })
        .await
}

/// A search filter's values that start with `search`, from the caller's
/// rows the other filters match.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/options/{filter}",
    tag = "Analyses",
    summary = "Search a filter's values",
    description = "The values of a search filter, such as a staff number, that start with `search`, in order, from the rows the caller sees that the request's other filters match; the search filter's own selection is left out, so its other values stay on offer. The filters are checked as a query's are. Read-only, so it needs no Idempotency-Key. Recorded in the analysis log. Needs `analyses:run`, and for an analyst an active grant.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
        ("filter" = String, Path, description = "A search filter of the analysis"),
    ),
    request_body = SearchRequest,
    responses(
        (status = 200, description = "The values", body = SearchResponse),
        (status = 400, description = "Not a search filter, a search or limit out of range, or filters that don't fit the analysis (`invalid_query`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "No active grant (`no_grant`), a grant the chain doesn't show (`grant_not_live`), or no row scope"),
        (status = 404, description = "Pool or analysis not found"),
        (status = 415, description = "The body isn't JSON"),
        (status = 422, description = "The search ran out of time (`analysis_timeout`)"),
        (status = 503, description = "The worker is busy (`analysis_busy`, with Retry-After), the analysis log is unavailable, the chain can't be read to check the grant (`rpc_unavailable`), the pool's last change is still being anchored or was made while the request ran (`pool_settling`, with Retry-After), or the pool's records are older than its on-chain generation (`pool_records_stale`)"),
    )
)]
pub async fn filtered_search(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id, filter)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SearchResponse>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    require_json(&headers)?;
    search_for(&caller, &state, &pool_pda, &analysis_id, filter, &body)
        .await
        .map(Json)
}

/// The search route's work.
async fn search_for(
    caller: &Caller,
    state: &AppState,
    pool_pda: &str,
    analysis_id: &str,
    filter: String,
    body: &Bytes,
) -> Result<SearchResponse, ApiError> {
    let (doc, analysis) = load(state, pool_pda, analysis_id).await?;
    let asked = match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(mut fields)) => {
            fields.insert("filter".into(), json!(filter));
            Value::Object(fields)
        }
        _ => json!({ "filter": filter }),
    };
    let mut logged = Logged::new(caller, &doc, &analysis, "search", asked);
    let result = async {
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
        let (grant, scope) = authorize(state, caller, &doc, &analysis, &def).await?;
        let analyst = grant.is_some();
        logged.through(grant);
        let request: SearchRequest = parse(body)?;
        let query = filters_only(&def, request.filters)?;
        let limit = request.limit.unwrap_or(DEFAULT_SEARCH_LIMIT);
        let table = state
            .analyses
            .table(&state.storage, &doc, &def, &scope)
            .await?;
        let prefix = request.search;
        let values = state
            .analyses
            .on_table(table, move |table, stop| {
                table
                    .search(&def, &filter, &prefix, limit, &query, stop)
                    .map_err(query_error)
            })
            .await?;
        if_current(state, &doc, analyst, SearchResponse { values }).await
    }
    .await;
    logged
        .finish(state, result, |r| (r.values.len() as u64, None))
        .await
}

/// A page of the rows that match a query, from the caller's rows.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/query",
    tag = "Analyses",
    summary = "Query an analysis",
    description = "Run the pool's approved SQL with the request's filters bound as values, on the rows the caller sees only, and return one page in the sort asked for (an output column, then a stable row key), with the total number of matching rows. Filters combine with AND, a filter's values with OR; an omitted filter, or mode `all`, adds no condition. Dates are DD/MM/YYYY, and date ranges are inclusive. Unknown filters, sorts or fields, such as a scope, are refused. Read-only, so it needs no Idempotency-Key. Recorded in the analysis log. Needs `analyses:run`, and for an analyst an active grant.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
    ),
    request_body = QueryRequest,
    responses(
        (status = 200, description = "A page of rows", body = Page),
        (status = 400, description = "The query doesn't fit the analysis (`invalid_query`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "No active grant (`no_grant`), a grant the chain doesn't show (`grant_not_live`), or no row scope"),
        (status = 404, description = "Pool or analysis not found"),
        (status = 415, description = "The body isn't JSON"),
        (status = 422, description = "The query ran out of time (`analysis_timeout`)"),
        (status = 503, description = "The worker is busy (`analysis_busy`, with Retry-After), the analysis log is unavailable, the chain can't be read to check the grant (`rpc_unavailable`), the pool's last change is still being anchored or was made while the request ran (`pool_settling`, with Retry-After), or the pool's records are older than its on-chain generation (`pool_records_stale`)"),
    )
)]
pub async fn run_query(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Page>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    require_json(&headers)?;
    let (doc, analysis) = load(&state, &pool_pda, &analysis_id).await?;
    let asked = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let mut logged = Logged::new(&caller, &doc, &analysis, "query", asked);
    let result = async {
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
        let (grant, scope) = authorize(&state, &caller, &doc, &analysis, &def).await?;
        let analyst = grant.is_some();
        logged.through(grant);
        let request: QueryRequest = parse(&body)?;
        let query = query::Query::check(&def, &request).map_err(query_error)?;
        if let Some(asked) = logged.record.request.as_object_mut() {
            asked.insert(
                "ran_with".into(),
                json!({
                    "sort": { "field": query.sort, "direction": query.direction },
                    "pagination": { "limit": query.limit, "offset": query.offset },
                }),
            );
        }
        let table = state
            .analyses
            .table(&state.storage, &doc, &def, &scope)
            .await?;
        let page = state
            .analyses
            .on_table(table, move |table, stop| {
                table.page(&def, &query, stop).map_err(query_error)
            })
            .await?;
        if_current(&state, &doc, analyst, page).await
    }
    .await;
    let page = logged
        .finish(&state, result, |page| {
            (page.rows.len() as u64, Some(page.total_matched))
        })
        .await?;
    audit::rows(page.rows.len() as u64);
    Ok(Json(page))
}

/// Every row of the caller's that a query matches, as a CSV or XLSX file.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/export",
    tag = "Analyses",
    summary = "Export an analysis",
    description = "Every row the caller sees that the request's filters match, in the sort asked for, as a file of the analysis's output columns: CSV (UTF-8 with a byte order mark, CRLF line ends) or XLSX. The filters and sort are checked as a query's are; an export takes no page, `distinct` or scope. Dates are DD/MM/YYYY and empty cells are empty. Every XLSX cell is text, never a number, formula or link; a CSV value that a spreadsheet would read as a formula starts with `'`, unless it's a plain amount such as `-25.00`. An export holds at most 100,000 rows and 50 MiB, and fails rather than returning part of its rows. It's recorded in the analysis log twice under the export ID it returns: when it's asked for, before any work, and when it ends, and a file is sent only once its success is stored. Read-only, so it needs no Idempotency-Key. Needs `analyses:run`, and for an analyst an active grant.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
    ),
    request_body = ExportRequest,
    responses(
        (status = 200, description = "The file",
            content(
                (String = "text/csv"),
                ([u8] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            ),
            headers(
                ("Content-Disposition" = String, description = "`attachment`, with a file name of the analysis ID and the UTC time the export was asked for"),
                ("X-Export-Id" = String, description = "The export's ID, as its two records in the analysis log name it"),
            ),
        ),
        (status = 400, description = "A format the worker doesn't make, or filters or a sort that don't fit the analysis (`invalid_query`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "No active grant (`no_grant`), a grant the chain doesn't show (`grant_not_live`), or no row scope"),
        (status = 404, description = "Pool or analysis not found"),
        (status = 415, description = "The body isn't JSON"),
        (status = 422, description = "More rows match than an export holds (`export_too_many_rows`), the file would be over 50 MiB or holds a cell over Excel's 32,767 characters (`export_too_large`), the export ran out of time (`analysis_timeout`), or it needs more memory than the worker has (`too_large_for_memory`)"),
        (status = 503, description = "The worker is busy (`analysis_busy` or `worker_busy`, with Retry-After), the export couldn't be recorded in the analysis log (`analysis_log_unavailable`), the chain can't be read to check the grant (`rpc_unavailable`), the pool's last change is still being anchored or was made while the export ran (`pool_settling`, with Retry-After), or the pool's records are older than its on-chain generation (`pool_records_stale`)"),
    )
)]
pub async fn export_analysis(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    require_json(&headers)?;
    let (doc, analysis) = load(&state, &pool_pda, &analysis_id).await?;
    let asked = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let format = asked
        .get("format")
        .and_then(|f| Format::deserialize(f).ok());
    let mut logged = Logged::new(&caller, &doc, &analysis, "export", asked);
    let requested_at = logged.record.at;
    let export_id = uuid::Uuid::new_v4().to_string();
    logged.record.outcome = "requested".into();
    logged.record.export = Some(ExportEvent {
        export_id: export_id.clone(),
        stage: "requested".into(),
        format,
        pool_name: doc.pool_name.clone(),
        requested_at,
        result: None,
        bytes: None,
        duration_ms: None,
    });
    if let Err(e) = state.storage.analysis_log().record(&logged.record).await {
        error!(alert = "analysis_log", error = %e, "An export request couldn't be logged");
        return Err(log_unavailable());
    }
    // The export runs in a task of its own, so that it records how it ended
    // even if its client goes away; dropping `cancel` stops its work.
    let cancel = Cancel::default();
    let task = tokio::spawn(
        run_export(state, caller, doc, analysis, body, logged, cancel.watch())
            .instrument(Span::current()),
    );
    let (exported, format) = task.await.map_err(|e| {
        error!(error = %e, "An export's task failed");
        ApiError::internal("the export failed")
    })??;
    let Exported { file, rows } = exported;
    audit::rows(rows);
    let name = file_name(&analysis_id, requested_at, format);
    let body = Body::new(FileBody(file));
    Response::builder()
        .header(header::CONTENT_TYPE, format.content_type())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .header(EXPORT_ID_HEADER, export_id)
        .body(body)
        .map_err(|e| {
            error!(error = %e, "An export's response couldn't be built");
            ApiError::internal("the export failed")
        })
}

/// The export route's work, after its request is recorded: the file, and
/// the record of how it ended, stored before the file is returned. A
/// success whose record can't be stored, once retried, returns nothing.
async fn run_export(
    state: AppState,
    caller: Caller,
    doc: PoolDoc,
    analysis: AnalysisRef,
    body: Bytes,
    mut logged: Logged,
    cancelled: Cancelled,
) -> Result<(Exported, Format), ApiError> {
    let result = async {
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
        let (grant, scope) = authorize(&state, &caller, &doc, &analysis, &def).await?;
        let analyst = grant.is_some();
        logged.through(grant);
        let request: ExportRequest = parse(&body)?;
        let asked = QueryRequest {
            filters: request.filters,
            sort: request.sort,
            ..Default::default()
        };
        let query = query::Query::check(&def, &asked).map_err(query_error)?;
        if let Some(asked) = logged.record.request.as_object_mut() {
            asked.insert(
                "ran_with".into(),
                json!({ "sort": { "field": query.sort, "direction": query.direction } }),
            );
        }
        let table = state
            .analyses
            .table(&state.storage, &doc, &def, &scope)
            .await?;
        let exported = state
            .analyses
            .export(table, def, query, request.format, &cancelled)
            .await?;
        if_current(&state, &doc, analyst, (exported, request.format)).await
    }
    .await;

    let record = &mut logged.record;
    let event = record.export.as_mut().expect("an export's record names it");
    let (result_name, outcome) = match &result {
        Ok(_) if cancelled.is_set() => ("cancelled", "cancelled"),
        Ok(_) => ("success", "success"),
        Err(e) if e.code == "analysis_timeout" && cancelled.is_set() => ("cancelled", "cancelled"),
        Err(e) if e.code == "analysis_timeout" => ("timeout", e.code),
        Err(e) if e.status.is_server_error() => ("failed", e.code),
        Err(e) => ("refused", e.code),
    };
    if let Ok((exported, _)) = &result {
        record.returned = Some(exported.rows);
        record.total_matched = Some(exported.rows);
        event.bytes = Some(exported.file.len() as u64);
    }
    record.event_id = uuid::Uuid::new_v4().to_string();
    record.at = Utc::now();
    record.outcome = outcome.into();
    event.stage = "finished".into();
    event.result = Some(result_name.into());
    event.duration_ms =
        Some(u64::try_from((record.at - event.requested_at).num_milliseconds()).unwrap_or(0));

    let log = state.storage.analysis_log();
    let stored = match log.record(record).await {
        Ok(()) => Ok(()),
        Err(first) => {
            warn!(error = %first, "An export's record couldn't be stored; retrying");
            log.record(record).await
        }
    };
    match (result, stored) {
        (Ok(file), Ok(())) => Ok(file),
        (Ok(_), Err(e)) => {
            error!(alert = "analysis_log", error = %e, "An export couldn't be logged");
            Err(log_unavailable())
        }
        (Err(e), stored) => {
            if let Err(log) = stored {
                warn!(error = %log, "A failed export couldn't be logged");
            }
            Err(e)
        }
    }
}

/// `503 analysis_log_unavailable`: the request couldn't be recorded.
fn log_unavailable() -> ApiError {
    ApiError::service_unavailable(
        "this request couldn't be recorded in the analysis log, so its result isn't returned; retry",
    )
    .with_code("analysis_log_unavailable")
}

/// An export's file name: the analysis ID, kept to characters any file
/// system and header take, and the UTC time it was asked for.
fn file_name(analysis_id: &str, requested_at: DateTime<Utc>, format: Format) -> String {
    let mut stem: String = analysis_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    if stem.trim_matches('.').is_empty() {
        stem = "export".into();
    }
    format!(
        "{stem}-{}.{}",
        requested_at.format("%Y%m%d-%H%M%S"),
        format.extension()
    )
}

/// The most of a file each frame of its body holds, so that a connection
/// that copies frames into its own buffer copies this much at a time, and
/// takes more only once the client has read what it holds.
const FILE_FRAME: usize = 64 << 10;

/// A file's body, sent a frame at a time.
struct FileBody(Bytes);

impl HttpBody for FileBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let rest = &mut self.get_mut().0;
        if rest.is_empty() {
            return Poll::Ready(None);
        }
        let frame = rest.split_to(rest.len().min(FILE_FRAME));
        Poll::Ready(Some(Ok(Frame::data(frame))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.len() as u64)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::{Arc, OnceLock, Weak};
    use std::time::Duration;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use sha2::{Digest, Sha256};
    use solana_pubkey::Pubkey;
    use tower::ServiceExt;

    use super::*;
    use crate::analysis::definition::tests::AWARDS_REPORT;
    use crate::analysis::export::tests::{read_csv, read_xlsx};
    use crate::analysis::export::Limits;
    use crate::analysis::runner::Analyses;
    use crate::api::credentials::tests::{send, sign_in, worker, worker_with, Admin, Worker};
    use crate::api::grants::tests::{analysis_pool, analyst, execute_drt_config, ANALYSIS};
    use crate::auth::entra::mint::Spec;
    use crate::auth::entra::tests::{config, entra_key};
    use crate::blockchain::drt::pda::derive_grant_pda;
    use crate::budget::Budget;
    use crate::data_validation::tests::{awards_schema, AWARDS_HEADER};
    use crate::storage::pools::GrantScope;
    use crate::storage::pools::{Grant, GrantRevocation, Upload, INITIAL};
    use crate::storage::Change;
    use crate::storage::{Storage, StorageKeys, StoreError};
    use crate::store::files::LocalFiles;
    use crate::store::{BoxFuture, Created, ETag, Fetched, Listed, ObjectStore, Replaced};
    use crate::tee::tests::fixed_key;
    use crate::work::Threads;
    use std::collections::BTreeSet;

    /// Employer group Group A's rows.
    pub(crate) const GROUP_A: &[(&str, &str)] = &[("employer_group", "Group A")];
    /// Employer Bank A Network's rows, which are in Group A.
    const NETWORK: &[(&str, &str)] = &[("employer", "Bank A Network")];

    /// Staff number, employer, employer group, award, exam board date.
    const ROWS: [(&str, &str, &str, &str, &str); 5] = [
        ("000123", "Bank A", "Group A", "Certificate", "01/01/2026"),
        ("000124", "Bank A", "Group A", "Diploma", "30/09/2026"),
        (
            "020001",
            "Bank A Network",
            "Group A",
            "Certificate",
            "15/06/2026",
        ),
        ("030001", "Bank B", "Group B", "Certificate", "01/01/2026"),
        ("040001", "Bank C", "Group C", "Advisor", "10/02/2026"),
    ];

    /// An Awards Report pool of `owner`'s whose first upload holds `ROWS`.
    pub(crate) async fn awards_pool(worker: &Worker, owner: &Admin) -> Pubkey {
        let pool_pda = analysis_pool(worker, owner, 1).await;
        let pda = pool_pda.to_string();
        worker
            .storage
            .scripts()
            .put(AWARDS_REPORT.as_bytes())
            .await
            .unwrap();
        let mut csv = format!("{AWARDS_HEADER}\n");
        for (i, (staff, employer, group, award, date)) in ROWS.iter().enumerate() {
            csv.push_str(&format!(
                "{staff},M{i},Mx,Sam,Example,01/01/1990,{employer},{group},{award},Pass,{date}\n"
            ));
        }
        let pools = worker.storage.pools();
        pools
            .put_dataset(&pda, "awards-1", csv.as_bytes())
            .await
            .unwrap();
        let upload = Upload {
            record_id: INITIAL.into(),
            upload_id: "awards-1".into(),
            sha256: hex::encode(Sha256::digest(csv.as_bytes())),
            rows: ROWS.len() as u64,
            bytes: Some(csv.len() as u64),
            uploaded_by: owner.user_id.clone(),
            uploaded_at: Utc::now(),
            signature: None,
            commitment: None,
        };
        pools
            .update::<ApiError>(&pda, |doc| {
                doc.schema = awards_schema();
                doc.initial = Some(upload.clone());
                Ok(Change::Changed)
            })
            .await
            .unwrap();
        pool_pda
    }

    /// `analyst` holds an active grant to the pool's analysis, which the
    /// chain shows, seeing the rows of `targets` (key, value).
    pub(crate) async fn grant(
        worker: &Worker,
        pool_pda: &Pubkey,
        analyst: &str,
        targets: &[(&str, &str)],
    ) {
        let targets: BTreeSet<Target> = targets
            .iter()
            .map(|(key, value)| Target {
                key: key.to_string(),
                value: value.to_string(),
            })
            .collect();
        let commitment: [u8; 32] = Sha256::digest(analyst).into();
        worker.chain.grant(
            derive_grant_pda(&commitment).0,
            execute_drt_config(pool_pda),
        );
        worker
            .storage
            .pools()
            .update::<ApiError>(&pool_pda.to_string(), |doc| {
                doc.grants.push(Grant {
                    grant_id: format!("g-{analyst}"),
                    analyst: analyst.into(),
                    drt_name: ANALYSIS.into(),
                    commitment: hex::encode(commitment),
                    granted_by: "admin".into(),
                    granted_at: Utc::now(),
                    staged_generation: None,
                    signature: Some("sig-grant".into()),
                    revoked: None,
                    scopes: if targets.is_empty() {
                        Vec::new()
                    } else {
                        vec![GrantScope {
                            targets: targets.clone(),
                            set_by: "admin".into(),
                            set_at: Utc::now(),
                            change_id: format!("g-{analyst}"),
                        }]
                    },
                });
                Ok(Change::Changed)
            })
            .await
            .unwrap();
    }

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

    fn column(page: &Value, name: &str) -> Vec<String> {
        page["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r[name].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn an_analyst_sees_their_employers_rows_and_an_admin_every_row() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (group_a, group_a_id) = analyst(&worker.app, "oid-group-a").await;
        let (network, network_id) = analyst(&worker.app, "oid-network").await;
        grant(&worker, &pool_pda, &group_a_id, GROUP_A).await;
        grant(&worker, &pool_pda, &network_id, NETWORK).await;
        let base = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        let query = format!("{base}/query");

        // Group A includes its employer Bank A Network; newest first by default.
        let (status, _, page) = send(&worker.app, post(&query, &group_a, &json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(
            (&page["total_matched"], &page["limit"], &page["offset"]),
            (&json!(3), &json!(100), &json!(0))
        );
        assert_eq!(
            column(&page, "staff_number"),
            ["000124", "020001", "000123"]
        );
        assert!(column(&page, "employer_group")
            .iter()
            .all(|g| g == "Group A"));
        assert!(page["rows"][0].get("_record_id").is_none());

        let filtered = json!({
            "filters": {
                "award": { "mode": "selected", "values": ["Certificate"] },
                "exam_board_date": { "from": "01/01/2026", "to": "15/06/2026" },
                "staff_number": { "mode": "all" },
            },
            "sort": { "field": "staff_number", "direction": "asc" },
            "pagination": { "limit": 1, "offset": 1 },
        });
        let (status, _, page) = send(&worker.app, post(&query, &group_a, &filtered)).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["total_matched"], 2);
        assert_eq!(column(&page, "staff_number"), ["020001"]);

        let (_, _, page) = send(&worker.app, post(&query, &network, &json!({}))).await;
        assert_eq!(column(&page, "employer"), ["Bank A Network"]);
        let (_, _, page) = send(&worker.app, post(&query, &owner.token, &json!({}))).await;
        assert_eq!(page["total_matched"], 5);

        // Options and searches come from the caller's rows only.
        let (status, _, options) = send(
            &worker.app,
            post(&format!("{base}/options"), &group_a, &json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        assert_eq!(
            options["options"],
            json!({
                "award": [
                    { "value": "Certificate", "count": 2 },
                    { "value": "Diploma", "count": 1 },
                ],
                "exam_board_date": { "min": "01/01/2026", "max": "30/09/2026" },
            })
        );
        let search = format!("{base}/options/staff_number");
        let body = json!({ "search": "0", "limit": 5 });
        let (_, _, found) = send(&worker.app, post(&search, &group_a, &body)).await;
        assert_eq!(found["values"], json!(["000123", "000124", "020001"]));
        let body = json!({ "search": "03" });
        let (_, _, found) = send(&worker.app, post(&search, &group_a, &body)).await;
        assert_eq!(found["values"], json!([]));

        // The summary names the caller's rows.
        let (status, _, summary) = send(&worker.app, get(&base, &group_a)).await;
        assert_eq!(status, StatusCode::OK, "{summary}");
        assert_eq!(
            summary["scope"],
            json!({ "all": false, "any_of": [[
                { "key": "employer_group", "header": "Employer Group", "value": "Group A" }
            ]] })
        );
        assert_eq!(
            summary["columns"][0],
            json!({ "name": "staff_number", "header": "Staff Number", "type": "text" })
        );
        assert_eq!(summary["columns"].as_array().unwrap().len(), 11);
        assert_eq!(
            summary["default_sort"],
            json!({ "field": "exam_board_date", "direction": "desc" })
        );
        let (_, _, summary) = send(&worker.app, get(&base, &owner.token)).await;
        assert_eq!(summary["scope"]["all"], true);

        // Every options, search and query request is in the analysis log.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let log = worker
            .storage
            .analysis_log()
            .on(&pool_pda.to_string(), &today)
            .await
            .unwrap();
        assert_eq!(log.len(), 7, "{log:#?}");
        assert!(log.iter().all(|r| r.outcome == "success"));
        let filtered_record = log
            .iter()
            .find(|r| r.request.get("pagination").is_some())
            .unwrap();
        assert_eq!(filtered_record.grant_id, Some(format!("g-{group_a_id}")));
        assert_eq!(filtered_record.request["filters"], filtered["filters"]);
        assert_eq!(
            filtered_record.request["ran_with"]["sort"],
            json!({ "field": "staff_number", "direction": "asc" })
        );
        assert_eq!(
            (filtered_record.returned, filtered_record.total_matched),
            (Some(1), Some(2))
        );
        let by_admin = log.iter().find(|r| r.user_id == owner.user_id).unwrap();
        assert!(by_admin.grant_id.is_none());

        // Admins read it; analysts can't.
        let path = format!("/v1/admin/analysis-log?pool_pda={pool_pda}&date={today}");
        let (status, _, read) = send(&worker.app, get(&path, &owner.token)).await;
        assert_eq!(status, StatusCode::OK, "{read}");
        assert_eq!(read["records"], serde_json::to_value(&log).unwrap());
        assert_eq!(
            send(&worker.app, get(&path, &group_a)).await.0,
            StatusCode::FORBIDDEN
        );
        let undated = format!("/v1/admin/analysis-log?pool_pda={pool_pda}&date=2026-10-5");
        assert_eq!(
            send(&worker.app, get(&undated, &owner.token)).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn options_and_searches_follow_the_other_filters() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (group_a, group_a_id) = analyst(&worker.app, "oid-group-a").await;
        grant(&worker, &pool_pda, &group_a_id, GROUP_A).await;
        let base = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        let diploma = json!({ "award": { "mode": "selected", "values": ["Diploma"] } });

        // Within Group A's rows, a Diploma narrows the dates and the staff
        // numbers; the awards stay as they were.
        let options = format!("{base}/options");
        let (status, _, found) = send(
            &worker.app,
            post(&options, &group_a, &json!({ "filters": diploma })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{found}");
        assert_eq!(
            found["options"],
            json!({
                "award": [
                    { "value": "Certificate", "count": 2 },
                    { "value": "Diploma", "count": 1 },
                ],
                "exam_board_date": { "min": "30/09/2026", "max": "30/09/2026" },
            })
        );
        let search = format!("{base}/options/staff_number");
        let body = json!({ "search": "0", "filters": diploma });
        let (status, _, found) = send(&worker.app, post(&search, &group_a, &body)).await;
        assert_eq!(status, StatusCode::OK, "{found}");
        assert_eq!(found["values"], json!(["000124"]));

        // The filters are checked as a query's are, and must be JSON.
        let scoped =
            json!({ "filters": { "employer": { "mode": "selected", "values": ["Bank C"] } } });
        for path in [&options, &search] {
            let (status, _, err) = send(&worker.app, post(path, &group_a, &scoped)).await;
            assert_eq!(
                (status, err["code"].as_str()),
                (StatusCode::BAD_REQUEST, Some("invalid_query")),
                "{path}"
            );
            let text = Request::post(path)
                .header(header::AUTHORIZATION, format!("Bearer {group_a}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("{}"))
                .unwrap();
            assert_eq!(
                send(&worker.app, text).await.0,
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            );
        }

        // The analysis log has each request as it was sent.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let log = worker
            .storage
            .analysis_log()
            .on(&pool_pda.to_string(), &today)
            .await
            .unwrap();
        let searched = log
            .iter()
            .find(|r| r.action == "search" && r.outcome == "success")
            .unwrap();
        assert_eq!(
            searched.request,
            json!({ "filter": "staff_number", "search": "0", "filters": diploma })
        );
        assert_eq!(searched.grant_id, Some(format!("g-{group_a_id}")));
        assert!(log
            .iter()
            .any(|r| r.action == "options" && r.request["filters"] == diploma));
        assert_eq!(
            log.iter().filter(|r| r.outcome == "invalid_query").count(),
            2
        );
    }

    #[tokio::test]
    async fn queries_fail_closed_and_refuse_what_the_analysis_does_not_define() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (granted, granted_id) = analyst(&worker.app, "oid-group-a").await;
        let (ungranted, _) = analyst(&worker.app, "oid-nogrant").await;
        let (untargeted, untargeted_id) = analyst(&worker.app, "oid-untargeted").await;
        let (empty, empty_id) = analyst(&worker.app, "oid-group-d").await;
        let (elsewhere, elsewhere_id) = analyst(&worker.app, "oid-region-e").await;
        // A groups overage marker means nothing: rows come from the grant.
        let mut spec = Spec::valid(&config());
        spec.groups_overage = true;
        let overage = spec.sign(entra_key()).unwrap();
        let overage_id = sign_in(&worker.app, &overage).await;
        let nobody = Spec::valid(&config()).sign(entra_key()).unwrap();
        grant(&worker, &pool_pda, &granted_id, GROUP_A).await;
        grant(&worker, &pool_pda, &overage_id, GROUP_A).await;
        grant(&worker, &pool_pda, &untargeted_id, &[]).await;
        let group_d = &[("employer_group", "Group D")];
        grant(&worker, &pool_pda, &empty_id, group_d).await;
        // Stored targets the analysis can't apply, as a hand-edited
        // document might hold.
        let region = &[("region", "Region E")];
        grant(&worker, &pool_pda, &elsewhere_id, region).await;
        let base = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        let query = format!("{base}/query");

        for (token, body, status, code) in [
            (&ungranted, json!({}), StatusCode::FORBIDDEN, "no_grant"),
            (
                &untargeted,
                json!({}),
                StatusCode::FORBIDDEN,
                "no_employer_scope",
            ),
            (
                &elsewhere,
                json!({}),
                StatusCode::FORBIDDEN,
                "invalid_grant_scope",
            ),
            (&nobody, json!({}), StatusCode::FORBIDDEN, "no_grant"),
            (
                &granted,
                json!({ "scope": { "employer_group": "Group C" } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "filters": { "employer_group": { "mode": "selected", "values": ["Group C"] } } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "filters": { "award": { "mode": "selected", "values": [] } } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "sort": { "field": "employer_id", "direction": "asc" } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "pagination": { "limit": 501 } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
        ] {
            let (got, _, err) = send(&worker.app, post(&query, token, &body)).await;
            assert_eq!(
                (got, err["code"].as_str()),
                (status, Some(code)),
                "{body}: {err}"
            );
        }

        let (status, _, page) = send(&worker.app, post(&query, &overage, &json!({}))).await;
        assert_eq!(
            (status, &page["total_matched"]),
            (StatusCode::OK, &json!(3))
        );

        // A target no row holds gets an empty page.
        let (status, _, page) = send(&worker.app, post(&query, &empty, &json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(
            (&page["total_matched"], &page["rows"]),
            (&json!(0), &json!([]))
        );

        // Other analyses, pools, filters, parameters and bodies.
        for (path, status) in [
            (
                format!("/v1/drt/pools/{pool_pda}/analyses/mean/query"),
                StatusCode::NOT_FOUND,
            ),
            (
                format!(
                    "/v1/drt/pools/{}/analyses/{ANALYSIS}/query",
                    Pubkey::new_unique()
                ),
                StatusCode::NOT_FOUND,
            ),
        ] {
            assert_eq!(
                send(&worker.app, post(&path, &granted, &json!({}))).await.0,
                status,
                "{path}"
            );
        }
        for (filter, body) in [
            ("award", json!({ "search": "C" })),
            ("staff_number", json!({ "search": "0", "scope": "all" })),
        ] {
            let path = format!("{base}/options/{filter}");
            let (status, _, err) = send(&worker.app, post(&path, &granted, &body)).await;
            assert_eq!(
                (status, err["code"].as_str()),
                (StatusCode::BAD_REQUEST, Some("invalid_query")),
                "{body}"
            );
        }
        let text = Request::post(&query)
            .header(header::AUTHORIZATION, format!("Bearer {granted}"))
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            send(&worker.app, text).await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        // A revoked grant runs nothing.
        worker
            .storage
            .pools()
            .update::<ApiError>(&pool_pda.to_string(), |doc| {
                let grant = doc
                    .grants
                    .iter_mut()
                    .find(|g| g.analyst == granted_id)
                    .unwrap();
                grant.revoked = Some(GrantRevocation {
                    revocation_id: "r-1".into(),
                    revoked_by: "admin".into(),
                    revoked_at: Utc::now(),
                    signature: None,
                    generation: None,
                });
                Ok(Change::Changed)
            })
            .await
            .unwrap();
        let (status, _, err) = send(&worker.app, post(&query, &granted, &json!({}))).await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("no_grant"))
        );

        // The refusals of this pool's analysis are in the analysis log too.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let log = worker
            .storage
            .analysis_log()
            .on(&pool_pda.to_string(), &today)
            .await
            .unwrap();
        let outcomes: BTreeMap<&str, usize> = log.iter().fold(BTreeMap::new(), |mut counts, r| {
            *counts.entry(r.outcome.as_str()).or_default() += 1;
            counts
        });
        assert_eq!(outcomes["no_grant"], 3);
        assert_eq!(outcomes["no_employer_scope"], 1);
        assert_eq!(outcomes["invalid_grant_scope"], 1);
        assert_eq!(outcomes["invalid_query"], 7);
        let override_attempt = log
            .iter()
            .find(|r| r.request.get("scope").is_some())
            .expect("the scope override is recorded as sent");
        assert_eq!(override_attempt.outcome, "invalid_query");
    }

    #[tokio::test]
    async fn every_query_is_logged_under_an_id_of_the_workers() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let query = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}/query");
        const CHOSEN: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

        // Two queries under one request ID that the caller chose.
        for offset in [0, 1] {
            let page = json!({ "pagination": { "limit": 1, "offset": offset } });
            let mut request = post(&query, &owner.token, &page);
            request.headers_mut().insert(
                crate::request_id::REQUEST_ID_HEADER,
                CHOSEN.parse().unwrap(),
            );
            let (status, _, body) = send(&worker.app, request).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["offset"], offset);
        }
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let log = worker
            .storage
            .analysis_log()
            .on(&pool_pda.to_string(), &today)
            .await
            .unwrap();
        assert_eq!(log.len(), 2, "{log:?}");
        assert!(log.iter().all(|r| r.request_id == CHOSEN));
        assert_ne!(log[0].event_id, log[1].event_id);
        let offsets: BTreeSet<String> = log
            .iter()
            .map(|r| r.request["pagination"]["offset"].to_string())
            .collect();
        assert_eq!(offsets, BTreeSet::from(["0".into(), "1".into()]));

        // A record that can't be stored withholds the result: in another
        // pool, an object stands where its log directory would go.
        let blocked = awards_pool(&worker, &owner).await;
        let in_the_way = worker
            .storage
            .state()
            .create_uncached(&format!("audit/analyses/{blocked}"), b"in the way")
            .await
            .unwrap();
        assert!(matches!(in_the_way, crate::store::Created::New(_)));
        let query = format!("/v1/drt/pools/{blocked}/analyses/{ANALYSIS}/query");
        let (status, _, body) = send(&worker.app, post(&query, &owner.token, &json!({}))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["code"], "analysis_log_unavailable");
        assert!(body.get("rows").is_none());
    }

    #[tokio::test]
    async fn an_analyst_needs_the_chain_to_show_their_grant() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (shown, shown_id) = analyst(&worker.app, "oid-shown").await;
        let (unseen, unseen_id) = analyst(&worker.app, "oid-unseen").await;
        grant(&worker, &pool_pda, &shown_id, GROUP_A).await;
        grant(&worker, &pool_pda, &unseen_id, GROUP_A).await;
        // The document says active, but the chain has no Grant: as after a
        // restore of an older pool document undid a revocation.
        let commitment: [u8; 32] = Sha256::digest(&unseen_id).into();
        worker.chain.close(&derive_grant_pda(&commitment).0);
        let query = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}/query");

        let (status, _, page) = send(&worker.app, post(&query, &shown, &json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let (status, _, refused) = send(&worker.app, post(&query, &unseen, &json!({}))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert_eq!(refused["code"], "grant_not_live");

        let mine = |token: String| {
            let app = worker.app.clone();
            async move {
                let (status, _, mine) = send(&app, get("/v1/drt/me/analyses", &token)).await;
                assert_eq!(status, StatusCode::OK, "{mine}");
                mine["analyses"].as_array().unwrap().len()
            }
        };
        assert_eq!(mine(shown.clone()).await, 1);
        assert_eq!(mine(unseen.clone()).await, 0, "only grants the chain shows");

        // The log ties each query to the chain reading that allowed it.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let log = worker
            .storage
            .analysis_log()
            .on(&pool_pda.to_string(), &today)
            .await
            .unwrap();
        let allowed = log.iter().find(|r| r.user_id == shown_id).unwrap();
        assert_eq!(allowed.chain_slot, Some(1));
        assert!(allowed.chain_verified_at.is_some());
        let denied = log.iter().find(|r| r.user_id == unseen_id).unwrap();
        assert_eq!(denied.outcome, "grant_not_live");

        // The grants list shows what the chain showed.
        let grants = format!("/v1/drt/pools/{pool_pda}/grants");
        let (_, _, listed) = send(&worker.app, get(&grants, &owner.token)).await;
        let on_chain = |analyst: &str| {
            listed["grants"]
                .as_array()
                .unwrap()
                .iter()
                .find(|g| g["analyst_user_id"] == analyst)
                .map(|g| g["on_chain"].clone())
                .unwrap()
        };
        assert_eq!(on_chain(&shown_id), "live");
        assert_eq!(on_chain(&unseen_id), "closed");
    }

    #[tokio::test]
    async fn a_grants_targets_decide_its_rows_from_the_next_request_on() {
        let worker = worker();
        // Each edit is a change of the pool's, anchored on-chain.
        worker
            .chain
            .lands
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (ana, ana_id) = analyst(&worker.app, "oid-ana").await;
        let (broken, broken_id) = analyst(&worker.app, "oid-broken").await;
        grant(&worker, &pool_pda, &ana_id, GROUP_A).await;
        grant(&worker, &pool_pda, &broken_id, &[("region", "Region E")]).await;
        let query = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}/query");
        let set_scope = |analyst: &str, revision: usize, scope: Value| {
            let body = json!({ "grant_id": format!("g-{analyst}"), "analyst_user_id": analyst,
                "analysis_id": ANALYSIS, "revision": revision, "scope": scope });
            Request::post(format!("/v1/drt/pools/{pool_pda}/grant-scope"))
                .header(header::AUTHORIZATION, format!("Bearer {}", owner.token))
                .header(
                    &crate::idempotency::KEY_HEADER,
                    uuid::Uuid::new_v4().to_string(),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let matched = |token: String| {
            let app = worker.app.clone();
            let query = query.clone();
            async move {
                let (status, _, page) = send(&app, post(&query, &token, &json!({}))).await;
                (status, page["total_matched"].clone(), page["code"].clone())
            }
        };

        assert_eq!(matched(ana.clone()).await.1, 3);
        let bank_b = json!([{ "key": "employer", "value": "Bank B" }]);
        let (status, _, changed) = send(&worker.app, set_scope(&ana_id, 1, bank_b)).await;
        assert_eq!(status, StatusCode::OK, "{changed}");
        assert_eq!(
            matched(ana.clone()).await.1,
            1,
            "the next query sees Bank B only"
        );

        // Targets the analysis can't apply see nothing until they're set again.
        assert_eq!(
            matched(broken.clone()).await,
            (
                StatusCode::FORBIDDEN,
                Value::Null,
                json!("invalid_grant_scope")
            )
        );
        let (status, _, repaired) = send(
            &worker.app,
            set_scope(
                &broken_id,
                1,
                json!([{ "key": "employer_group", "value": "Group B" }]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{repaired}");
        assert_eq!(matched(broken).await.1, 1);

        // The summary lists every target the grant sees.
        let base = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        let (_, _, summary) = send(&worker.app, get(&base, &ana)).await;
        assert_eq!(
            summary["scope"]["any_of"],
            json!([[{ "key": "employer", "header": "Employer", "value": "Bank B" }]])
        );
    }

    #[tokio::test]
    async fn a_scope_check_counts_what_targets_give_each_row_once() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (ana, _) = analyst(&worker.app, "oid-ana").await;
        let path = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}/scope-check");
        let check = |token: &str, scope: Value| post(&path, token, &json!({ "scope": scope }));

        let (status, _, values) = send(&worker.app, check(&owner.token, json!([]))).await;
        assert_eq!(status, StatusCode::OK, "{values}");
        assert_eq!(
            (&values["total_rows"], &values["rows"]),
            (&json!(5), &json!(0))
        );
        assert_eq!(
            values["keys"],
            json!([
                { "key": "employer", "header": "Employer", "values": [
                    { "value": "Bank A", "rows": 2 }, { "value": "Bank A Network", "rows": 1 },
                    { "value": "Bank B", "rows": 1 }, { "value": "Bank C", "rows": 1 },
                ] },
                { "key": "employer_group", "header": "Employer Group", "values": [
                    { "value": "Group A", "rows": 3 }, { "value": "Group B", "rows": 1 },
                    { "value": "Group C", "rows": 1 },
                ] },
            ])
        );

        let overlapping = json!([
            { "key": "employer_group", "value": "Group A" },
            { "key": "employer", "value": "Bank A Network" },
            { "key": "employer", "value": "Bank B" },
        ]);
        let (_, _, counted) = send(&worker.app, check(&owner.token, overlapping)).await;
        assert_eq!(counted["rows"], 4, "Bank A Network is in Group A");
        assert_eq!(counted["target_rows"], json!([3, 1, 1]));
        assert_eq!(counted["warnings"], json!([]));

        let misspelt = json!([{ "key": "employer_group", "value": "group a" }]);
        let (_, _, flagged) = send(&worker.app, check(&owner.token, misspelt)).await;
        assert_eq!(flagged["rows"], 0);
        assert_eq!(
            flagged["warnings"],
            json!([{ "code": "no_rows", "key": "employer_group", "value": "group a",
                "near": ["Group A"] }])
        );

        let (status, _, err) = send(
            &worker.app,
            check(&owner.token, json!([{ "key": "region", "value": "E" }])),
        )
        .await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_scope"))
        );
        let (status, _, _) = send(&worker.app, check(&ana, json!([]))).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "analysts don't see other employers' values"
        );
    }

    /// The analysis log's records of `pool_pda` today.
    async fn logged_today(worker: &Worker, pool_pda: &Pubkey) -> Vec<AnalysisRecord> {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        worker
            .storage
            .analysis_log()
            .on(&pool_pda.to_string(), &today)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_open_returns_the_options_and_first_page_and_is_logged_once() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let path = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");

        // A description alone runs no page and records nothing.
        let (status, _, described) = send(&worker.app, get(&path, &owner.token)).await;
        assert_eq!(status, StatusCode::OK, "{described}");
        assert!(described.get("page").is_none() && described.get("options").is_none());
        assert!(logged_today(&worker, &pool_pda).await.is_empty());

        let open = format!("{path}?include=page&distinct=membership_number");
        let (status, _, opened) = send(&worker.app, get(&open, &owner.token)).await;
        assert_eq!(status, StatusCode::OK, "{opened}");
        assert_eq!(opened["columns"], described["columns"]);
        assert_eq!(
            opened["options"]["exam_board_date"],
            json!({ "min": "01/01/2026", "max": "30/09/2026" })
        );
        assert!(
            opened["options"].get("staff_number").is_none(),
            "searches stay out"
        );
        assert_eq!(opened["page"]["total_matched"], 5);
        assert_eq!(
            opened["searches"]["staff_number"],
            json!(["000123", "000124", "020001", "030001", "040001"])
        );
        assert_eq!(
            opened["searches"]["membership_number"],
            json!(["M0", "M1", "M2", "M3", "M4"])
        );
        assert_eq!(
            opened["page"]["distinct"],
            json!({ "membership_number": 5 })
        );

        // The page is the one a query with no filters returns.
        let query = format!("{path}/query");
        let asked = json!({ "distinct": ["membership_number"] });
        let (_, _, page) = send(&worker.app, post(&query, &owner.token, &asked)).await;
        assert_eq!(opened["page"], page);

        let log = logged_today(&worker, &pool_pda).await;
        let opens: Vec<_> = log.iter().filter(|r| r.action == "open").collect();
        assert_eq!(opens.len(), 1, "{log:?}");
        let open = opens[0];
        assert_eq!(open.outcome, "success");
        assert_eq!(open.request["filters"], json!({}));
        assert_eq!(
            open.request["sort"],
            json!({ "field": "exam_board_date", "direction": "desc" })
        );
        assert_eq!(
            open.request["pagination"],
            json!({ "limit": 100, "offset": 0 })
        );
        assert_eq!(open.request["distinct"], json!(["membership_number"]));
        assert_eq!((open.returned, open.total_matched), (Some(5), Some(5)));
    }

    #[tokio::test]
    async fn an_open_takes_include_page_and_its_distinct_only() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let path = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        for (query, message) in [
            ("distinct=award", "distinct needs include=page"),
            ("include=rows", "include takes page, once"),
            ("include=page&include=page", "include takes page, once"),
            (
                "include=page&limit=5",
                "the analysis takes no parameter limit",
            ),
            (
                "include=page&distinct=_record_id",
                "awards-report-v1 can't count the distinct values of _record_id",
            ),
        ] {
            let (status, _, body) =
                send(&worker.app, get(&format!("{path}?{query}"), &owner.token)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
            assert_eq!(body["code"], "invalid_query", "{query}");
            assert_eq!(body["error"], message, "{query}");
        }
    }

    #[tokio::test]
    async fn an_open_follows_the_analysts_grant() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (group_a, group_a_id) = analyst(&worker.app, "oid-group-a").await;
        let (ungranted, _) = analyst(&worker.app, "oid-ungranted").await;
        grant(&worker, &pool_pda, &group_a_id, GROUP_A).await;
        let open = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}?include=page");

        let (status, _, opened) = send(&worker.app, get(&open, &group_a)).await;
        assert_eq!(status, StatusCode::OK, "{opened}");
        assert_eq!(opened["page"]["total_matched"], 3);
        assert_eq!(
            opened["searches"]["staff_number"],
            json!(["000123", "000124", "020001"]),
            "the grant's rows only"
        );
        assert!(column(&opened["page"], "employer_group")
            .iter()
            .all(|g| g == "Group A"));
        assert_eq!(
            opened["options"]["award"],
            json!([
                { "value": "Certificate", "count": 2 },
                { "value": "Diploma", "count": 1 }
            ])
        );

        let (status, _, refused) = send(&worker.app, get(&open, &ungranted)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert_eq!(refused["code"], "no_grant");
        assert!(refused.get("page").is_none());
    }

    #[tokio::test]
    async fn an_open_that_cant_be_logged_returns_nothing() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let blocked = awards_pool(&worker, &owner).await;
        worker
            .storage
            .state()
            .create_uncached(&format!("audit/analyses/{blocked}"), b"in the way")
            .await
            .unwrap();
        let path = format!("/v1/drt/pools/{blocked}/analyses/{ANALYSIS}");
        let (status, _, body) = send(
            &worker.app,
            get(&format!("{path}?include=page"), &owner.token),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["code"], "analysis_log_unavailable");
        assert!(body.get("page").is_none());

        // A description isn't logged, so it still answers.
        let (status, _, body) = send(&worker.app, get(&path, &owner.token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn an_open_counts_against_the_per_user_limit_and_a_description_does_not() {
        let worker = crate::api::credentials::tests::worker_with(|state| {
            state.limiter =
                std::sync::Arc::new(crate::edge::Limiter::new(&crate::config::RateLimits {
                    ip_per_second: 1000,
                    ip_burst: 1000,
                    user_mutations_per_second: 1,
                }));
        });
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let mut spec = Spec::valid(&config());
        spec.oid = "oid-reader".into();
        spec.roles = vec!["Admin".into()];
        let reader = spec.sign(entra_key()).unwrap();
        sign_in(&worker.app, &reader).await;

        let path = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        for _ in 0..3 {
            let (status, _, body) = send(&worker.app, get(&path, &reader)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        let open = format!("{path}?include=page");
        let (status, _, body) = send(&worker.app, get(&open, &reader)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _, body) = send(&worker.app, get(&open, &reader)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(body["code"], "rate_limited");
    }

    fn export_path(pool_pda: &Pubkey) -> String {
        format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}/export")
    }

    /// A response's status and headers, its body's bytes, and the length
    /// its body declares.
    async fn download(
        app: &Router,
        request: Request<Body>,
    ) -> (StatusCode, HeaderMap, Vec<u8>, Option<u64>) {
        let response = app.clone().oneshot(request).await.unwrap();
        let length = response.body().size_hint().exact();
        let (parts, body) = response.into_parts();
        let body = to_bytes(body, 64 << 20).await.unwrap();
        (parts.status, parts.headers, body.to_vec(), length)
    }

    fn error_of(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap_or_default()
    }

    fn stage(record: &AnalysisRecord) -> Option<&str> {
        record.export.as_ref().map(|e| e.stage.as_str())
    }

    /// The records of export `export_id`: the one written when it was
    /// asked for and the one written when it ended.
    fn pair<'a>(
        log: &'a [AnalysisRecord],
        export_id: &str,
    ) -> (&'a AnalysisRecord, &'a AnalysisRecord) {
        let records: Vec<_> = log
            .iter()
            .filter(|r| r.export.as_ref().is_some_and(|e| e.export_id == export_id))
            .collect();
        assert_eq!(records.len(), 2, "{log:#?}");
        let of = |s| *records.iter().find(|r| stage(r) == Some(s)).unwrap();
        let (requested, finished) = (of("requested"), of("finished"));
        assert_eq!(requested.outcome, "requested");
        assert_ne!(requested.event_id, finished.event_id);
        let (asked, ended) = (
            requested.export.as_ref().unwrap(),
            finished.export.as_ref().unwrap(),
        );
        assert_eq!(asked.requested_at, ended.requested_at);
        assert_eq!(
            (&asked.pool_name, asked.format),
            (&ended.pool_name, ended.format)
        );
        assert!(asked.result.is_none() && ended.result.is_some());
        (requested, finished)
    }

    /// The finished records of every export in `log`.
    fn finished(log: &[AnalysisRecord]) -> Vec<&AnalysisRecord> {
        log.iter()
            .filter(|r| stage(r) == Some("finished"))
            .collect()
    }

    /// A worker whose analyses are `analyses`.
    fn worker_exporting(analyses: Analyses) -> (Worker, Arc<Analyses>) {
        let analyses = Arc::new(analyses);
        let shared = analyses.clone();
        (worker_with(move |state| state.analyses = shared), analyses)
    }

    #[tokio::test]
    async fn an_export_is_every_matching_row_as_a_file_and_is_logged_twice() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (group_a, group_a_id) = analyst(&worker.app, "oid-group-a").await;
        grant(&worker, &pool_pda, &group_a_id, GROUP_A).await;
        let base = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        let (_, _, summary) = send(&worker.app, get(&base, &owner.token)).await;
        let named = |field: &str| -> Vec<String> {
            summary["columns"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c[field].as_str().unwrap().to_string())
                .collect()
        };
        let (columns, headers) = (named("name"), named("header"));

        // The file holds the rows the query pages through, in its sort.
        let asked = json!({
            "filters": { "award": { "mode": "selected", "values": ["Certificate"] } },
            "sort": { "field": "staff_number", "direction": "desc" },
        });
        let mut paged = asked.clone();
        paged["pagination"] = json!({ "limit": 500 });
        let (_, _, page) = send(
            &worker.app,
            post(&format!("{base}/query"), &owner.token, &paged),
        )
        .await;
        let mut expected = vec![headers.clone()];
        expected.extend(page["rows"].as_array().unwrap().iter().map(|row| {
            columns
                .iter()
                .map(|c| row[c].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        }));
        assert_eq!(expected.len(), 4, "{page}");

        let path = format!("{base}/export");
        let mut exports = Vec::new();
        for format in [Format::Csv, Format::Xlsx] {
            let mut body = asked.clone();
            body["format"] = json!(format);
            let (status, sent, file, length) =
                download(&worker.app, post(&path, &owner.token, &body)).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&file));
            let cells = match format {
                Format::Csv => read_csv(&file),
                Format::Xlsx => read_xlsx(&file),
            };
            assert_eq!(cells, expected, "{format:?}");
            assert_eq!(length, Some(file.len() as u64));
            assert_eq!(sent[header::CONTENT_TYPE], format.content_type());
            assert_eq!(sent[header::CACHE_CONTROL], "no-store");
            let disposition = sent[header::CONTENT_DISPOSITION].to_str().unwrap();
            let name = disposition
                .strip_prefix("attachment; filename=\"awards-report-v1-")
                .and_then(|n| n.strip_suffix(&format!(".{}\"", format.extension())))
                .unwrap_or_else(|| panic!("{disposition}"));
            assert!(
                chrono::NaiveDateTime::parse_from_str(name, "%Y%m%d-%H%M%S").is_ok(),
                "{disposition}"
            );
            let export_id = sent[&EXPORT_ID_HEADER].to_str().unwrap().to_string();
            exports.push((format, body, file.len(), export_id));
        }

        // An analyst's file holds their rows only, in the default sort.
        let (status, sent, file, _) = download(
            &worker.app,
            post(&path, &group_a, &json!({ "format": "csv" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let rows = read_csv(&file);
        let group = columns.iter().position(|c| c == "employer_group").unwrap();
        let staff: Vec<_> = rows[1..].iter().map(|r| r[0].as_str()).collect();
        assert_eq!(staff, ["000124", "020001", "000123"]);
        assert!(rows[1..].iter().all(|r| r[group] == "Group A"));
        let analysts = sent[&EXPORT_ID_HEADER].to_str().unwrap().to_string();

        // Each export has its two records, the request as it was sent and
        // then how it ended.
        let log = logged_today(&worker, &pool_pda).await;
        assert_eq!(log.len(), 7, "a query and three exports: {log:#?}");
        for (format, body, bytes, export_id) in &exports {
            let (requested, finished) = pair(&log, export_id);
            assert_eq!(&requested.request, body);
            let event = requested.export.as_ref().unwrap();
            assert_eq!(event.format, Some(*format));
            assert_eq!(event.pool_name, summary["pool_name"].as_str().unwrap());
            assert_eq!(finished.outcome, "success");
            assert_eq!(
                (finished.returned, finished.total_matched),
                (Some(3), Some(3))
            );
            assert_eq!(finished.request["ran_with"]["sort"], asked["sort"]);
            let ended = finished.export.as_ref().unwrap();
            assert_eq!(ended.result.as_deref(), Some("success"));
            assert_eq!(ended.bytes, Some(*bytes as u64));
            assert!(ended.duration_ms.is_some());
            assert!(finished.grant_id.is_none());
        }
        let (requested, finished) = pair(&log, &analysts);
        assert_eq!(requested.user_id, group_a_id);
        assert!(requested.grant_id.is_none(), "checked after it's recorded");
        assert_eq!(finished.grant_id, Some(format!("g-{group_a_id}")));
        assert!(finished.chain_slot.is_some());
        assert_eq!(
            finished.request["ran_with"]["sort"],
            json!({ "field": "exam_board_date", "direction": "desc" })
        );
    }

    #[tokio::test]
    async fn an_export_takes_a_querys_filters_and_sort_only_and_fails_closed() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (granted, granted_id) = analyst(&worker.app, "oid-group-a").await;
        let (ungranted, _) = analyst(&worker.app, "oid-nogrant").await;
        let (unseen, unseen_id) = analyst(&worker.app, "oid-unseen").await;
        let (revoked, revoked_id) = analyst(&worker.app, "oid-revoked").await;
        for id in [&granted_id, &unseen_id, &revoked_id] {
            grant(&worker, &pool_pda, id, GROUP_A).await;
        }
        let commitment: [u8; 32] = Sha256::digest(&unseen_id).into();
        worker.chain.close(&derive_grant_pda(&commitment).0);
        worker
            .storage
            .pools()
            .update::<ApiError>(&pool_pda.to_string(), |doc| {
                let grant = doc
                    .grants
                    .iter_mut()
                    .find(|g| g.analyst == revoked_id)
                    .unwrap();
                grant.revoked = Some(GrantRevocation {
                    revocation_id: "r-1".into(),
                    revoked_by: "admin".into(),
                    revoked_at: Utc::now(),
                    signature: None,
                    generation: None,
                });
                Ok(Change::Changed)
            })
            .await
            .unwrap();
        let path = export_path(&pool_pda);

        let refusals = [
            (
                &granted,
                json!({ "format": "csv", "scope": { "employer_group": "Group C" } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "format": "csv", "pagination": { "limit": 10 } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "format": "xlsx", "distinct": ["membership_number"] }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "format": "csv", "filters": { "employer_group": { "mode": "selected", "values": ["Group C"] } } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "format": "csv", "sort": { "field": "_record_id", "direction": "asc" } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "format": "pdf" }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({}),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &ungranted,
                json!({ "format": "csv" }),
                StatusCode::FORBIDDEN,
                "no_grant",
            ),
            (
                &revoked,
                json!({ "format": "csv" }),
                StatusCode::FORBIDDEN,
                "no_grant",
            ),
            (
                &unseen,
                json!({ "format": "xlsx" }),
                StatusCode::FORBIDDEN,
                "grant_not_live",
            ),
        ];
        for (token, body, status, code) in &refusals {
            let (got, sent, file, _) = download(&worker.app, post(&path, token, body)).await;
            let err = error_of(&file);
            assert_eq!(
                (got, err["code"].as_str()),
                (*status, Some(*code)),
                "{body}: {err}"
            );
            assert!(sent.get(&EXPORT_ID_HEADER).is_none());
        }

        // A body that isn't JSON is refused before it's recorded.
        let text = Request::post(&path)
            .header(header::AUTHORIZATION, format!("Bearer {granted}"))
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(r#"{"format":"csv"}"#))
            .unwrap();
        assert_eq!(
            download(&worker.app, text).await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        // A filter no row matches makes a file of the header only.
        let later = json!({ "exam_board_date": { "from": "01/01/2027" } });
        for format in [Format::Csv, Format::Xlsx] {
            let body = json!({ "format": format, "filters": later });
            let (status, _, file, _) = download(&worker.app, post(&path, &granted, &body)).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&file));
            let cells = match format {
                Format::Csv => read_csv(&file),
                Format::Xlsx => read_xlsx(&file),
            };
            assert_eq!(cells.len(), 1, "{cells:?}");
            assert_eq!(cells[0][0], "Staff Number");
        }

        // Each refusal is recorded as asked for and as refused.
        let log = logged_today(&worker, &pool_pda).await;
        let ended = finished(&log);
        assert_eq!(ended.len(), refusals.len() + 2, "{log:#?}");
        assert_eq!(log.len(), 2 * ended.len());
        for (_, body, _, code) in &refusals {
            let record = ended
                .iter()
                .find(|r| {
                    let asked = r.request.as_object().map(|o| {
                        o.iter()
                            .filter(|(k, _)| *k != "ran_with")
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect::<serde_json::Map<_, _>>()
                    });
                    asked.as_ref() == body.as_object() && r.outcome == *code
                })
                .unwrap_or_else(|| panic!("{body}: {log:#?}"));
            let (requested, _) = pair(&log, &record.export.as_ref().unwrap().export_id);
            assert_eq!(&requested.request, body);
            assert_eq!(
                record.export.as_ref().unwrap().result.as_deref(),
                Some("refused")
            );
        }
        let pdf = log.iter().find(|r| r.request["format"] == "pdf").unwrap();
        assert_eq!(pdf.export.as_ref().unwrap().format, None);
        let empty: Vec<_> = ended.iter().filter(|r| r.outcome == "success").collect();
        assert_eq!(empty.len(), 2);
        assert!(empty
            .iter()
            .all(|r| (r.returned, r.total_matched) == (Some(0), Some(0))));
    }

    #[tokio::test]
    async fn an_export_over_a_limit_is_refused_whole() {
        let limited = |limits| Analyses::default().with_exports(limits, Duration::from_secs(5));
        let cases = [
            (
                limited(Limits {
                    max_rows: 4,
                    ..Limits::default()
                }),
                Format::Csv,
                "export_too_many_rows",
                "refused",
            ),
            (
                limited(Limits {
                    max_bytes: 512,
                    ..Limits::default()
                }),
                Format::Xlsx,
                "export_too_large",
                "refused",
            ),
            (
                limited(Limits {
                    deadline: Duration::ZERO,
                    ..Limits::default()
                }),
                Format::Csv,
                "analysis_timeout",
                "timeout",
            ),
            (
                Analyses::new(Arc::new(Budget::new(8 << 20))),
                Format::Csv,
                "too_large_for_memory",
                "refused",
            ),
        ];
        for (analyses, format, code, result) in cases {
            let (worker, analyses) = worker_exporting(analyses);
            let owner = worker.admin("oid-owner").await;
            let pool_pda = awards_pool(&worker, &owner).await;
            let body = json!({ "format": format });
            let (status, sent, file, _) = download(
                &worker.app,
                post(&export_path(&pool_pda), &owner.token, &body),
            )
            .await;
            let err = error_of(&file);
            assert_eq!(
                (status, err["code"].as_str()),
                (StatusCode::UNPROCESSABLE_ENTITY, Some(code)),
                "{err}"
            );
            assert!(sent.get(&EXPORT_ID_HEADER).is_none());
            if code == "export_too_many_rows" {
                assert_eq!(
                    err["error"],
                    "5 rows match, and an export holds at most 4; narrow the filters"
                );
            }
            let log = logged_today(&worker, &pool_pda).await;
            let ended = finished(&log);
            assert_eq!(ended.len(), 1, "{log:#?}");
            assert_eq!(ended[0].outcome, code);
            assert_eq!(
                ended[0].export.as_ref().unwrap().result.as_deref(),
                Some(result)
            );
            assert!(ended[0].export.as_ref().unwrap().bytes.is_none());
            drop(analyses);
        }
    }

    #[tokio::test]
    async fn an_export_waits_for_a_slot_and_then_is_busy() {
        let analyses = Analyses::with_threads(Arc::new(Budget::default()), Threads::new(3))
            .with_exports(Limits::default(), Duration::from_millis(50));
        let (worker, analyses) = worker_exporting(analyses);
        assert_eq!(analyses.export_slots().available_permits(), 1);
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let export = || {
            post(
                &export_path(&pool_pda),
                &owner.token,
                &json!({ "format": "csv" }),
            )
        };

        let slot = analyses
            .export_slots()
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let (status, sent, file, _) = download(&worker.app, export()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_of(&file)["code"], "analysis_busy");
        assert_eq!(sent[header::RETRY_AFTER], "1");
        drop(slot);
        let (status, _, _, _) = download(&worker.app, export()).await;
        assert_eq!(status, StatusCode::OK);

        let log = logged_today(&worker, &pool_pda).await;
        let busy = finished(&log)
            .into_iter()
            .find(|r| r.outcome == "analysis_busy")
            .unwrap();
        assert_eq!(
            busy.export.as_ref().unwrap().result.as_deref(),
            Some("failed")
        );
    }

    /// What `work` comes to, failing the test if that takes over 10 s.
    async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), work)
            .await
            .unwrap_or_else(|_| panic!("{what} took too long"))
    }

    #[tokio::test]
    async fn an_export_whose_client_goes_away_is_logged_as_cancelled() {
        let one_slot = Analyses::with_threads(Arc::new(Budget::default()), Threads::new(2));
        let (worker, analyses) = worker_exporting(one_slot);
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        // The export's table, built first and its turn held, so that the
        // export waits for it.
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        let hash = doc.analysis.as_ref().unwrap().code_hash_hex.clone();
        let def = analyses.definition(&worker.storage, &hash).await.unwrap();
        let table = analyses
            .table(&worker.storage, &doc, &def, &Scope::All)
            .await
            .unwrap();
        let turn = table.turn().await.unwrap();

        let body = json!({ "format": "xlsx" });
        let mut request = tokio::spawn(worker.app.clone().oneshot(post(
            &export_path(&pool_pda),
            &owner.token,
            &body,
        )));
        within("the export taking a slot", async {
            while analyses.export_slots().available_permits() > 0 && !request.is_finished() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(!request.is_finished(), "{:?}", {
            let response = (&mut request).await.unwrap().unwrap();
            let (parts, body) = response.into_parts();
            (parts.status, to_bytes(body, 1 << 20).await.unwrap())
        });
        request.abort();
        let aborted = within("the request stopping", request).await;
        assert!(aborted.unwrap_err().is_cancelled());
        drop(turn);

        // The export's own task records how it ended.
        let ended = within("the export recording its end", async {
            loop {
                let log = logged_today(&worker, &pool_pda).await;
                if let Some(ended) = finished(&log).into_iter().next() {
                    break ended.clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert_eq!(ended.outcome, "cancelled");
        let event = ended.export.as_ref().unwrap();
        assert_eq!(event.result.as_deref(), Some("cancelled"));
        assert!(event.bytes.is_none());
        assert_eq!(analyses.export_slots().available_permits(), 1);
    }

    type Hook = Box<
        dyn Fn(Arc<Storage>, String, usize) -> BoxFuture<'static, Result<(), StoreError>>
            + Send
            + Sync,
    >;

    /// A store that calls `hook` before each analysis log write, with the
    /// worker's storage, the record's path and the write's number from 0.
    /// A write whose hook fails is refused.
    struct Hooked {
        files: LocalFiles,
        storage: OnceLock<Weak<Storage>>,
        writes: AtomicUsize,
        hook: Hook,
    }

    impl ObjectStore for Hooked {
        fn get<'a>(
            &'a self,
            path: &'a str,
            cached: Option<&'a ETag>,
        ) -> BoxFuture<'a, Result<Fetched, StoreError>> {
            self.files.get(path, cached)
        }
        fn put_if_absent<'a>(
            &'a self,
            path: &'a str,
            body: Bytes,
        ) -> BoxFuture<'a, Result<Created, StoreError>> {
            Box::pin(async move {
                if path.contains("audit/analyses/") {
                    let write = self.writes.fetch_add(1, SeqCst);
                    let storage = self.storage.get().and_then(Weak::upgrade).unwrap();
                    (self.hook)(storage, path.to_string(), write).await?;
                }
                self.files.put_if_absent(path, body).await
            })
        }
        fn put_if_match<'a>(
            &'a self,
            path: &'a str,
            body: Bytes,
            etag: &'a ETag,
        ) -> BoxFuture<'a, Result<Replaced, StoreError>> {
            self.files.put_if_match(path, body, etag)
        }
        fn list<'a>(&'a self, dir: &'a str) -> BoxFuture<'a, Result<Vec<Listed>, StoreError>> {
            self.files.list(dir)
        }
    }

    /// A worker on a store that `hook` sees each analysis log write of.
    fn hooked_worker(hook: Hook) -> (Worker, Arc<Analyses>) {
        let store = Arc::new(Hooked {
            files: LocalFiles::temporary(),
            storage: OnceLock::new(),
            writes: AtomicUsize::new(0),
            hook,
        });
        let storage = Arc::new(Storage::new(
            store.clone(),
            StorageKeys::derive(&fixed_key(1)),
            "worker-a".into(),
        ));
        assert!(store.storage.set(Arc::downgrade(&storage)).is_ok());
        let analyses = Arc::new(Analyses::default());
        let shared = analyses.clone();
        let worker = worker_with(move |state| {
            state.storage = storage;
            state.analyses = shared;
        });
        (worker, analyses)
    }

    /// A hook that refuses the writes `refused` picks by number.
    fn refusing(refused: fn(usize) -> bool) -> Hook {
        Box::new(
            move |_, _, write| -> BoxFuture<'static, Result<(), StoreError>> {
                Box::pin(async move {
                    if refused(write) {
                        Err(StoreError::Unavailable("refused by the test".into()))
                    } else {
                        Ok(())
                    }
                })
            },
        )
    }

    #[tokio::test]
    async fn an_export_runs_only_once_recorded_and_is_sent_only_once_its_success_is() {
        let export = |pool_pda: &Pubkey, token: &str| {
            post(&export_path(pool_pda), token, &json!({ "format": "csv" }))
        };

        // A request that can't be recorded runs nothing.
        let (worker, analyses) = hooked_worker(refusing(|write| write == 0));
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (status, sent, file, _) = download(&worker.app, export(&pool_pda, &owner.token)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_of(&file)["code"], "analysis_log_unavailable");
        assert!(sent.get(&EXPORT_ID_HEADER).is_none());
        assert_eq!(analyses.usage().1 .1, 0, "no table was built");
        assert!(logged_today(&worker, &pool_pda).await.is_empty());

        // A success that fails to store once is stored when retried, and sent.
        let (worker, _) = hooked_worker(refusing(|write| write == 1));
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (status, sent, file, _) = download(&worker.app, export(&pool_pda, &owner.token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(read_csv(&file).len(), 6);
        let log = logged_today(&worker, &pool_pda).await;
        let (_, ended) = pair(&log, sent[&EXPORT_ID_HEADER].to_str().unwrap());
        assert_eq!(ended.outcome, "success");

        // One that fails twice is not sent, and no success is recorded.
        let (worker, _) = hooked_worker(refusing(|write| write >= 1));
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (status, sent, file, _) = download(&worker.app, export(&pool_pda, &owner.token)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_of(&file)["code"], "analysis_log_unavailable");
        assert!(sent.get(&EXPORT_ID_HEADER).is_none());
        let log = logged_today(&worker, &pool_pda).await;
        assert_eq!(log.len(), 1, "{log:#?}");
        assert_eq!(log[0].outcome, "requested");
    }

    #[tokio::test]
    async fn a_revocation_recorded_while_an_export_runs_withholds_its_file() {
        // Once the export is recorded, after it read the pool, its grants
        // are revoked, as a revocation landing while it ran would be.
        let (worker, analyses) = hooked_worker(Box::new(
            |storage: Arc<Storage>,
             path: String,
             write|
             -> BoxFuture<'static, Result<(), StoreError>> {
                Box::pin(async move {
                    if write > 0 {
                        return Ok(());
                    }
                    let pool = path
                        .split("audit/analyses/")
                        .nth(1)
                        .and_then(|p| p.split('/').next())
                        .unwrap()
                        .to_string();
                    storage
                        .pools()
                        .update::<ApiError>(&pool, |doc| {
                            for grant in &mut doc.grants {
                                grant.revoked = Some(GrantRevocation {
                                    revocation_id: "r-1".into(),
                                    revoked_by: "admin".into(),
                                    revoked_at: Utc::now(),
                                    signature: None,
                                    generation: None,
                                });
                            }
                            doc.generation += 1;
                            Ok(Change::Changed)
                        })
                        .await
                        .map_err(|e| StoreError::Invalid(e.message))?;
                    Ok(())
                })
            },
        ));
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let (ana, ana_id) = analyst(&worker.app, "oid-ana").await;
        grant(&worker, &pool_pda, &ana_id, GROUP_A).await;

        let body = json!({ "format": "csv" });
        let (status, sent, file, _) =
            download(&worker.app, post(&export_path(&pool_pda), &ana, &body)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_of(&file)["code"], "pool_settling");
        assert!(sent.get(&EXPORT_ID_HEADER).is_none());

        // It ran under the grant it read, and its file was dropped.
        assert_eq!(analyses.usage().1 .1, 1, "its table was built");
        let log = logged_today(&worker, &pool_pda).await;
        let ended = finished(&log);
        assert_eq!(ended.len(), 1, "{log:#?}");
        assert_eq!(ended[0].grant_id, Some(format!("g-{ana_id}")));
        assert_eq!(ended[0].outcome, "pool_settling");
        assert!(ended[0].export.as_ref().unwrap().bytes.is_none());
    }

    #[tokio::test]
    async fn an_exports_file_holds_its_memory_until_its_last_bytes_are_dropped() {
        let (worker, analyses) = worker_exporting(Analyses::default());
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let export = || {
            post(
                &export_path(&pool_pda),
                &owner.token,
                &json!({ "format": "xlsx" }),
            )
        };
        // The first export loads the table, which stays cached.
        let (status, _, _, _) = download(&worker.app, export()).await;
        assert_eq!(status, StatusCode::OK);
        let memory = analyses.memory().clone();
        let free = memory.available();

        let response = worker.app.clone().oneshot(export()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let held = free - memory.available();
        assert!(held >= frame.len().max(1), "{held} bytes held");
        // A connection can hold a frame after it has dropped the body.
        drop(body);
        assert_eq!(free - memory.available(), held);
        drop(frame);
        assert_eq!(memory.available(), free);
    }

    #[tokio::test]
    async fn a_files_body_is_sent_a_frame_at_a_time() {
        let file: Vec<u8> = (0..=255u8).cycle().take(3 * FILE_FRAME + 100).collect();
        let mut body = FileBody(Bytes::from(file.clone()));
        assert_eq!(body.size_hint().exact(), Some(file.len() as u64));
        let (mut sent, mut frames) = (Vec::new(), Vec::new());
        while let Some(frame) = body.frame().await {
            let data = frame.unwrap().into_data().unwrap();
            frames.push(data.len());
            sent.extend_from_slice(&data);
        }
        assert_eq!(frames, [FILE_FRAME, FILE_FRAME, FILE_FRAME, 100]);
        assert_eq!(sent, file);
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[test]
    fn an_exports_file_name_is_its_analysis_and_when_it_was_asked_for() {
        let at = "2026-10-05T09:30:07Z".parse().unwrap();
        assert_eq!(
            file_name("awards-report-v1", at, Format::Xlsx),
            "awards-report-v1-20261005-093007.xlsx"
        );
        assert_eq!(
            file_name("a\"b;c/..\\d", at, Format::Csv),
            "abc..d-20261005-093007.csv"
        );
        assert_eq!(
            file_name("..", at, Format::Csv),
            "export-20261005-093007.csv"
        );
    }
}
