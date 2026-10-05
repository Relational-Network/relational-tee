// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Running a pool's analysis: an admin over every row, an analyst with an
//! active grant over the rows their employer scope allows.
//!
//! - `GET  …/analyses/{analysis_id}`                  — the analysis, and the caller's rows
//! - `GET  …/analyses/{analysis_id}/options`          — filter options from the caller's rows
//! - `GET  …/analyses/{analysis_id}/options/{filter}` — a search filter's values
//! - `POST …/analyses/{analysis_id}/query`            — a page of matching rows
//!
//! under `/v1/drt/pools/{pool_pda}`. The SQL is the pool's definition, read
//! from storage by the hash its Execute DRT pins; requests only bind values
//! to it. Every options, search and query request is recorded in the
//! analysis log ([`crate::storage::analysis_log`]), and a success whose
//! record can't be stored returns nothing.

use std::collections::BTreeMap;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{error, warn};
use utoipa::{IntoParams, ToSchema};

use crate::analysis::definition::{ColumnType, Definition, FilterKind};
use crate::analysis::query::{
    self, FilterOptions, Page, QueryError, QueryRequest, SortRequest, DEFAULT_SEARCH_LIMIT,
};
use crate::analysis::runner::DEADLINE;
use crate::analysis::table::Scope;
use crate::api::pools::load_pool;
use crate::audit;
use crate::auth::{Caller, Permission};
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::analysis_log::AnalysisRecord;
use crate::storage::pools::{AnalysisRef, PoolDoc};

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
    #[schema(value_type = String)]
    pub kind: ColumnType,
}

/// A filter a request may use.
#[derive(Debug, Serialize, ToSchema)]
pub struct FilterSummary {
    pub name: String,
    /// `date_range` (`from` and `to`), `multi_select` (values from the
    /// options) or `search_select` (values from a search).
    #[schema(value_type = String)]
    pub kind: FilterKind,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PageSize {
    pub default: u32,
    pub max: u32,
}

/// The rows the caller sees: every row, or those of these employer groups
/// and employers.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeSummary {
    pub all: bool,
    pub employer_groups: Vec<String>,
    pub employers: Vec<String>,
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
}

/// Each filter's options but the searches', from the caller's rows.
#[derive(Debug, Serialize, ToSchema)]
pub struct OptionsResponse {
    /// By filter: `{ min, max }` (DD/MM/YYYY) for a date range, and the
    /// values with their row counts for a multi-select.
    pub options: BTreeMap<String, FilterOptions>,
}

/// Query for a search filter's values.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    /// The values' prefix, matched literally; empty for the first values.
    #[serde(default)]
    pub search: String,
    /// How many values (default 20, max 100).
    pub limit: Option<u32>,
}

/// A search filter's values that start with the search, in order.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResponse {
    pub values: Vec<String>,
}

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

/// The grant the caller runs the analysis through (none for an admin), and
/// the rows they see. Fails closed: no active grant, or no employer scope,
/// is 403.
async fn authorize(
    state: &AppState,
    caller: &Caller,
    doc: &PoolDoc,
    analysis: &AnalysisRef,
) -> Result<(Option<String>, Scope), ApiError> {
    if caller.is_admin() {
        return Ok((None, Scope::All));
    }
    let grant = doc
        .active_grant(&caller.user_id, &analysis.analysis_id)
        .ok_or_else(|| {
            ApiError::forbidden("you have no active grant to this analysis").with_code("no_grant")
        })?;
    let mapping = state.storage.employer_scopes().get().await?;
    Ok((Some(grant.grant_id.clone()), caller.row_scope(&mapping)?))
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
                request_id: crate::request_id::current().unwrap_or_default(),
                at: Utc::now(),
                user_id: caller.user_id.clone(),
                grant_id: None,
                pool_pda: doc.pool_pda.clone(),
                analysis_id: analysis.analysis_id.clone(),
                definition_sha256: analysis.code_hash_hex.clone(),
                action: action.into(),
                request,
                returned: None,
                total_matched: None,
                outcome: String::new(),
            },
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
                Err(ApiError::service_unavailable(
                    "this request couldn't be recorded in the analysis log, so its result isn't returned; retry",
                )
                .with_code("analysis_log_unavailable"))
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

fn scope_summary(scope: &Scope) -> ScopeSummary {
    match scope {
        Scope::All => ScopeSummary {
            all: true,
            employer_groups: Vec::new(),
            employers: Vec::new(),
        },
        Scope::Only {
            employer_groups,
            employers,
        } => ScopeSummary {
            all: false,
            employer_groups: employer_groups.iter().cloned().collect(),
            employers: employers.iter().cloned().collect(),
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
        scope: scope_summary(scope),
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
    description = "The pool's analysis as the caller may run it: the columns a page returns, the filters a query may use, the default sort and page sizes, the definition's URL and hash, and the rows the caller sees (every row for an admin; for an analyst, their employer scope). Needs `analyses:run`, and for an analyst an active grant.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
    ),
    responses(
        (status = 200, description = "The analysis", body = AnalysisSummary),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "No active grant (`no_grant`), or no employer scope (`no_employer_scope`, `groups_overage`)"),
        (status = 404, description = "Pool or analysis not found"),
    )
)]
pub async fn get_analysis(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id)): Path<(String, String)>,
) -> Result<Json<AnalysisSummary>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    let (doc, analysis) = load(&state, &pool_pda, &analysis_id).await?;
    let (_, scope) = authorize(&state, &caller, &doc, &analysis).await?;
    let def = state
        .analyses
        .definition(&state.storage, &analysis.code_hash_hex)
        .await?;
    Ok(Json(summary(&doc, &analysis, &def, &scope)))
}

/// Each filter's options, from the caller's rows.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/options",
    tag = "Analyses",
    summary = "Filter options",
    description = "The options of each filter but the searches, computed from the rows the caller sees only: the earliest and latest date of a date range, and each value of a multi-select with its row count. Recorded in the analysis log. Needs `analyses:run`, and for an analyst an active grant.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
    ),
    responses(
        (status = 200, description = "The options", body = OptionsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "No active grant, or no employer scope"),
        (status = 404, description = "Pool or analysis not found"),
        (status = 503, description = "The worker is busy (`analysis_busy`, with Retry-After), or the analysis log is unavailable"),
    )
)]
pub async fn get_options(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id)): Path<(String, String)>,
) -> Result<Json<OptionsResponse>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    let (doc, analysis) = load(&state, &pool_pda, &analysis_id).await?;
    let mut logged = Logged::new(&caller, &doc, &analysis, "options", json!({}));
    let result = async {
        let (grant, scope) = authorize(&state, &caller, &doc, &analysis).await?;
        logged.record.grant_id = grant;
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
        let table = state
            .analyses
            .table(&state.storage, &doc, &def, &scope)
            .await?;
        let options = state
            .analyses
            .blocking(move || {
                table
                    .options(&def, Instant::now() + DEADLINE)
                    .map_err(query_error)
            })
            .await?;
        Ok(OptionsResponse { options })
    }
    .await;
    let response = logged
        .finish(&state, result, |r| {
            let values = r.options.values().map(|o| match o {
                FilterOptions::Values(values) => values.len() as u64,
                FilterOptions::DateRange { .. } => 0,
            });
            (values.sum(), None)
        })
        .await?;
    Ok(Json(response))
}

/// A search filter's values that start with `search`.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/analyses/{analysis_id}/options/{filter}",
    tag = "Analyses",
    summary = "Search a filter's values",
    description = "The values of a search filter, such as a staff number, that start with `search`, in order, from the rows the caller sees only. Recorded in the analysis log. Needs `analyses:run`, and for an analyst an active grant.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analysis_id" = String, Path, description = "The pool's analysis"),
        ("filter" = String, Path, description = "A search filter of the analysis"),
        SearchQuery,
    ),
    responses(
        (status = 200, description = "The values", body = SearchResponse),
        (status = 400, description = "Not a search filter, or a search or limit out of range (`invalid_query`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "No active grant, or no employer scope"),
        (status = 404, description = "Pool or analysis not found"),
        (status = 503, description = "The worker is busy (`analysis_busy`, with Retry-After), or the analysis log is unavailable"),
    )
)]
pub async fn search_values(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda, analysis_id, filter)): Path<(String, String, String)>,
    Query(search): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    let (doc, analysis) = load(&state, &pool_pda, &analysis_id).await?;
    let limit = search.limit.unwrap_or(DEFAULT_SEARCH_LIMIT);
    let asked = json!({ "filter": filter, "search": search.search, "limit": limit });
    let mut logged = Logged::new(&caller, &doc, &analysis, "search", asked);
    let result = async {
        let (grant, scope) = authorize(&state, &caller, &doc, &analysis).await?;
        logged.record.grant_id = grant;
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
        let table = state
            .analyses
            .table(&state.storage, &doc, &def, &scope)
            .await?;
        let prefix = search.search;
        let values = state
            .analyses
            .blocking(move || {
                table
                    .search(&def, &filter, &prefix, limit, Instant::now() + DEADLINE)
                    .map_err(query_error)
            })
            .await?;
        Ok(SearchResponse { values })
    }
    .await;
    let response = logged
        .finish(&state, result, |r| (r.values.len() as u64, None))
        .await?;
    Ok(Json(response))
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
        (status = 403, description = "No active grant, or no employer scope"),
        (status = 404, description = "Pool or analysis not found"),
        (status = 415, description = "The body isn't JSON"),
        (status = 422, description = "The query ran out of time (`analysis_timeout`)"),
        (status = 503, description = "The worker is busy (`analysis_busy`, with Retry-After), or the analysis log is unavailable"),
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
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));
    if !is_json {
        return Err(ApiError::unsupported_media_type(
            "a query is JSON: send Content-Type: application/json",
        ));
    }
    let (doc, analysis) = load(&state, &pool_pda, &analysis_id).await?;
    let asked = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let mut logged = Logged::new(&caller, &doc, &analysis, "query", asked);
    let result = async {
        let (grant, scope) = authorize(&state, &caller, &doc, &analysis).await?;
        logged.record.grant_id = grant;
        let request: QueryRequest = serde_json::from_slice(&body).map_err(|e| {
            ApiError::bad_request(format!("the query isn't valid: {e}")).with_code("invalid_query")
        })?;
        let def = state
            .analyses
            .definition(&state.storage, &analysis.code_hash_hex)
            .await?;
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
        state
            .analyses
            .blocking(move || {
                table
                    .page(&def, &query, Instant::now() + DEADLINE)
                    .map_err(query_error)
            })
            .await
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

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sha2::{Digest, Sha256};
    use solana_pubkey::Pubkey;

    use super::*;
    use crate::analysis::definition::tests::AWARDS_REPORT;
    use crate::api::credentials::tests::{send, sign_in, worker, Admin, Worker};
    use crate::api::grants::tests::{analysis_pool, analyst, ANALYSIS};
    use crate::auth::entra::mint::Spec;
    use crate::auth::entra::tests::{config, entra_key};
    use crate::data_validation::tests::{awards_schema, AWARDS_HEADER};
    use crate::storage::pools::{Grant, GrantRevocation, Upload, INITIAL};
    use crate::storage::scopes::tests::{fixture, AIB_GROUP, EBS_GROUP};
    use crate::storage::scopes::EmployerScope;
    use crate::storage::Change;

    /// Staff number, employer, employer group, award, exam board date.
    const ROWS: [(&str, &str, &str, &str, &str); 5] = [
        ("000123", "AIB", "AIB", "Certificate", "01/01/2026"),
        ("000124", "AIB", "AIB", "Diploma", "30/09/2026"),
        ("020001", "EBS Network", "AIB", "Certificate", "15/06/2026"),
        (
            "030001",
            "Bank of Ireland",
            "Bank of Ireland",
            "Certificate",
            "01/01/2026",
        ),
        ("040001", "PTSB", "PTSB", "Advisor", "10/02/2026"),
    ];

    /// An Awards Report pool of `owner`'s whose first upload holds `ROWS`.
    async fn awards_pool(worker: &Worker, owner: &Admin) -> Pubkey {
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
                "{staff},M{i},Mx,Sam,Doyle,01/01/1990,{employer},{group},{award},Pass,{date}\n"
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

    /// `analyst` holds an active grant to the pool's analysis.
    async fn grant(worker: &Worker, pool_pda: &Pubkey, analyst: &str) {
        worker
            .storage
            .pools()
            .update::<ApiError>(&pool_pda.to_string(), |doc| {
                doc.grants.push(Grant {
                    grant_id: format!("g-{analyst}"),
                    analyst: analyst.into(),
                    drt_name: ANALYSIS.into(),
                    commitment: hex::encode(Sha256::digest(analyst)),
                    granted_by: "admin".into(),
                    granted_at: Utc::now(),
                    signature: Some("sig-grant".into()),
                    revoked: None,
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
        let scopes = worker.storage.employer_scopes();
        scopes.replace(0, fixture(), "admin").await.unwrap();
        let (aib, aib_id) = analyst(&worker.app, "oid-aib", &[AIB_GROUP]).await;
        let (ebs, ebs_id) = analyst(&worker.app, "oid-ebs", &[EBS_GROUP]).await;
        grant(&worker, &pool_pda, &aib_id).await;
        grant(&worker, &pool_pda, &ebs_id).await;
        let base = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        let query = format!("{base}/query");

        // Group AIB includes its employer EBS Network; newest first by default.
        let (status, _, page) = send(&worker.app, post(&query, &aib, &json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(
            (&page["total_matched"], &page["limit"], &page["offset"]),
            (&json!(3), &json!(100), &json!(0))
        );
        assert_eq!(
            column(&page, "staff_number"),
            ["000124", "020001", "000123"]
        );
        assert!(column(&page, "employer_group").iter().all(|g| g == "AIB"));
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
        let (status, _, page) = send(&worker.app, post(&query, &aib, &filtered)).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["total_matched"], 2);
        assert_eq!(column(&page, "staff_number"), ["020001"]);

        let (_, _, page) = send(&worker.app, post(&query, &ebs, &json!({}))).await;
        assert_eq!(column(&page, "employer"), ["EBS Network"]);
        let (_, _, page) = send(&worker.app, post(&query, &owner.token, &json!({}))).await;
        assert_eq!(page["total_matched"], 5);

        // Options and searches come from the caller's rows only.
        let (status, _, options) = send(&worker.app, get(&format!("{base}/options"), &aib)).await;
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
        let search = format!("{base}/options/staff_number?search=0&limit=5");
        let (_, _, found) = send(&worker.app, get(&search, &aib)).await;
        assert_eq!(found["values"], json!(["000123", "000124", "020001"]));
        let search = format!("{base}/options/staff_number?search=03");
        let (_, _, found) = send(&worker.app, get(&search, &aib)).await;
        assert_eq!(found["values"], json!([]));

        // The summary names the caller's rows.
        let (status, _, summary) = send(&worker.app, get(&base, &aib)).await;
        assert_eq!(status, StatusCode::OK, "{summary}");
        assert_eq!(
            summary["scope"],
            json!({ "all": false, "employer_groups": ["AIB"], "employers": [] })
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
        assert_eq!(filtered_record.grant_id, Some(format!("g-{aib_id}")));
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
            send(&worker.app, get(&path, &aib)).await.0,
            StatusCode::FORBIDDEN
        );
        let undated = format!("/v1/admin/analysis-log?pool_pda={pool_pda}&date=2026-10-5");
        assert_eq!(
            send(&worker.app, get(&undated, &owner.token)).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn queries_fail_closed_and_refuse_what_the_analysis_does_not_define() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = awards_pool(&worker, &owner).await;
        let mut scopes = fixture();
        scopes.push(EmployerScope {
            group_id: "g-cu".into(),
            label: "UAT_EDQ_CREDIT_UNION".into(),
            employer_group: Some("Credit Union".into()),
            employer: None,
        });
        worker
            .storage
            .employer_scopes()
            .replace(0, scopes, "admin")
            .await
            .unwrap();
        let (granted, granted_id) = analyst(&worker.app, "oid-aib", &[AIB_GROUP]).await;
        let (ungranted, _) = analyst(&worker.app, "oid-nogrant", &[AIB_GROUP]).await;
        let (unmapped, unmapped_id) = analyst(&worker.app, "oid-unmapped", &["g-other"]).await;
        let (empty, empty_id) = analyst(&worker.app, "oid-cu", &["g-cu"]).await;
        let mut spec = Spec::valid(&config());
        spec.roles = vec!["Analyst".into()];
        spec.groups_overage = true;
        let overage = spec.sign(entra_key()).unwrap();
        let overage_id = sign_in(&worker.app, &overage).await;
        let nobody = Spec::valid(&config()).sign(entra_key()).unwrap();
        for analyst in [&granted_id, &unmapped_id, &empty_id, &overage_id] {
            grant(&worker, &pool_pda, analyst).await;
        }
        let base = format!("/v1/drt/pools/{pool_pda}/analyses/{ANALYSIS}");
        let query = format!("{base}/query");

        for (token, body, status, code) in [
            (&ungranted, json!({}), StatusCode::FORBIDDEN, "no_grant"),
            (
                &unmapped,
                json!({}),
                StatusCode::FORBIDDEN,
                "no_employer_scope",
            ),
            (&overage, json!({}), StatusCode::FORBIDDEN, "groups_overage"),
            (&nobody, json!({}), StatusCode::FORBIDDEN, "forbidden"),
            (
                &granted,
                json!({ "scope": { "employer_group": "PTSB" } }),
                StatusCode::BAD_REQUEST,
                "invalid_query",
            ),
            (
                &granted,
                json!({ "filters": { "employer_group": { "mode": "selected", "values": ["PTSB"] } } }),
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

        // An empty but valid scope gets an empty page.
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
        let (status, _, err) = send(
            &worker.app,
            get(&format!("{base}/options/award?search=C"), &granted),
        )
        .await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_query"))
        );
        let (status, _, _) = send(
            &worker.app,
            get(&format!("{base}/options/staff_number?scope=all"), &granted),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
        assert_eq!(outcomes["no_grant"], 2);
        assert_eq!(outcomes["groups_overage"], 1);
        assert_eq!(outcomes["invalid_query"], 6);
        let override_attempt = log
            .iter()
            .find(|r| r.request.get("scope").is_some())
            .expect("the scope override is recorded as sent");
        assert_eq!(override_attempt.outcome, "invalid_query");
    }
}
