// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Requests against an analysis: checked against its definition, then run on
//! a caller's table with every value bound as a parameter and the sort taken
//! from the definition's output columns.

use std::collections::BTreeMap;
use std::time::Instant;

use rusqlite::{Connection, Statement, ToSql};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

use super::dates;
use super::definition::{ColumnType, Definition, Direction, FilterKind};
use super::table::Table;

/// The most values one select filter may name.
const MAX_SELECTED: usize = 1000;
/// The longest value or search prefix a request may send.
const MAX_VALUE_CHARS: usize = 256;
/// The furthest a request may page.
const MAX_OFFSET: u64 = 10_000_000;
/// The most values a search returns.
pub const MAX_SEARCH_LIMIT: u32 = 100;
/// How many values a search returns when the request doesn't say.
pub const DEFAULT_SEARCH_LIMIT: u32 = 20;
/// How many SQLite steps run between deadline checks.
const DEADLINE_STEPS: i32 = 1000;

/// A query, as the browser sends it.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    /// By filter name. An omitted filter adds no condition.
    #[serde(default)]
    pub filters: BTreeMap<String, FilterRequest>,
    /// The definition's default sort when omitted.
    #[serde(default)]
    pub sort: Option<SortRequest>,
    #[serde(default)]
    pub pagination: Option<PageRequest>,
}

/// A date range takes `from` and `to` (DD/MM/YYYY, inclusive, either may be
/// omitted); a select takes `mode` `all`, or `selected` with `values`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FilterRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    All,
    Selected,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SortRequest {
    pub field: String,
    #[schema(value_type = String, example = "desc")]
    pub direction: Direction,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u64>,
}

/// A request that fits its definition, ready to bind.
#[derive(Debug, Clone)]
pub struct Query {
    params: Vec<(String, Option<String>)>,
    pub sort: String,
    pub direction: Direction,
    pub limit: u32,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// The request doesn't fit the definition.
    Invalid(String),
    /// The query ran past its deadline.
    Timeout,
    Failed(String),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Failed(message) => f.write_str(message),
            Self::Timeout => f.write_str("the analysis ran out of time"),
        }
    }
}

impl From<rusqlite::Error> for QueryError {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::OperationInterrupted) => Self::Timeout,
            _ => Self::Failed(format!("SQLite failed: {e}")),
        }
    }
}

fn invalid<T>(message: String) -> Result<T, QueryError> {
    Err(QueryError::Invalid(message))
}

fn date(filter: &str, end: &str, value: Option<&str>) -> Result<Option<String>, QueryError> {
    match value {
        None => Ok(None),
        Some(v) => dates::to_sql(v).map(Some).ok_or_else(|| {
            QueryError::Invalid(format!("{filter}.{end} must be a DD/MM/YYYY date"))
        }),
    }
}

fn selection(filter: &str, given: &FilterRequest) -> Result<Option<String>, QueryError> {
    if given.from.is_some() || given.to.is_some() {
        return invalid(format!("{filter} takes a mode, not from and to"));
    }
    match (given.mode, &given.values) {
        (Some(Mode::All), None) => Ok(None),
        (Some(Mode::Selected), Some(values)) => {
            if values.is_empty() {
                return invalid(format!("{filter} selects no values"));
            }
            if values.len() > MAX_SELECTED {
                return invalid(format!("{filter} selects more than {MAX_SELECTED} values"));
            }
            if values
                .iter()
                .any(|v| v.is_empty() || v.chars().count() > MAX_VALUE_CHARS)
            {
                return invalid(format!(
                    "{filter}'s values must be 1-{MAX_VALUE_CHARS} characters"
                ));
            }
            Ok(Some(
                serde_json::to_string(values).map_err(|e| QueryError::Failed(e.to_string()))?,
            ))
        }
        _ => invalid(format!(
            "{filter} needs mode all, or mode selected with values"
        )),
    }
}

impl Query {
    /// Check `request` against `def`: only its filters, each in its own
    /// shape, a sort on an output column, and paging within its limits.
    pub fn check(def: &Definition, request: &QueryRequest) -> Result<Self, QueryError> {
        if let Some(name) = request.filters.keys().find(|n| def.filter(n).is_none()) {
            return invalid(format!("{} has no filter {name}", def.analysis_id));
        }
        let mut params = Vec::new();
        for filter in &def.filters {
            let given = request.filters.get(&filter.name);
            match filter.kind {
                FilterKind::DateRange => {
                    let (from, to) = match given {
                        None => (None, None),
                        Some(f) if f.mode.is_some() || f.values.is_some() => {
                            return invalid(format!("{} takes from and to", filter.name));
                        }
                        Some(f) => (
                            date(&filter.name, "from", f.from.as_deref())?,
                            date(&filter.name, "to", f.to.as_deref())?,
                        ),
                    };
                    if from.is_some() && to.is_some() && from > to {
                        return invalid(format!("{}.from is after its to", filter.name));
                    }
                    params.push((format!(":{}_from", filter.name), from));
                    params.push((format!(":{}_to", filter.name), to));
                }
                FilterKind::MultiSelect | FilterKind::SearchSelect => {
                    let values = match given {
                        None => None,
                        Some(f) => selection(&filter.name, f)?,
                    };
                    params.push((format!(":{}", filter.name), values));
                }
            }
        }

        let (sort, direction) = match &request.sort {
            None => def.default_sort.clone(),
            Some(s) if def.output.contains(&s.field) => (s.field.clone(), s.direction),
            Some(s) => {
                return invalid(format!(
                    "{} can't be sorted on {}",
                    def.analysis_id, s.field
                ))
            }
        };
        let page = request.pagination.clone().unwrap_or_default();
        let limit = page.limit.unwrap_or(def.page_default);
        if limit == 0 || limit > def.page_max {
            return invalid(format!("limit must be 1 to {}", def.page_max));
        }
        let offset = page.offset.unwrap_or(0);
        if offset > MAX_OFFSET {
            return invalid(format!("offset must be at most {MAX_OFFSET}"));
        }
        Ok(Self {
            params,
            sort,
            direction,
            limit,
            offset,
        })
    }
}

/// One page of matching rows.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Page {
    /// By output column; dates as DD/MM/YYYY.
    #[schema(value_type = Vec<Object>)]
    pub rows: Vec<Map<String, Value>>,
    /// Every row the filters match in the caller's scope.
    pub total_matched: u64,
    pub limit: u32,
    pub offset: u64,
}

/// A filter's options, from the caller's rows.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[serde(untagged)]
pub enum FilterOptions {
    /// The earliest and latest dates, as DD/MM/YYYY; none without rows.
    DateRange {
        min: Option<String>,
        max: Option<String>,
    },
    Values(Vec<OptionValue>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct OptionValue {
    pub value: String,
    pub count: u64,
}

fn bind(statement: &mut Statement<'_>, name: &str, value: &dyn ToSql) -> rusqlite::Result<()> {
    match statement.parameter_index(name)? {
        Some(index) => statement.raw_bind_parameter(index, value),
        None => Ok(()),
    }
}

fn bind_all(
    statement: &mut Statement<'_>,
    params: &[(String, Option<String>)],
) -> rusqlite::Result<()> {
    for (name, value) in params {
        bind(statement, name, value)?;
    }
    Ok(())
}

fn cell(value: Option<String>, kind: ColumnType) -> Value {
    match (value, kind) {
        (None, _) => Value::Null,
        (Some(v), ColumnType::Date) => Value::String(dates::from_sql(&v).unwrap_or(v)),
        (Some(v), ColumnType::Text) => Value::String(v),
    }
}

/// `%`, `_` and `\` matched literally by `LIKE ... ESCAPE '\'`.
fn like_prefix(prefix: &str) -> String {
    let mut escaped = String::with_capacity(prefix.len());
    for c in prefix.chars() {
        if matches!(c, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

impl Table {
    /// Run `f` on the connection, stopping it at `deadline`.
    fn run<T>(
        &self,
        deadline: Instant,
        f: impl FnOnce(&Connection) -> Result<T, QueryError>,
    ) -> Result<T, QueryError> {
        let conn = self.connection();
        conn.progress_handler(DEADLINE_STEPS, Some(move || Instant::now() >= deadline))?;
        let result = f(&conn);
        conn.progress_handler(0, None::<fn() -> bool>)?;
        result
    }

    /// The page `query` asks for, and how many rows match in all.
    pub fn page(
        &self,
        def: &Definition,
        query: &Query,
        deadline: Instant,
    ) -> Result<Page, QueryError> {
        self.run(deadline, |conn| {
            let mut count = conn.prepare(&def.count_sql())?;
            bind_all(&mut count, &query.params)?;
            let total: i64 = match count.raw_query().next()? {
                Some(row) => row.get(0)?,
                None => 0,
            };

            let mut page = conn.prepare(&def.page_sql(&query.sort, query.direction))?;
            bind_all(&mut page, &query.params)?;
            bind(&mut page, ":_limit", &i64::from(query.limit))?;
            bind(&mut page, ":_offset", &(query.offset as i64))?;
            let kinds: Vec<ColumnType> = def
                .output
                .iter()
                .map(|name| def.column(name).map_or(ColumnType::Text, |c| c.kind))
                .collect();
            let mut rows = Vec::new();
            let mut cursor = page.raw_query();
            while let Some(row) = cursor.next()? {
                let mut out = Map::new();
                for (i, (name, kind)) in def.output.iter().zip(&kinds).enumerate() {
                    out.insert(name.clone(), cell(row.get(i)?, *kind));
                }
                rows.push(out);
            }
            Ok(Page {
                rows,
                total_matched: u64::try_from(total).unwrap_or(0),
                limit: query.limit,
                offset: query.offset,
            })
        })
    }

    /// Every filter's options but the searches', from this table's rows.
    pub fn options(
        &self,
        def: &Definition,
        deadline: Instant,
    ) -> Result<BTreeMap<String, FilterOptions>, QueryError> {
        self.run(deadline, |conn| {
            let mut options = BTreeMap::new();
            for filter in &def.filters {
                let Some(sql) = def.options_sql(&filter.name) else {
                    continue;
                };
                let found = match filter.kind {
                    FilterKind::SearchSelect => continue,
                    FilterKind::DateRange => {
                        let (min, max): (Option<String>, Option<String>) =
                            conn.query_row(sql, [], |row| Ok((row.get(0)?, row.get(1)?)))?;
                        FilterOptions::DateRange {
                            min: min.and_then(|v| dates::from_sql(&v)),
                            max: max.and_then(|v| dates::from_sql(&v)),
                        }
                    }
                    FilterKind::MultiSelect => {
                        let mut statement = conn.prepare(sql)?;
                        let values = statement
                            .query_map([], |row| {
                                Ok(OptionValue {
                                    value: row.get(0)?,
                                    count: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                                })
                            })?
                            .collect::<rusqlite::Result<Vec<_>>>()?;
                        FilterOptions::Values(values)
                    }
                };
                options.insert(filter.name.clone(), found);
            }
            Ok(options)
        })
    }

    /// The values of search filter `filter` that start with `prefix`.
    pub fn search(
        &self,
        def: &Definition,
        filter: &str,
        prefix: &str,
        limit: u32,
        deadline: Instant,
    ) -> Result<Vec<String>, QueryError> {
        match def.filter(filter).map(|f| f.kind) {
            Some(FilterKind::SearchSelect) => {}
            _ => return invalid(format!("{} has no search filter {filter}", def.analysis_id)),
        }
        if prefix.chars().count() > MAX_VALUE_CHARS {
            return invalid(format!("a search is at most {MAX_VALUE_CHARS} characters"));
        }
        if limit == 0 || limit > MAX_SEARCH_LIMIT {
            return invalid(format!("limit must be 1 to {MAX_SEARCH_LIMIT}"));
        }
        let Some(sql) = def.options_sql(filter) else {
            return invalid(format!("{} has no search filter {filter}", def.analysis_id));
        };
        self.run(deadline, |conn| {
            let mut statement = conn.prepare(sql)?;
            bind(&mut statement, ":search", &like_prefix(prefix))?;
            bind(&mut statement, ":limit", &i64::from(limit))?;
            let mut values = Vec::new();
            let mut cursor = statement.raw_query();
            while let Some(row) = cursor.next()? {
                values.push(row.get(0)?);
            }
            Ok(values)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use super::*;
    use crate::analysis::definition::tests::awards_report;
    use crate::analysis::table::Scope;

    const HEADER: &str = "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,\
                          Employer,Employer Group,Award,Award Grade,Exam Board Date";

    /// Staff number, surname, employer, employer group, award, exam board date.
    const ROWS: [[&str; 6]; 10] = [
        [
            "000123",
            "Brennan",
            "AIB",
            "AIB",
            "Certificate",
            "01/01/2026",
        ],
        ["000123", "Brennan", "AIB", "AIB", "Diploma", "30/09/2026"],
        ["123", "Doyle", "AIB", "AIB", "Certificate", "31/12/2025"],
        [
            "001234",
            "Fitzgerald",
            "AIB",
            "AIB",
            "Diploma",
            "01/10/2026",
        ],
        [
            "020001",
            "Lynch",
            "EBS Network",
            "AIB",
            "Certificate",
            "15/06/2026",
        ],
        [
            "020002",
            "McCarthy",
            "EBS Network",
            "AIB",
            "Advisor",
            "15/06/2026",
        ],
        [
            "030001",
            "O'Connor",
            "Bank of Ireland",
            "Bank of Ireland",
            "Certificate",
            "01/01/2026",
        ],
        [
            "030002",
            "Power",
            "BOI Insurance",
            "Bank of Ireland",
            "Diploma",
            "14/05/2026",
        ],
        ["040001", "Tobin", "PTSB", "PTSB", "Advisor", "10/02/2026"],
        [
            "050001",
            "Clarke",
            "Credit Union Partners",
            "",
            "Advisor",
            "05/05/2026",
        ],
    ];

    fn upload(rows: &[[&str; 6]]) -> Vec<u8> {
        let mut csv = format!("{HEADER}\n");
        for (i, [staff, surname, employer, group, award, date]) in rows.iter().enumerate() {
            csv.push_str(&format!(
                "{staff},M{i:04},Mx,Sam,{surname},01/01/1990,{employer},{group},{award},Pass,{date}\n"
            ));
        }
        csv.into_bytes()
    }

    fn table(scope: &Scope) -> Table {
        let (first, second) = (upload(&ROWS[..6]), upload(&ROWS[6..]));
        Table::build(&awards_report(), &[&first, &second], scope).unwrap()
    }

    fn groups(names: &[&str]) -> Scope {
        Scope::Only {
            employer_groups: names.iter().map(|n| n.to_string()).collect(),
            employers: BTreeSet::new(),
        }
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn request(json: serde_json::Value) -> QueryRequest {
        serde_json::from_value(json).unwrap()
    }

    fn run(table: &Table, json: serde_json::Value) -> Page {
        let def = awards_report();
        let query = Query::check(&def, &request(json)).unwrap();
        table.page(&def, &query, soon()).unwrap()
    }

    fn column(page: &Page, name: &str) -> Vec<String> {
        page.rows
            .iter()
            .map(|r| r[name].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn a_scope_sees_only_its_rows_and_admins_see_all() {
        let aib = table(&groups(&["AIB"]));
        assert_eq!(aib.rows, 6);
        let page = run(&aib, serde_json::json!({}));
        assert_eq!(page.total_matched, 6);
        assert!(column(&page, "employer_group").iter().all(|g| g == "AIB"));

        let ebs = table(&Scope::Only {
            employer_groups: BTreeSet::new(),
            employers: ["EBS Network".to_string()].into(),
        });
        assert_eq!(run(&ebs, serde_json::json!({})).total_matched, 2);

        let both = table(&groups(&["AIB", "PTSB"]));
        assert_eq!(run(&both, serde_json::json!({})).total_matched, 7);

        let all = table(&Scope::All);
        assert_eq!(run(&all, serde_json::json!({})).total_matched, 10);

        let nothing = table(&groups(&[]));
        let page = run(&nothing, serde_json::json!({}));
        assert_eq!((page.total_matched, page.rows.len()), (0, 0));
    }

    #[test]
    fn options_and_searches_come_from_the_scope_only() {
        let def = awards_report();
        let aib = table(&groups(&["AIB"]));
        let options = aib.options(&def, soon()).unwrap();
        assert_eq!(
            options["exam_board_date"],
            FilterOptions::DateRange {
                min: Some("31/12/2025".into()),
                max: Some("01/10/2026".into()),
            }
        );
        let FilterOptions::Values(awards) = &options["award"] else {
            panic!("award options are values");
        };
        let counts: Vec<(&str, u64)> = awards.iter().map(|o| (o.value.as_str(), o.count)).collect();
        assert_eq!(counts, [("Advisor", 1), ("Certificate", 3), ("Diploma", 2)]);
        assert!(
            !options.contains_key("staff_number"),
            "searches aren't listed"
        );

        assert_eq!(
            aib.search(&def, "staff_number", "00", 10, soon()).unwrap(),
            ["000123", "001234"]
        );
        assert_eq!(
            aib.search(&def, "staff_number", "03", 10, soon()).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            aib.search(&def, "staff_number", "0%", 10, soon()).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            aib.search(&def, "staff_number", "", 1, soon())
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            aib.search(&def, "award", "C", 10, soon()),
            Err(QueryError::Invalid(_))
        ));
        assert!(matches!(
            aib.search(&def, "staff_number", "0", 101, soon()),
            Err(QueryError::Invalid(_))
        ));
    }

    #[test]
    fn filters_work_alone_and_together() {
        let all = table(&Scope::All);
        let dates = run(
            &all,
            serde_json::json!({ "filters": { "exam_board_date": { "from": "01/01/2026", "to": "30/09/2026" } } }),
        );
        assert_eq!(dates.total_matched, 8, "both ends are inclusive");

        let from_only = run(
            &all,
            serde_json::json!({ "filters": { "exam_board_date": { "from": "01/10/2026" } } }),
        );
        assert_eq!(column(&from_only, "staff_number"), ["001234"]);

        let awards = run(
            &all,
            serde_json::json!({ "filters": { "award": { "mode": "selected", "values": ["Diploma", "Advisor"] } } }),
        );
        assert_eq!(
            awards.total_matched, 6,
            "values within a filter combine with OR"
        );

        let staff = run(
            &all,
            serde_json::json!({ "filters": { "staff_number": { "mode": "selected", "values": ["000123"] } } }),
        );
        assert_eq!(
            staff.total_matched, 2,
            "leading zeroes are kept: 123 doesn't match"
        );

        let together = run(
            &all,
            serde_json::json!({ "filters": {
                "exam_board_date": { "from": "01/01/2026", "to": "30/09/2026" },
                "award": { "mode": "selected", "values": ["Certificate"] },
                "staff_number": { "mode": "all" },
                "membership_number": { "mode": "all" },
            } }),
        );
        assert_eq!(
            together.total_matched, 3,
            "different filters combine with AND"
        );
    }

    #[test]
    fn sorting_spans_the_whole_selection_and_paging_is_deterministic() {
        let all = table(&Scope::All);
        let sorted = |offset: u64| {
            run(
                &all,
                serde_json::json!({
                    "sort": { "field": "exam_board_date", "direction": "asc" },
                    "pagination": { "limit": 3, "offset": offset },
                }),
            )
        };
        let mut dates = Vec::new();
        let mut staff = Vec::new();
        for offset in [0, 3, 6, 9] {
            let page = sorted(offset);
            assert_eq!(
                (page.limit, page.offset, page.total_matched),
                (3, offset, 10)
            );
            dates.extend(column(&page, "exam_board_date"));
            staff.extend(column(&page, "staff_number"));
        }
        assert_eq!(dates.len(), 10);
        let iso: Vec<String> = dates
            .iter()
            .map(|d| crate::analysis::dates::to_sql(d).unwrap())
            .collect();
        assert!(iso.windows(2).all(|w| w[0] <= w[1]), "{dates:?}");
        assert_eq!(dates[0], "31/12/2025");
        // Ties keep upload order: 01/01/2026 is first Brennan (first upload),
        // then O'Connor (second upload), on every run.
        assert_eq!(staff[1..3], ["000123", "030001"]);
        let again: Vec<String> = [0, 3, 6, 9]
            .into_iter()
            .flat_map(|offset| column(&sorted(offset), "staff_number"))
            .collect();
        assert_eq!(staff, again);

        let by_name = run(
            &all,
            serde_json::json!({ "sort": { "field": "surname", "direction": "desc" } }),
        );
        assert_eq!(column(&by_name, "surname")[0], "Tobin");

        let default = run(&all, serde_json::json!({}));
        assert_eq!(
            column(&default, "exam_board_date")[0],
            "01/10/2026",
            "exam board date, newest first"
        );
        assert_eq!(default.limit, 100);
    }

    #[test]
    fn dates_leave_as_dd_mm_yyyy() {
        let all = table(&Scope::All);
        let page = run(&all, serde_json::json!({ "pagination": { "limit": 1 } }));
        assert_eq!(page.rows[0]["date_of_birth"], "01/01/1990");
        assert_eq!(page.rows[0]["exam_board_date"], "01/10/2026");
        assert!(!page.rows[0].contains_key("_record_id"));
    }

    #[test]
    fn requests_that_do_not_fit_are_refused() {
        let def = awards_report();
        for (json, says) in [
            (
                serde_json::json!({ "filters": { "employer_group": { "mode": "all" } } }),
                "no filter employer_group",
            ),
            (
                serde_json::json!({ "filters": { "employer": { "mode": "selected", "values": ["PTSB"] } } }),
                "no filter employer",
            ),
            (
                serde_json::json!({ "filters": { "award": { "mode": "selected", "values": [] } } }),
                "selects no values",
            ),
            (
                serde_json::json!({ "filters": { "award": { "mode": "selected" } } }),
                "needs mode",
            ),
            (
                serde_json::json!({ "filters": { "award": { "from": "01/01/2026" } } }),
                "takes a mode",
            ),
            (
                serde_json::json!({ "filters": { "exam_board_date": { "from": "2026-01-01" } } }),
                "DD/MM/YYYY",
            ),
            (
                serde_json::json!({ "filters": { "exam_board_date": { "from": "02/01/2026", "to": "01/01/2026" } } }),
                "after",
            ),
            (
                serde_json::json!({ "filters": { "exam_board_date": { "mode": "all" } } }),
                "takes from and to",
            ),
            (
                serde_json::json!({ "sort": { "field": "_record_id", "direction": "asc" } }),
                "can't be sorted",
            ),
            (
                serde_json::json!({ "pagination": { "limit": 501 } }),
                "limit",
            ),
            (serde_json::json!({ "pagination": { "limit": 0 } }), "limit"),
        ] {
            match Query::check(&def, &request(json.clone())) {
                Err(QueryError::Invalid(message)) => {
                    assert!(message.contains(says), "{json}: {message}")
                }
                other => panic!("{json}: {other:?}"),
            }
        }
        for json in [
            serde_json::json!({ "scope": { "employer_group": "PTSB" } }),
            serde_json::json!({ "filters": { "award": { "mode": "some" } } }),
            serde_json::json!({ "sort": { "field": "surname", "direction": "up" } }),
        ] {
            assert!(
                serde_json::from_value::<QueryRequest>(json.clone()).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn a_query_stops_at_its_deadline() {
        let def = awards_report();
        // Enough rows that a query takes more steps than one deadline check.
        let many = upload(&[ROWS[0]; 5000]);
        let all = Table::build(&def, &[&many], &Scope::All).unwrap();
        let query = Query::check(&def, &QueryRequest::default()).unwrap();
        assert_eq!(
            all.page(&def, &query, Instant::now()),
            Err(QueryError::Timeout)
        );
        all.page(&def, &query, soon()).unwrap();
    }
}
