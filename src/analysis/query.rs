// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Requests against an analysis: checked against its definition, then run on
//! a caller's table with every value bound as a parameter. A page is a
//! statement over the definition's table that names only the filters the
//! request sets, so SQLite can read it from the table's indexes, sorted by
//! one of the definition's output columns.

use std::collections::BTreeMap;
use std::time::Instant;

use rusqlite::{Connection, Statement, ToSql};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

use super::dates;
use super::definition::{ColumnType, Definition, Direction, FilterKind, RECORD_ID};
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
pub(super) const DEADLINE_STEPS: i32 = 1000;

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

/// What a filter a request sets binds: a date range's ends as
/// `YYYY-MM-DD` (at least one), or a select's values as a JSON array.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Bound {
    Range {
        from: Option<String>,
        to: Option<String>,
    },
    Values(String),
}

/// A request that fits its definition, ready to bind.
#[derive(Debug, Clone)]
pub struct Query {
    /// The filters the request sets, by name, in the definition's order. An
    /// omitted filter, a select in mode `all` and a range with neither end
    /// set no condition, so they aren't here.
    filters: Vec<(String, Bound)>,
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
        let mut filters = Vec::new();
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
                    if from.is_some() || to.is_some() {
                        filters.push((filter.name.clone(), Bound::Range { from, to }));
                    }
                }
                FilterKind::MultiSelect | FilterKind::SearchSelect => {
                    let values = match given {
                        None => None,
                        Some(f) => selection(&filter.name, f)?,
                    };
                    if let Some(values) = values {
                        filters.push((filter.name.clone(), Bound::Values(values)));
                    }
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
            filters,
            sort,
            direction,
            limit,
            offset,
        })
    }

    /// Whether the query sets no filter.
    pub fn is_unfiltered(&self) -> bool {
        self.filters.is_empty()
    }

    /// The `WHERE` clause of the filters this query sets (empty if it sets
    /// none), and the values it binds. The names in it are the definition's
    /// filters, which `check` admitted, and are its columns' names.
    fn conditions(&self) -> (String, Vec<(String, String)>) {
        self.conditions_except(None)
    }

    /// The same, leaving out filter `except`: a filter's own options and
    /// searches follow the other filters only, so its other values stay on
    /// offer.
    fn conditions_except(&self, except: Option<&str>) -> (String, Vec<(String, String)>) {
        let mut terms = Vec::new();
        let mut binds = Vec::new();
        for (name, bound) in self
            .filters
            .iter()
            .filter(|(name, _)| Some(name.as_str()) != except)
        {
            match bound {
                Bound::Range { from, to } => {
                    for (end, op, value) in [("from", ">=", from), ("to", "<=", to)] {
                        if let Some(value) = value {
                            terms.push(format!("\"{name}\" {op} :{name}_{end}"));
                            binds.push((format!(":{name}_{end}"), value.clone()));
                        }
                    }
                }
                Bound::Values(values) => {
                    terms.push(format!(
                        "\"{name}\" IN (SELECT value FROM json_each(:{name}))"
                    ));
                    binds.push((format!(":{name}"), values.clone()));
                }
            }
        }
        let clause = if terms.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", terms.join(" AND "))
        };
        (clause, binds)
    }

    /// This query's page of `def`'s table under `conditions`: the output
    /// columns, sorted by the sort column (case-insensitively for text) and
    /// then `_record_id`, which its index holds in that order, with
    /// `:_limit` and `:_offset` to bind.
    fn page_sql(&self, def: &Definition, conditions: &str) -> String {
        let columns: Vec<String> = def.output.iter().map(|c| format!("\"{c}\"")).collect();
        let collate = match def.column(&self.sort).map(|c| c.kind) {
            Some(ColumnType::Text) => " COLLATE NOCASE",
            _ => "",
        };
        format!(
            "SELECT {} FROM \"{}\"{conditions} ORDER BY \"{}\"{collate} {}, {RECORD_ID} ASC \
             LIMIT :_limit OFFSET :_offset",
            columns.join(", "),
            def.relation,
            self.sort,
            self.direction.sql()
        )
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

fn bind_all(statement: &mut Statement<'_>, binds: &[(String, String)]) -> rusqlite::Result<()> {
    for (name, value) in binds {
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

/// The rows `page` returns, by output column.
fn page_rows(
    def: &Definition,
    page: &mut Statement<'_>,
) -> Result<Vec<Map<String, Value>>, QueryError> {
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
    Ok(rows)
}

/// The definition's option or search query `sql`, run on the rows that
/// `conditions` match: a `WITH` of the relation's own name shadows the table
/// for the statement, so the definition's SQL runs as written.
fn narrowed(def: &Definition, conditions: &str, sql: &str) -> String {
    if conditions.is_empty() {
        return sql.to_string();
    }
    let relation = &def.relation;
    format!("WITH \"{relation}\" AS (SELECT * FROM main.\"{relation}\"{conditions}) {sql}")
}

/// A date range's or multi-select's options, by its option query `sql`.
fn read_options(
    conn: &Connection,
    sql: &str,
    kind: FilterKind,
    binds: &[(String, String)],
) -> rusqlite::Result<FilterOptions> {
    let mut statement = conn.prepare(sql)?;
    bind_all(&mut statement, binds)?;
    let mut cursor = statement.raw_query();
    if kind == FilterKind::DateRange {
        let (min, max): (Option<String>, Option<String>) = match cursor.next()? {
            Some(row) => (row.get(0)?, row.get(1)?),
            None => (None, None),
        };
        return Ok(FilterOptions::DateRange {
            min: min.and_then(|v| dates::from_sql(&v)),
            max: max.and_then(|v| dates::from_sql(&v)),
        });
    }
    let mut values = Vec::new();
    while let Some(row) = cursor.next()? {
        values.push(OptionValue {
            value: row.get(0)?,
            count: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
        });
    }
    Ok(FilterOptions::Values(values))
}

/// Every filter's options but the searches', from the rows of `conn`'s
/// table, by the definition's option queries.
pub(super) fn filter_options(
    conn: &Connection,
    def: &Definition,
) -> rusqlite::Result<BTreeMap<String, FilterOptions>> {
    let mut options = BTreeMap::new();
    for filter in def
        .filters
        .iter()
        .filter(|f| f.kind != FilterKind::SearchSelect)
    {
        if let Some(sql) = def.options_sql(&filter.name) {
            options.insert(
                filter.name.clone(),
                read_options(conn, sql, filter.kind, &[])?,
            );
        }
    }
    Ok(options)
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

    /// The page `query` asks for, and how many rows match in all: every row
    /// when it sets no filter, so then nothing is counted.
    pub fn page(
        &self,
        def: &Definition,
        query: &Query,
        deadline: Instant,
    ) -> Result<Page, QueryError> {
        let (conditions, binds) = query.conditions();
        self.run(deadline, |conn| {
            let total = if query.filters.is_empty() {
                self.rows as u64
            } else {
                let sql = format!("SELECT count(*) FROM \"{}\"{conditions}", def.relation);
                let mut count = conn.prepare(&sql)?;
                bind_all(&mut count, &binds)?;
                let total: i64 = match count.raw_query().next()? {
                    Some(row) => row.get(0)?,
                    None => 0,
                };
                u64::try_from(total).unwrap_or(0)
            };

            let mut page = conn.prepare(&query.page_sql(def, &conditions))?;
            bind_all(&mut page, &binds)?;
            bind(&mut page, ":_limit", &i64::from(query.limit))?;
            bind(&mut page, ":_offset", &(query.offset as i64))?;
            Ok(Page {
                rows: page_rows(def, &mut page)?,
                total_matched: total,
                limit: query.limit,
                offset: query.offset,
            })
        })
    }

    /// Each filter's options but the searches', from the rows the other
    /// filters `query` sets match. A filter whose others are all unset keeps
    /// the options the table was built with, so with no filter set this
    /// runs nothing.
    pub fn facets(
        &self,
        def: &Definition,
        query: &Query,
        deadline: Instant,
    ) -> Result<BTreeMap<String, FilterOptions>, QueryError> {
        let mut options = self.options().clone();
        let narrowed_filters: Vec<_> = def
            .filters
            .iter()
            .filter(|f| f.kind != FilterKind::SearchSelect)
            .filter_map(|f| {
                let (conditions, binds) = query.conditions_except(Some(&f.name));
                let sql = def.options_sql(&f.name)?;
                (!conditions.is_empty()).then(|| (f, narrowed(def, &conditions, sql), binds))
            })
            .collect();
        if narrowed_filters.is_empty() {
            return Ok(options);
        }
        self.run(deadline, |conn| {
            for (filter, sql, binds) in narrowed_filters {
                options.insert(
                    filter.name.clone(),
                    read_options(conn, &sql, filter.kind, &binds)?,
                );
            }
            Ok(options)
        })
    }

    /// The values of search filter `filter` that start with `prefix`, from
    /// the rows the other filters `query` sets match.
    pub fn search(
        &self,
        def: &Definition,
        filter: &str,
        prefix: &str,
        limit: u32,
        query: &Query,
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
        let (conditions, binds) = query.conditions_except(Some(filter));
        let sql = narrowed(def, &conditions, sql);
        self.run(deadline, |conn| {
            let mut statement = conn.prepare(&sql)?;
            bind_all(&mut statement, &binds)?;
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
    use std::time::Duration;

    use super::*;
    use crate::analysis::definition::tests::{awards_report, AWARDS_REPORT};
    use crate::analysis::table::tests::only;
    use crate::analysis::table::{Conditions, Scope};

    const HEADER: &str = "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,\
                          Employer,Employer Group,Award,Award Grade,Exam Board Date";

    /// Staff number, surname, employer, employer group, award, exam board date.
    const ROWS: [[&str; 6]; 10] = [
        [
            "000123",
            "Bravo",
            "Bank A",
            "Group A",
            "Certificate",
            "01/01/2026",
        ],
        [
            "000123",
            "Bravo",
            "Bank A",
            "Group A",
            "Diploma",
            "30/09/2026",
        ],
        [
            "123",
            "Delta",
            "Bank A",
            "Group A",
            "Certificate",
            "31/12/2025",
        ],
        [
            "001234",
            "Foxtrot",
            "Bank A",
            "Group A",
            "Diploma",
            "01/10/2026",
        ],
        [
            "020001",
            "Lima",
            "Bank A Network",
            "Group A",
            "Certificate",
            "15/06/2026",
        ],
        [
            "020002",
            "Mike",
            "Bank A Network",
            "Group A",
            "Advisor",
            "15/06/2026",
        ],
        [
            "030001",
            "Oscar",
            "Bank B",
            "Group B",
            "Certificate",
            "01/01/2026",
        ],
        [
            "030002",
            "Papa",
            "Bank B Insurance",
            "Group B",
            "Diploma",
            "14/05/2026",
        ],
        [
            "040001",
            "Tango",
            "Bank C",
            "Group C",
            "Advisor",
            "10/02/2026",
        ],
        ["050001", "Charlie", "Lender D", "", "Advisor", "05/05/2026"],
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
        Scope::Only(
            names
                .iter()
                .map(|n| Conditions::from([("employer_group".to_string(), n.to_string())]))
                .collect(),
        )
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
        let group_a = table(&groups(&["Group A"]));
        assert_eq!(group_a.rows, 6);
        let page = run(&group_a, serde_json::json!({}));
        assert_eq!(page.total_matched, 6);
        assert!(column(&page, "employer_group")
            .iter()
            .all(|g| g == "Group A"));

        let network = table(&only(&[&[("employer", "Bank A Network")]]));
        assert_eq!(run(&network, serde_json::json!({})).total_matched, 2);

        let both = table(&groups(&["Group A", "Group C"]));
        assert_eq!(run(&both, serde_json::json!({})).total_matched, 7);

        let all = table(&Scope::All);
        assert_eq!(run(&all, serde_json::json!({})).total_matched, 10);

        let nothing = table(&groups(&[]));
        let page = run(&nothing, serde_json::json!({}));
        assert_eq!((page.total_matched, page.rows.len()), (0, 0));
    }

    #[test]
    fn the_definition_decides_which_columns_scope_rows() {
        let def = Definition::parse(
            AWARDS_REPORT
                .replace(
                    "employer_group = \"employer_group\"",
                    "employer_group = \"employer_group\"\nsurname = \"surname\"",
                )
                .as_bytes(),
        )
        .unwrap();
        let (first, second) = (upload(&ROWS[..6]), upload(&ROWS[6..]));
        let rows = |scope: &Scope| Table::build(&def, &[&first, &second], scope).unwrap().rows;
        assert_eq!(rows(&only(&[&[("surname", "Bravo")]])), 2);
        // An entry's conditions apply together, and entries add up.
        let delta_in_group_a = [("employer_group", "Group A"), ("surname", "Delta")];
        assert_eq!(rows(&only(&[&delta_in_group_a])), 1);
        assert_eq!(
            rows(&only(&[&delta_in_group_a, &[("employer", "Bank C")]])),
            2
        );
        assert_eq!(rows(&only(&[&[]])), 0, "no conditions match nothing");

        // The awards report declares no surname key, so an entry on it
        // applies nowhere there.
        let awards = awards_report();
        let bravo = only(&[&[("surname", "Bravo")]]);
        assert_eq!(bravo.for_definition(&awards), None);
        assert_eq!(
            only(&[&[("surname", "Bravo")], &[("employer", "Bank C")]]).for_definition(&awards),
            Some(only(&[&[("employer", "Bank C")]]))
        );
        assert_eq!(Scope::All.for_definition(&awards), Some(Scope::All));
        let bank_c_or_bravo = Table::build(
            &awards,
            &[&first, &second],
            &only(&[&[("surname", "Bravo")], &[("employer", "Bank C")]]),
        )
        .unwrap();
        assert_eq!(bank_c_or_bravo.rows, 1, "unknown keys match nothing");
    }

    #[test]
    fn options_and_searches_come_from_the_scope_only() {
        let def = awards_report();
        let group_a = table(&groups(&["Group A"]));
        let options = group_a.options();
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

        let none = Query::check(&def, &QueryRequest::default()).unwrap();
        let search = |prefix: &str, limit: u32| {
            group_a.search(&def, "staff_number", prefix, limit, &none, soon())
        };
        assert_eq!(search("00", 10).unwrap(), ["000123", "001234"]);
        assert_eq!(search("03", 10).unwrap(), Vec::<String>::new());
        assert_eq!(search("0%", 10).unwrap(), Vec::<String>::new());
        assert_eq!(search("", 1).unwrap().len(), 1);
        assert!(matches!(
            group_a.search(&def, "award", "C", 10, &none, soon()),
            Err(QueryError::Invalid(_))
        ));
        assert!(matches!(search("0", 101), Err(QueryError::Invalid(_))));
    }

    #[test]
    fn options_and_searches_follow_the_other_filters() {
        let def = awards_report();
        let all = table(&Scope::All);
        let filtered = |json: serde_json::Value| {
            Query::check(&def, &request(serde_json::json!({ "filters": json }))).unwrap()
        };
        let facets = |query: &Query| all.facets(&def, query, soon()).unwrap();
        let award_counts = |options: &BTreeMap<String, FilterOptions>| {
            let FilterOptions::Values(values) = &options["award"] else {
                panic!("award options are values");
            };
            values
                .iter()
                .map(|o| (o.value.clone(), o.count))
                .collect::<Vec<_>>()
        };

        // With nothing set, the options are the table's own.
        let none = filtered(serde_json::json!({}));
        assert_eq!(&facets(&none), all.options());

        // An award narrows the dates, but its own values stay on offer.
        let diploma = filtered(serde_json::json!({
            "award": { "mode": "selected", "values": ["Diploma"] },
        }));
        let options = facets(&diploma);
        assert_eq!(
            options["exam_board_date"],
            FilterOptions::DateRange {
                min: Some("14/05/2026".into()),
                max: Some("01/10/2026".into()),
            }
        );
        assert_eq!(award_counts(&options), award_counts(all.options()));

        // A date range narrows the awards and their counts.
        let from_june = filtered(serde_json::json!({
            "exam_board_date": { "from": "01/06/2026" },
        }));
        assert_eq!(
            award_counts(&facets(&from_june)),
            [
                ("Advisor".to_string(), 1),
                ("Certificate".to_string(), 1),
                ("Diploma".to_string(), 2)
            ]
        );

        // A search keeps to the rows the other filters match, not its own.
        let search = |query: &Query| {
            all.search(&def, "staff_number", "0", 20, query, soon())
                .unwrap()
        };
        assert_eq!(search(&diploma), ["000123", "001234", "030002"]);
        let staff = filtered(serde_json::json!({
            "staff_number": { "mode": "selected", "values": ["000123"] },
            "award": { "mode": "selected", "values": ["Diploma"] },
        }));
        assert_eq!(search(&staff), ["000123", "001234", "030002"]);
        let membership = all
            .search(&def, "membership_number", "M", 20, &staff, soon())
            .unwrap();
        assert_eq!(membership, ["M0001"]);
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
        // Ties keep upload order: 01/01/2026 is first Bravo (first upload),
        // then Oscar (second upload), on every run.
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
        assert_eq!(column(&by_name, "surname")[0], "Tango");

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
                serde_json::json!({ "filters": { "employer": { "mode": "selected", "values": ["Bank C"] } } }),
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
            serde_json::json!({ "scope": { "employer_group": "Group C" } }),
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

    /// `n` rows that tie, differ only in case, repeat and leave values
    /// empty, across four employers.
    fn varied(n: usize) -> Vec<u8> {
        let surnames = [
            "Bravo", "bravo", "Delta", "Óscar", "", "Mike", "mike", "Zulu",
        ];
        let awards = ["Certificate", "Diploma", "certificate", "", "Advisor"];
        let dates = [
            "01/01/2026",
            "15/06/2026",
            "",
            "31/12/2025",
            "01/01/2026",
            "30/09/2026",
        ];
        let employers = [
            ("Bank A", "Group A"),
            ("Bank A Network", "Group A"),
            ("Bank C", "Group C"),
            ("Lender D", ""),
        ];
        let mut csv = format!("{HEADER}\n");
        for i in 0..n {
            let (employer, group) = employers[i % employers.len()];
            csv.push_str(&format!(
                "{:06},M{:04},{},Sam,{},0{}/01/1990,{employer},{group},{},Pass,{}\n",
                (i * 37) % 50,
                i % 9,
                if i % 3 == 0 { "Mx" } else { "" },
                surnames[i % surnames.len()],
                1 + i % 9,
                awards[(i * 7) % awards.len()],
                dates[(i * 5) % dates.len()],
            ));
        }
        csv.into_bytes()
    }

    /// The page the definition's own `rows` query gives, wrapped with the
    /// sort and paging and counted, as every page ran before.
    fn wrapped(table: &Table, def: &Definition, query: &Query) -> Page {
        let (_, binds) = query.conditions();
        table
            .run(soon(), |conn| {
                let mut count = conn.prepare(&def.count_sql())?;
                bind_all(&mut count, &binds)?;
                let total: i64 = count.raw_query().next()?.map_or(Ok(0), |row| row.get(0))?;
                let mut page = conn.prepare(&def.page_sql(&query.sort, query.direction))?;
                bind_all(&mut page, &binds)?;
                bind(&mut page, ":_limit", &i64::from(query.limit))?;
                bind(&mut page, ":_offset", &(query.offset as i64))?;
                Ok(Page {
                    rows: page_rows(def, &mut page)?,
                    total_matched: u64::try_from(total).unwrap_or(0),
                    limit: query.limit,
                    offset: query.offset,
                })
            })
            .unwrap()
    }

    #[test]
    fn pages_match_the_definitions_own_rows_query() {
        let def = awards_report();
        let data = varied(300);
        let mut requests = vec![
            serde_json::json!({}),
            serde_json::json!({ "pagination": { "limit": 500 } }),
            serde_json::json!({ "pagination": { "limit": 10, "offset": 295 } }),
            serde_json::json!({ "pagination": { "offset": 1000 } }),
            serde_json::json!({ "filters": { "exam_board_date": { "from": "01/01/2026" } } }),
            serde_json::json!({ "filters": { "exam_board_date": { "to": "01/01/2026" } } }),
            serde_json::json!({ "filters": { "exam_board_date": { "from": "01/01/2026", "to": "15/06/2026" } } }),
            serde_json::json!({ "filters": { "exam_board_date": {} } }),
            serde_json::json!({ "filters": { "award": { "mode": "selected", "values": ["Certificate", "Diploma"] } } }),
            serde_json::json!({ "filters": { "award": { "mode": "selected", "values": ["certificate"] } } }),
            serde_json::json!({ "filters": { "award": { "mode": "all" } } }),
            serde_json::json!({ "filters": { "staff_number": { "mode": "selected", "values": ["000012", "000037", "999999"] } } }),
            serde_json::json!({ "filters": { "membership_number": { "mode": "selected", "values": ["M0001"] } } }),
            serde_json::json!({
                "filters": {
                    "exam_board_date": { "from": "31/12/2025", "to": "30/09/2026" },
                    "award": { "mode": "selected", "values": ["Certificate", "Advisor"] },
                    "staff_number": { "mode": "selected", "values": ["000012", "000024", "000049"] },
                },
                "sort": { "field": "surname", "direction": "desc" },
                "pagination": { "limit": 3, "offset": 1 },
            }),
        ];
        for field in &def.output {
            for direction in ["asc", "desc"] {
                requests.push(serde_json::json!({
                    "sort": { "field": field, "direction": direction },
                    "pagination": { "limit": 7, "offset": 3 },
                }));
                requests.push(serde_json::json!({
                    "filters": { "award": { "mode": "selected", "values": ["Certificate", "Advisor"] } },
                    "sort": { "field": field, "direction": direction },
                }));
            }
        }
        for scope in [Scope::All, groups(&["Group A"])] {
            let table = Table::build(&def, &[&data], &scope).unwrap();
            for json in &requests {
                let query = Query::check(&def, &request(json.clone())).unwrap();
                let page = table.page(&def, &query, soon()).unwrap();
                assert_eq!(page, wrapped(&table, &def, &query), "{scope:?} {json}");
            }
        }
    }

    /// SQLite's plan for `sql` on `table`, one step per line.
    fn plan(table: &Table, sql: &str) -> String {
        let conn = table.connection();
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let mut cursor = statement.raw_query();
        let mut steps = Vec::new();
        while let Some(row) = cursor.next().unwrap() {
            steps.push(row.get::<_, String>(3).unwrap());
        }
        steps.join("\n")
    }

    #[test]
    fn pages_and_searches_read_the_indexes() {
        let def = awards_report();
        let all = Table::build(&def, &[&varied(400)], &Scope::All).unwrap();
        let page_plan = |json: serde_json::Value| {
            let query = Query::check(&def, &request(json)).unwrap();
            let (conditions, _) = query.conditions();
            plan(&all, &query.page_sql(&def, &conditions))
        };

        // With no filter, a page walks its sort column's index: no sort.
        for column in &def.output {
            for direction in ["asc", "desc"] {
                let steps = page_plan(serde_json::json!({
                    "sort": { "field": column, "direction": direction },
                }));
                assert!(
                    steps.contains(&format!("INDEX _by_{column}")),
                    "{column} {direction}: {steps}"
                );
                assert!(
                    !steps.contains("USE TEMP B-TREE FOR ORDER BY"),
                    "{column} {direction}: {steps}"
                );
            }
        }

        // A range on the sort column reads only its part of that index.
        for direction in ["asc", "desc"] {
            let steps = page_plan(serde_json::json!({
                "filters": { "exam_board_date": { "from": "01/01/2026", "to": "30/06/2026" } },
                "sort": { "field": "exam_board_date", "direction": direction },
            }));
            assert!(
                steps.contains("SEARCH") && steps.contains("INDEX _by_exam_board_date"),
                "{direction}: {steps}"
            );
            assert!(
                !steps.contains("USE TEMP B-TREE FOR ORDER BY"),
                "{direction}: {steps}"
            );
        }

        // A selected value is a lookup in its column's exact index.
        let query = Query::check(
            &def,
            &request(serde_json::json!({
                "filters": { "staff_number": { "mode": "selected", "values": ["000012"] } },
            })),
        )
        .unwrap();
        let (conditions, _) = query.conditions();
        let steps = plan(
            &all,
            &format!("SELECT count(*) FROM \"awards\"{conditions}"),
        );
        assert!(
            steps.contains("SEARCH") && steps.contains("INDEX _exact_staff_number"),
            "{steps}"
        );

        // A search walks its column's exact index in order and stops at
        // its limit.
        for filter in ["staff_number", "membership_number"] {
            let steps = plan(&all, def.options_sql(filter).unwrap());
            assert!(
                steps.contains(&format!("INDEX _exact_{filter}")),
                "{filter}: {steps}"
            );
            assert!(!steps.contains("TEMP B-TREE"), "{filter}: {steps}");
        }
    }
}
