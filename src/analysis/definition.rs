// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Analysis definitions: the static TOML file a pool's Execute DRT pins by
//! its SHA-256 (`drt-examples/` holds them). A definition is checked once,
//! when the pool is created: its keys, names, filters and paging, and every
//! SQL statement, which must be read-only and may use only the parameters its
//! filters define.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::data_validation::{FieldSchema, FieldType};

/// The largest page a definition may allow.
pub const MAX_PAGE_SIZE: u32 = 500;

/// The largest definition the worker accepts.
pub const MAX_DEFINITION_BYTES: usize = 256 * 1024;

/// The internal row key every `rows` query returns: the tie-break that makes
/// paging deterministic. It is never part of a page.
pub const RECORD_ID: &str = "_record_id";

/// The parameters an option query of a `search_select` filter may use.
const SEARCH_PARAMS: [&str; 2] = [":search", ":limit"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    Text,
    /// DD/MM/YYYY in the CSV and the API; `YYYY-MM-DD` inside SQLite.
    Date,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterKind {
    DateRange,
    MultiSelect,
    SearchSelect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Asc,
    Desc,
}

impl Direction {
    fn sql(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

/// A column: its name in SQL, the CSV header it comes from, and its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub header: String,
    pub kind: ColumnType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub name: String,
    pub kind: FilterKind,
}

/// Why a definition was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionError(pub String);

impl std::fmt::Display for DefinitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DefinitionError {}

fn refuse<T>(message: impl Into<String>) -> Result<T, DefinitionError> {
    Err(DefinitionError(message.into()))
}

/// A checked definition.
#[derive(Debug, Clone)]
pub struct Definition {
    pub analysis_id: String,
    pub display_name: String,
    pub relation: String,
    /// The output columns in output order, then any others by name.
    pub columns: Vec<Column>,
    /// The columns the caller's employer scope applies to.
    pub employer: String,
    pub employer_group: String,
    pub filters: Vec<Filter>,
    pub output: Vec<String>,
    pub default_sort: (String, Direction),
    pub page_default: u32,
    pub page_max: u32,
    rows_sql: String,
    options_sql: BTreeMap<String, String>,
    /// SHA-256 of the file, which the Execute DRT records on-chain.
    pub sha256: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    analysis_id: String,
    display_name: String,
    relation: String,
    columns: BTreeMap<String, RawColumn>,
    scope: RawScope,
    #[serde(default)]
    filters: BTreeMap<String, FilterKind>,
    output: RawOutput,
    sql: RawSql,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawColumn {
    header: String,
    #[serde(rename = "type")]
    kind: ColumnType,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScope {
    employer: String,
    employer_group: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutput {
    columns: Vec<String>,
    default_sort: RawSort,
    page_size: RawPageSize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSort {
    column: String,
    direction: Direction,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPageSize {
    default: u32,
    max: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSql {
    rows: String,
    #[serde(default)]
    options: BTreeMap<String, String>,
}

/// A name SQL can use unquoted: lowercase letters, digits and underscores,
/// starting with a letter.
fn is_sql_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_analysis_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl Definition {
    /// Parse and check the definition in `bytes`.
    pub fn parse(bytes: &[u8]) -> Result<Self, DefinitionError> {
        if bytes.len() > MAX_DEFINITION_BYTES {
            return refuse(format!(
                "the definition is over {MAX_DEFINITION_BYTES} bytes"
            ));
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return refuse("the definition isn't UTF-8");
        };
        let raw: Raw = toml::from_str(text)
            .map_err(|e| DefinitionError(format!("the definition isn't valid: {e}")))?;
        let definition = Self::check(raw, Sha256::digest(bytes).into())?;
        definition.check_sql()?;
        Ok(definition)
    }

    fn check(raw: Raw, sha256: [u8; 32]) -> Result<Self, DefinitionError> {
        if !is_analysis_id(&raw.analysis_id) {
            return refuse("analysis_id must be 1-64 lowercase letters, digits and hyphens");
        }
        let display_name = raw.display_name.trim();
        if display_name.is_empty() || display_name.chars().count() > 100 {
            return refuse("display_name must be 1-100 characters");
        }
        if !is_sql_name(&raw.relation) {
            return refuse("relation must be a lowercase SQL name");
        }
        if raw.columns.is_empty() {
            return refuse("the definition has no columns");
        }
        let mut headers = BTreeSet::new();
        for (name, column) in &raw.columns {
            if !is_sql_name(name) {
                return refuse(format!("column {name:?} must be a lowercase SQL name"));
            }
            let header = &column.header;
            if header.trim().is_empty()
                || header.trim() != header
                || header.chars().count() > 128
                || header.chars().any(char::is_control)
            {
                return refuse(format!(
                    "column {name}'s header must be 1-128 characters, without surrounding spaces"
                ));
            }
            if !headers.insert(header.as_str()) {
                return refuse(format!("two columns read the header {header:?}"));
            }
        }
        let kind_of = |name: &str| raw.columns.get(name).map(|c| c.kind);

        for (role, name) in [
            ("employer", &raw.scope.employer),
            ("employer_group", &raw.scope.employer_group),
        ] {
            if kind_of(name) != Some(ColumnType::Text) {
                return refuse(format!("scope.{role} must name a text column"));
            }
        }
        if raw.scope.employer == raw.scope.employer_group {
            return refuse("scope.employer and scope.employer_group must differ");
        }

        for (name, kind) in &raw.filters {
            let Some(column) = kind_of(name) else {
                return refuse(format!("filter {name} names no column"));
            };
            if *name == raw.scope.employer || *name == raw.scope.employer_group {
                return refuse(format!("filter {name} is a scope column"));
            }
            let expected = match kind {
                FilterKind::DateRange => ColumnType::Date,
                FilterKind::MultiSelect | FilterKind::SearchSelect => ColumnType::Text,
            };
            if column != expected {
                return refuse(format!("filter {name} doesn't fit its column's type"));
            }
        }
        let filter_names: BTreeSet<&String> = raw.filters.keys().collect();
        let option_names: BTreeSet<&String> = raw.sql.options.keys().collect();
        if filter_names != option_names {
            return refuse("sql.options must have exactly one query per filter");
        }

        let output = raw.output.columns;
        if output.is_empty() {
            return refuse("output.columns is empty");
        }
        let mut seen = BTreeSet::new();
        for name in &output {
            if kind_of(name).is_none() {
                return refuse(format!("output column {name} names no column"));
            }
            if !seen.insert(name.as_str()) {
                return refuse(format!("output column {name} is listed twice"));
            }
        }
        if !seen.contains(raw.output.default_sort.column.as_str()) {
            return refuse("output.default_sort must name an output column");
        }
        let RawPageSize { default, max } = raw.output.page_size;
        if default == 0 || default > max || max > MAX_PAGE_SIZE {
            return refuse(format!(
                "output.page_size needs 1 <= default <= max <= {MAX_PAGE_SIZE}"
            ));
        }

        let columns: Vec<Column> = output
            .iter()
            .map(|name| (name, &raw.columns[name]))
            .chain(
                raw.columns
                    .iter()
                    .filter(|(name, _)| !seen.contains(name.as_str())),
            )
            .map(|(name, column)| Column {
                name: name.clone(),
                header: column.header.clone(),
                kind: column.kind,
            })
            .collect();

        Ok(Self {
            analysis_id: raw.analysis_id,
            display_name: display_name.to_string(),
            relation: raw.relation,
            columns,
            employer: raw.scope.employer,
            employer_group: raw.scope.employer_group,
            filters: raw
                .filters
                .into_iter()
                .map(|(name, kind)| Filter { name, kind })
                .collect(),
            output,
            default_sort: (
                raw.output.default_sort.column,
                raw.output.default_sort.direction,
            ),
            page_default: default,
            page_max: max,
            rows_sql: raw
                .sql
                .rows
                .trim()
                .trim_end_matches(';')
                .trim_end()
                .to_string(),
            options_sql: raw
                .sql
                .options
                .into_iter()
                .map(|(name, sql)| {
                    (
                        name,
                        sql.trim().trim_end_matches(';').trim_end().to_string(),
                    )
                })
                .collect(),
            sha256,
        })
    }

    /// The pool's schema: each column's header and type. Any value may be
    /// empty.
    pub fn schema(&self) -> Vec<FieldSchema> {
        self.columns
            .iter()
            .map(|c| FieldSchema {
                name: c.header.clone(),
                field_type: match c.kind {
                    ColumnType::Text => FieldType::Text,
                    ColumnType::Date => FieldType::Date,
                },
                nullable: true,
            })
            .collect()
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    pub fn filter(&self, name: &str) -> Option<&Filter> {
        self.filters.iter().find(|f| f.name == name)
    }

    /// The parameters the `rows` query may use, which the filters define.
    fn row_params(&self) -> BTreeSet<String> {
        self.filters
            .iter()
            .flat_map(|f| match f.kind {
                FilterKind::DateRange => {
                    vec![format!(":{}_from", f.name), format!(":{}_to", f.name)]
                }
                FilterKind::MultiSelect | FilterKind::SearchSelect => vec![format!(":{}", f.name)],
            })
            .collect()
    }

    /// The table the SQL reads: `_record_id`, then every column, as text.
    pub(crate) fn create_table_sql(&self) -> String {
        let columns: Vec<String> = self
            .columns
            .iter()
            .map(|c| format!("\"{}\" TEXT", c.name))
            .collect();
        format!(
            "CREATE TABLE \"{}\" ({RECORD_ID} INTEGER PRIMARY KEY, {})",
            self.relation,
            columns.join(", ")
        )
    }

    /// One page of the `rows` query: sorted by `sort` (case-insensitively for
    /// text), then `_record_id`, with `:_limit` and `:_offset` bound.
    pub(crate) fn page_sql(&self, sort: &str, direction: Direction) -> String {
        let columns: Vec<String> = self.output.iter().map(|c| format!("\"{c}\"")).collect();
        let collate = match self.column(sort).map(|c| c.kind) {
            Some(ColumnType::Text) => " COLLATE NOCASE",
            _ => "",
        };
        format!(
            "SELECT {} FROM ({}) ORDER BY \"{sort}\"{collate} {}, {RECORD_ID} ASC \
             LIMIT :_limit OFFSET :_offset",
            columns.join(", "),
            self.rows_sql,
            direction.sql()
        )
    }

    /// How many rows the `rows` query matches.
    pub(crate) fn count_sql(&self) -> String {
        format!("SELECT count(*) FROM ({})", self.rows_sql)
    }

    pub(crate) fn options_sql(&self, filter: &str) -> Option<&str> {
        self.options_sql.get(filter).map(String::as_str)
    }

    /// Prepare every statement against an empty table, as queries will run.
    fn check_sql(&self) -> Result<(), DefinitionError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| DefinitionError(format!("SQLite unavailable: {e}")))?;
        conn.execute_batch(&self.create_table_sql())
            .map_err(|e| DefinitionError(format!("the columns don't make a table: {e}")))?;

        let row_params = self.row_params();
        let rows = check_statement(&conn, "sql.rows", &self.rows_sql, |p| {
            row_params.contains(p)
        })?;
        for name in std::iter::once(RECORD_ID).chain(self.output.iter().map(String::as_str)) {
            if !rows.iter().any(|c| c == name) {
                return refuse(format!("sql.rows must return {name}"));
            }
        }
        let wrapped = self.page_sql(&self.default_sort.0, self.default_sort.1);
        check_statement(&conn, "sql.rows", &wrapped, |p| {
            row_params.contains(p) || p == ":_limit" || p == ":_offset"
        })?;
        check_statement(&conn, "sql.rows", &self.count_sql(), |p| {
            row_params.contains(p)
        })?;

        for filter in &self.filters {
            let label = format!("sql.options.{}", filter.name);
            let sql = &self.options_sql[&filter.name];
            let (allowed, returns): (&[&str], &[&str]) = match filter.kind {
                FilterKind::DateRange => (&[], &["min", "max"]),
                FilterKind::MultiSelect => (&[], &["value", "count"]),
                FilterKind::SearchSelect => (&SEARCH_PARAMS, &["value"]),
            };
            let columns = check_statement(&conn, &label, sql, |p| allowed.contains(&p))?;
            if columns != returns {
                return refuse(format!("{label} must return {}", returns.join(", ")));
            }
        }
        Ok(())
    }
}

/// Prepare `sql`, require it to be read-only with only parameters `allowed`
/// admits, and return its result columns.
fn check_statement(
    conn: &Connection,
    label: &str,
    sql: &str,
    allowed: impl Fn(&str) -> bool,
) -> Result<Vec<String>, DefinitionError> {
    let statement = conn
        .prepare(sql)
        .map_err(|e| DefinitionError(format!("{label} doesn't prepare: {e}")))?;
    if !statement.readonly() {
        return refuse(format!("{label} must be read-only"));
    }
    for index in 1..=statement.parameter_count() {
        match statement.parameter_name(index) {
            Some(name) if name.starts_with(':') && allowed(name) => {}
            Some(name) => return refuse(format!("{label} may not use the parameter {name}")),
            None => return refuse(format!("{label} may use only named parameters")),
        }
    }
    Ok(statement
        .column_names()
        .into_iter()
        .map(String::from)
        .collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const AWARDS_REPORT: &str =
        include_str!("../../drt-examples/awards-report/awards-report-v1.toml");

    pub(crate) fn awards_report() -> Definition {
        Definition::parse(AWARDS_REPORT.as_bytes()).unwrap()
    }

    fn refused(toml: &str) -> String {
        Definition::parse(toml.as_bytes()).unwrap_err().0
    }

    #[test]
    fn the_awards_report_is_a_valid_definition() {
        let def = awards_report();
        assert_eq!(def.analysis_id, "awards-report-v1");
        assert_eq!(def.columns.len(), 11);
        assert_eq!(def.columns[0].header, "Staff Number");
        assert_eq!(def.columns[10].header, "Exam Board Date");
        assert_eq!(
            def.default_sort,
            ("exam_board_date".into(), Direction::Desc)
        );
        assert_eq!((def.page_default, def.page_max), (100, 500));
        assert_eq!(def.filters.len(), 4);
        assert_eq!(def.sha256, <[u8; 32]>::from(Sha256::digest(AWARDS_REPORT)));
    }

    #[test]
    fn unknown_keys_are_refused() {
        let toml = AWARDS_REPORT.replace(
            "relation     = \"awards\"",
            "relation = \"awards\"\nextra = 1",
        );
        assert!(
            refused(&toml).contains("unknown field"),
            "{}",
            refused(&toml)
        );
    }

    #[test]
    fn statements_must_be_read_only() {
        let toml = AWARDS_REPORT.replace(
            "SELECT award AS value, count(*) AS count\nFROM awards WHERE award IS NOT NULL\n\
             GROUP BY award ORDER BY award",
            "DELETE FROM awards RETURNING award AS value, 1 AS count",
        );
        assert!(refused(&toml).contains("read-only"), "{}", refused(&toml));
    }

    #[test]
    fn statements_may_use_only_their_filters_parameters() {
        let toml = AWARDS_REPORT.replace(
            "(:award             IS NULL",
            "(:employer_group IS NULL OR :award IS NULL",
        );
        assert!(
            refused(&toml).contains(":employer_group"),
            "{}",
            refused(&toml)
        );

        let toml =
            AWARDS_REPORT.replace("LIMIT :limit\n'''\nmembership", "LIMIT ?\n'''\nmembership");
        assert!(
            refused(&toml).contains("named parameters"),
            "{}",
            refused(&toml)
        );
    }

    #[test]
    fn rows_must_return_the_record_id_and_every_output_column() {
        let toml = AWARDS_REPORT.replace("SELECT _record_id,", "SELECT");
        assert!(refused(&toml).contains("_record_id"), "{}", refused(&toml));
        let toml = AWARDS_REPORT.replacen("date_of_birth, employer,", "employer,", 1);
        assert!(
            refused(&toml).contains("date_of_birth"),
            "{}",
            refused(&toml)
        );
    }

    #[test]
    fn scope_columns_can_not_be_filters() {
        let toml = AWARDS_REPORT
            .replace(
                "award             = \"multi_select\"",
                "employer_group    = \"multi_select\"",
            )
            .replace("award = '''", "employer_group = '''");
        assert!(
            refused(&toml).contains("scope column"),
            "{}",
            refused(&toml)
        );
    }

    #[test]
    fn every_filter_needs_its_options_query() {
        let toml = AWARDS_REPORT.replace("award = '''", "award_x = '''");
        assert!(
            refused(&toml).contains("one query per filter"),
            "{}",
            refused(&toml)
        );
    }

    #[test]
    fn names_and_paging_are_checked() {
        let toml = AWARDS_REPORT.replace("\"awards-report-v1\"", "\"Awards Report\"");
        assert!(refused(&toml).contains("analysis_id"));
        let toml = AWARDS_REPORT.replace("max = 500", "max = 501");
        assert!(refused(&toml).contains("page_size"));
        let toml = AWARDS_REPORT.replace("default = 100", "default = 0");
        assert!(refused(&toml).contains("page_size"));
        let toml = AWARDS_REPORT.replace("column = \"exam_board_date\"", "column = \"nope\"");
        assert!(refused(&toml).contains("default_sort"));
        let toml = AWARDS_REPORT.replace("header = \"Award\",", "header = \"Award Grade\",");
        assert!(refused(&toml).contains("two columns"));
    }

    #[test]
    fn a_trailing_semicolon_is_harmless() {
        let toml = AWARDS_REPORT.replace(
            "membership_number IN (SELECT value FROM json_each(:membership_number)))\n'''",
            "membership_number IN (SELECT value FROM json_each(:membership_number)));\n'''",
        );
        Definition::parse(toml.as_bytes()).unwrap();
    }
}
