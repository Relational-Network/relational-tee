// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The table an analysis reads: the rows of a pool's uploads that one
//! caller's scope allows, in an in-memory SQLite database built for that
//! pool version and scope. Rows outside the scope are never inserted, so no
//! statement can reach them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use rusqlite::{Connection, ToSql};

use super::dates;
use super::definition::{Column, ColumnType, Definition, RECORD_ID};
use super::query::{filter_options, FilterOptions, DEADLINE_STEPS};
use super::runner::DEADLINE;

/// Scope keys, such as `employer_group`, each with the value a row's column
/// for that key must hold exactly. A row matches when it meets them all.
pub type Conditions = BTreeMap<String, String>;

/// The rows a caller may see.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// Every row: admins.
    All,
    /// The rows that match any of these. None matches nothing, and neither
    /// do empty conditions or conditions on a key the definition doesn't
    /// declare.
    Only(BTreeSet<Conditions>),
}

impl Scope {
    /// The part of this scope `def` can apply, or `None` if nothing is left.
    /// Conditions on a key `def` doesn't declare can't be met by its rows,
    /// so they go, whole.
    pub fn for_definition(&self, def: &Definition) -> Option<Self> {
        match self {
            Self::All => Some(Self::All),
            Self::Only(entries) => {
                let kept: BTreeSet<Conditions> = entries
                    .iter()
                    .filter(|c| !c.is_empty() && c.keys().all(|k| def.scope.contains_key(k)))
                    .cloned()
                    .collect();
                (!kept.is_empty()).then_some(Self::Only(kept))
            }
        }
    }

    /// Whether a row is in scope. `positions` gives each scope key's
    /// column in `values`.
    fn allows(&self, positions: &BTreeMap<&str, usize>, values: &[Option<String>]) -> bool {
        match self {
            Self::All => true,
            Self::Only(entries) => entries.iter().any(|conditions| {
                !conditions.is_empty()
                    && conditions.iter().all(|(key, value)| {
                        positions
                            .get(key.as_str())
                            .and_then(|&i| values[i].as_deref())
                            .is_some_and(|v| v == value)
                    })
            }),
        }
    }
}

/// Why a table couldn't be built.
#[derive(Debug)]
pub enum TableError {
    /// An upload has no column the definition reads.
    MissingHeader(String),
    Csv(csv::Error),
    Sql(rusqlite::Error),
}

impl std::fmt::Display for TableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader(header) => write!(f, "an upload has no {header:?} column"),
            Self::Csv(e) => write!(f, "an upload isn't valid CSV: {e}"),
            Self::Sql(e) => write!(f, "SQLite failed: {e}"),
        }
    }
}

impl std::error::Error for TableError {}

impl From<csv::Error> for TableError {
    fn from(e: csv::Error) -> Self {
        Self::Csv(e)
    }
}

impl From<rusqlite::Error> for TableError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}

/// A caller's rows, ready for queries.
pub struct Table {
    conn: Mutex<Connection>,
    /// How many rows it holds.
    pub rows: usize,
    /// The memory SQLite holds for it, indexes included.
    pub bytes: usize,
    options: BTreeMap<String, FilterOptions>,
}

impl Table {
    /// The rows of `datasets` that `scope` allows, indexed for every sort
    /// and filter, with each filter's options computed once. Every row, in
    /// or out of scope, numbers `_record_id` in the order the uploads and
    /// their rows come, so a row has the same key in every scope's table.
    pub fn build(def: &Definition, datasets: &[&[u8]], scope: &Scope) -> Result<Self, TableError> {
        let position = |name: &str| {
            def.columns
                .iter()
                .position(|c| c.name == name)
                .ok_or_else(|| TableError::MissingHeader(name.to_string()))
        };
        let positions = def
            .scope
            .iter()
            .map(|(key, column)| Ok((key.as_str(), position(column)?)))
            .collect::<Result<BTreeMap<&str, usize>, TableError>>()?;
        let names: Vec<String> = def
            .columns
            .iter()
            .map(|c| format!("\"{}\"", c.name))
            .collect();
        let slots: Vec<String> = (1..=def.columns.len() + 1)
            .map(|i| format!("?{i}"))
            .collect();
        let insert = format!(
            "INSERT INTO \"{}\" ({RECORD_ID}, {}) VALUES ({})",
            def.relation,
            names.join(", "),
            slots.join(", ")
        );

        let mut conn = Connection::open_in_memory()?;
        conn.execute_batch(&def.create_table_sql())?;
        let (mut record_id, mut rows) = (0i64, 0usize);
        let tx = conn.transaction()?;
        {
            let mut statement = tx.prepare(&insert)?;
            let mut values: Vec<Option<String>> = Vec::with_capacity(def.columns.len());
            for data in datasets {
                let mut reader = csv::ReaderBuilder::new()
                    .has_headers(true)
                    .from_reader(*data);
                let headers = reader.headers()?.clone();
                let index = header_positions(&headers, &def.columns)?;
                for record in reader.records() {
                    let record = record?;
                    record_id += 1;
                    values.clear();
                    for (column, &i) in def.columns.iter().zip(&index) {
                        let raw = cell(&record, i);
                        values.push(match column.kind {
                            ColumnType::Text => raw.map(String::from),
                            ColumnType::Date => raw.and_then(dates::to_sql),
                        });
                    }
                    if !scope.allows(&positions, &values) {
                        continue;
                    }
                    let params: Vec<&dyn ToSql> = std::iter::once(&record_id as &dyn ToSql)
                        .chain(values.iter().map(|v| v as &dyn ToSql))
                        .collect();
                    statement.execute(params.as_slice())?;
                    rows += 1;
                }
            }
        }
        tx.commit()?;
        conn.execute_batch(&def.create_index_sql())?;
        let page_count: i64 = conn.pragma_query_value(None, "page_count", |row| row.get(0))?;
        let page_size: i64 = conn.pragma_query_value(None, "page_size", |row| row.get(0))?;
        conn.pragma_update(None, "query_only", true)?;

        let deadline = Instant::now() + DEADLINE;
        conn.progress_handler(DEADLINE_STEPS, Some(move || Instant::now() >= deadline))?;
        let options = filter_options(&conn, def)?;
        conn.progress_handler(0, None::<fn() -> bool>)?;
        Ok(Self {
            conn: Mutex::new(conn),
            rows,
            bytes: usize::try_from(page_count.saturating_mul(page_size)).unwrap_or(usize::MAX),
            options,
        })
    }

    /// Each filter's options but the searches', from this table's rows.
    pub fn options(&self) -> &BTreeMap<String, FilterOptions> {
        &self.options
    }

    pub(super) fn connection(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Where each of `columns` is in an upload with these headers.
fn header_positions<'a>(
    headers: &csv::StringRecord,
    columns: impl IntoIterator<Item = &'a Column>,
) -> Result<Vec<usize>, TableError> {
    columns
        .into_iter()
        .map(|c| {
            headers
                .iter()
                .position(|h| h.trim() == c.header)
                .ok_or_else(|| TableError::MissingHeader(c.header.clone()))
        })
        .collect()
}

/// A cell as a table holds it: trimmed, and none if that leaves nothing.
fn cell(record: &csv::StringRecord, i: usize) -> Option<&str> {
    record.get(i).map(str::trim).filter(|v| !v.is_empty())
}

/// The rows that hold one combination of scope values, in the order of
/// [`ScopeCounts::keys`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combination {
    pub values: Vec<Option<String>>,
    pub rows: u64,
}

/// How many rows of some uploads hold each combination of a definition's
/// scope values. Values are read as a table reads them, so a scope decides
/// a combination as it decides each of that combination's rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeCounts {
    /// The definition's scope keys, in order.
    pub keys: Vec<String>,
    /// Every combination that occurs, in order.
    pub combinations: Vec<Combination>,
}

impl ScopeCounts {
    pub fn count(def: &Definition, datasets: &[&[u8]]) -> Result<Self, TableError> {
        let columns = def
            .scope
            .values()
            .map(|name| {
                def.column(name)
                    .ok_or_else(|| TableError::MissingHeader(name.clone()))
            })
            .collect::<Result<Vec<&Column>, _>>()?;
        let mut counts: HashMap<Vec<Option<String>>, u64> = HashMap::new();
        for data in datasets {
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(true)
                .from_reader(*data);
            let headers = reader.headers()?.clone();
            let index = header_positions(&headers, columns.iter().copied())?;
            for record in reader.records() {
                let record = record?;
                let values = index
                    .iter()
                    .map(|&i| cell(&record, i).map(String::from))
                    .collect();
                *counts.entry(values).or_default() += 1;
            }
        }
        let mut combinations: Vec<Combination> = counts
            .into_iter()
            .map(|(values, rows)| Combination { values, rows })
            .collect();
        combinations.sort_unstable_by(|a, b| a.values.cmp(&b.values));
        Ok(Self {
            keys: def.scope.keys().cloned().collect(),
            combinations,
        })
    }

    /// Every row counted.
    pub fn rows(&self) -> u64 {
        self.combinations.iter().map(|c| c.rows).sum()
    }

    /// The combinations `scope` lets into a table, and those it keeps out.
    pub fn split(&self, scope: &Scope) -> (Vec<&Combination>, Vec<&Combination>) {
        let positions: BTreeMap<&str, usize> = self
            .keys
            .iter()
            .enumerate()
            .map(|(i, key)| (key.as_str(), i))
            .collect();
        self.combinations
            .iter()
            .partition(|c| scope.allows(&positions, &c.values))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::analysis::definition::tests::awards_report;
    use crate::data_validation::tests::AWARDS_HEADER;

    #[test]
    fn scope_counts_read_values_as_tables_do_and_scopes_decide_them_alike() {
        let def = awards_report();
        let first = format!(
            "{AWARDS_HEADER}\n\
             1,M1,Mx,Sam,Alpha,01/01/1990,Bank A,Group A,Certificate,Pass,01/01/2026\n\
             2,M2,Mx,Sam,Bravo,01/01/1990, Bank A ,Group A,Diploma,Pass,02/01/2026\n\
             3,M3,Mx,Sam,Charlie,01/01/1990,Bank A Network,Group A,Certificate,Pass,03/01/2026\n\
             4,M4,Mx,Sam,Delta,01/01/1990,Bank B,,Certificate,Pass,04/01/2026\n"
        );
        let second = "Employer Group,Staff Number,Membership Number,Title,First Name,Surname,\
                      Date of Birth,Employer,Award,Award Grade,Exam Board Date\n\
                      Group B,5,M5,Mx,Sam,Echo,01/01/1990,Bank B,Certificate,Pass,05/01/2026\n";
        let datasets = [first.as_bytes(), second.as_bytes()];
        let counts = ScopeCounts::count(&def, &datasets).unwrap();
        assert_eq!(counts.keys, ["employer", "employer_group"]);
        let combination = |employer: &str, group: Option<&str>, rows| Combination {
            values: vec![Some(employer.into()), group.map(String::from)],
            rows,
        };
        assert_eq!(
            counts.combinations,
            [
                combination("Bank A", Some("Group A"), 2),
                combination("Bank A Network", Some("Group A"), 1),
                combination("Bank B", None, 1),
                combination("Bank B", Some("Group B"), 1),
            ]
        );
        assert_eq!(counts.rows(), 5);

        let scope = only(&[
            &[("employer_group", "Group A")],
            &[("employer", "Bank B"), ("employer_group", "Group B")],
        ]);
        let (allowed, kept_out) = counts.split(&scope);
        let table = Table::build(&def, &datasets, &scope).unwrap();
        assert_eq!(
            allowed.iter().map(|c| c.rows).sum::<u64>(),
            table.rows as u64
        );
        assert_eq!(kept_out, [&combination("Bank B", None, 1)]);
        assert!(counts.split(&Scope::All).1.is_empty());
    }

    /// The scope of these entries, each a list of conditions.
    pub(crate) fn only(entries: &[&[(&str, &str)]]) -> Scope {
        Scope::Only(
            entries
                .iter()
                .map(|conditions| {
                    conditions
                        .iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect()
                })
                .collect(),
        )
    }
}
