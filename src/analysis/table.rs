// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The table an analysis reads: the rows of a pool's uploads that one
//! caller's scope allows, in an in-memory SQLite database built for that
//! pool version and scope. Rows outside the scope are never inserted, so no
//! statement can reach them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use rusqlite::{Connection, ToSql};

use super::dates;
use super::definition::{ColumnType, Definition, RECORD_ID};
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
                let index = def
                    .columns
                    .iter()
                    .map(|c| {
                        headers
                            .iter()
                            .position(|h| h.trim() == c.header)
                            .ok_or_else(|| TableError::MissingHeader(c.header.clone()))
                    })
                    .collect::<Result<Vec<usize>, _>>()?;
                for record in reader.records() {
                    let record = record?;
                    record_id += 1;
                    values.clear();
                    for (column, &i) in def.columns.iter().zip(&index) {
                        let raw = record.get(i).map(str::trim).filter(|v| !v.is_empty());
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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
