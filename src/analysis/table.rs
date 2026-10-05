// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The table an analysis reads: the rows of a pool's uploads that one
//! caller's scope allows, in an in-memory SQLite database built for that
//! pool version and scope. Rows outside the scope are never inserted, so no
//! statement can reach them.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rusqlite::{Connection, ToSql};

use super::dates;
use super::definition::{ColumnType, Definition, RECORD_ID};

/// The rows a caller may see.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// Every row: admins.
    All,
    /// Rows whose employer group is one of `employer_groups`, or whose
    /// employer is one of `employers`. Both empty matches nothing.
    Only {
        employer_groups: BTreeSet<String>,
        employers: BTreeSet<String>,
    },
}

impl Scope {
    fn allows(&self, employer: Option<&str>, employer_group: Option<&str>) -> bool {
        match self {
            Self::All => true,
            Self::Only {
                employer_groups,
                employers,
            } => {
                employer_group.is_some_and(|g| employer_groups.contains(g))
                    || employer.is_some_and(|e| employers.contains(e))
            }
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
    /// Roughly how much memory it holds.
    pub bytes: usize,
}

impl Table {
    /// The rows of `datasets` that `scope` allows. Every row, in or out of
    /// scope, numbers `_record_id` in the order the uploads and their rows
    /// come, so a row has the same key in every scope's table.
    pub fn build(def: &Definition, datasets: &[&[u8]], scope: &Scope) -> Result<Self, TableError> {
        let position = |name: &str| {
            def.columns
                .iter()
                .position(|c| c.name == name)
                .ok_or_else(|| TableError::MissingHeader(name.to_string()))
        };
        let (employer, employer_group) = (position(&def.employer)?, position(&def.employer_group)?);
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
        let (mut record_id, mut rows, mut bytes) = (0i64, 0usize, 0usize);
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
                    if !scope.allows(
                        values[employer].as_deref(),
                        values[employer_group].as_deref(),
                    ) {
                        continue;
                    }
                    let params: Vec<&dyn ToSql> = std::iter::once(&record_id as &dyn ToSql)
                        .chain(values.iter().map(|v| v as &dyn ToSql))
                        .collect();
                    statement.execute(params.as_slice())?;
                    rows += 1;
                    bytes += 64
                        + values
                            .iter()
                            .map(|v| 16 + v.as_ref().map_or(0, String::len))
                            .sum::<usize>();
                }
            }
        }
        tx.commit()?;
        conn.pragma_update(None, "query_only", true)?;
        Ok(Self {
            conn: Mutex::new(conn),
            rows,
            bytes,
        })
    }

    pub(super) fn connection(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
