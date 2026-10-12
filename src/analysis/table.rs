// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The table an analysis reads: the rows of a pool's uploads that one
//! caller's scope allows, in an in-memory SQLite database built for that
//! pool version and scope. Rows outside the scope are never inserted, so no
//! statement can reach them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rusqlite::{Connection, ToSql};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use utoipa::ToSchema;

use super::dates;
use super::definition::{Column, ColumnType, Definition, RECORD_ID};
use super::query::{filter_options, FilterOptions, DEADLINE_STEPS};
use crate::budget::Reservation;
use crate::work::{Stop, Stopped};

/// How many CSV records a build reads between checks of its stop.
const RECORDS_PER_CHECK: i64 = 1024;

/// Scope keys, such as `employer_group`, each with the value a row's column
/// for that key must hold exactly. A row matches when it meets them all.
pub type Conditions = BTreeMap<String, String>;

/// What a grant lets its analyst see: the rows whose column for scope key
/// `key` holds `value` exactly, such as employer group "Group A". A grant
/// sees the rows of any of its targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// A scope key the pool's definition declares, such as `employer`.
    pub key: String,
    /// The value, as the data holds it.
    pub value: String,
}

/// The most targets a grant holds.
pub const MAX_TARGETS: usize = 100;

/// The longest target value, in bytes.
const MAX_VALUE: usize = 256;

/// `targets` as a grant's scope under `def`, or why they can't be one. A
/// value is compared exactly, as the data holds it, so it must not carry
/// stray spaces; the same name under two keys is two targets.
pub fn check_targets(def: &Definition, targets: &[Target]) -> Result<BTreeSet<Target>, String> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(format!(
            "a grant sees 1 to {MAX_TARGETS} targets, such as {{ \"key\": \"employer_group\", \"value\": \"Group A\" }}"
        ));
    }
    let mut set = BTreeSet::new();
    for (i, target) in targets.iter().enumerate() {
        if !def.scope.contains_key(&target.key) {
            let keys: Vec<&str> = def.scope.keys().map(String::as_str).collect();
            return Err(format!(
                "scope[{i}].key {:?} isn't a scope key of this analysis: one of {}",
                target.key,
                keys.join(", ")
            ));
        }
        let value = &target.value;
        if value.is_empty()
            || value.len() > MAX_VALUE
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(format!(
                "scope[{i}].value must be 1 to {MAX_VALUE} bytes, with no surrounding spaces or control characters"
            ));
        }
        if !set.insert(target.clone()) {
            return Err(format!("scope[{i}] repeats an earlier target"));
        }
    }
    Ok(set)
}

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
    /// The rows of any of `targets`.
    pub fn of(targets: &BTreeSet<Target>) -> Self {
        Self::Only(
            targets
                .iter()
                .map(|t| Conditions::from([(t.key.clone(), t.value.clone())]))
                .collect(),
        )
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
    /// The build ran out of time, or no one waits for it any more.
    Stopped,
}

impl std::fmt::Display for TableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader(header) => write!(f, "an upload has no {header:?} column"),
            Self::Csv(e) => write!(f, "an upload isn't valid CSV: {e}"),
            Self::Sql(e) => write!(f, "SQLite failed: {e}"),
            Self::Stopped => f.write_str("building the table ran out of time"),
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
        match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::OperationInterrupted) => Self::Stopped,
            _ => Self::Sql(e),
        }
    }
}

impl From<Stopped> for TableError {
    fn from(_: Stopped) -> Self {
        Self::Stopped
    }
}

/// A caller's rows, ready for queries.
pub struct Table {
    conn: Mutex<Connection>,
    /// How many rows it holds.
    pub rows: usize,
    /// The memory it holds: SQLite's, indexes included, and its filters'
    /// options.
    pub bytes: usize,
    options: BTreeMap<String, FilterOptions>,
    /// Its share of the worker's memory budget, held while it lives.
    held: Option<Reservation>,
    /// One request's work at a time, taken before a thread is.
    turn: Arc<Semaphore>,
}

impl Table {
    /// The rows of `datasets` that `scope` allows, indexed for every sort
    /// and filter, with each filter's options computed once. Every row, in
    /// or out of scope, numbers `_record_id` in the order the uploads and
    /// their rows come, so a row has the same key in every scope's table.
    /// It stops, between records and inside SQLite, once `stop` fires.
    pub fn build(
        def: &Definition,
        datasets: &[&[u8]],
        scope: &Scope,
        stop: &Stop,
    ) -> Result<Self, TableError> {
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
        // Rows never reach a disk, and the image has no temporary directory:
        // the files SQLite spills large index builds and sorts to stay in
        // memory too.
        conn.pragma_update(None, "temp_store", "MEMORY")?;
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
                    if record_id % RECORDS_PER_CHECK == 0 {
                        stop.check()?;
                    }
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
        stop.check()?;
        let stopping = stop.clone();
        conn.progress_handler(DEADLINE_STEPS, Some(move || stopping.stopped()))?;
        conn.execute_batch(&def.create_index_sql())?;
        let page_count: i64 = conn.pragma_query_value(None, "page_count", |row| row.get(0))?;
        let page_size: i64 = conn.pragma_query_value(None, "page_size", |row| row.get(0))?;
        conn.pragma_update(None, "query_only", true)?;
        let options = filter_options(&conn, def)?;
        conn.progress_handler(0, None::<fn() -> bool>)?;
        let pages = usize::try_from(page_count.saturating_mul(page_size)).unwrap_or(usize::MAX);
        Ok(Self {
            conn: Mutex::new(conn),
            rows,
            bytes: pages.saturating_add(options.values().map(FilterOptions::bytes).sum()),
            options,
            held: None,
            turn: Arc::new(Semaphore::new(1)),
        })
    }

    /// This table's turn: once earlier requests' work on it is done.
    pub async fn turn(&self) -> Option<OwnedSemaphorePermit> {
        self.turn.clone().acquire_owned().await.ok()
    }

    /// Hold `reservation` for as long as the table lives.
    pub fn hold(&mut self, reservation: Reservation) {
        self.held = Some(reservation);
    }

    /// Each filter's options but the searches', from this table's rows.
    pub fn options(&self) -> &BTreeMap<String, FilterOptions> {
        &self.options
    }

    /// The table's SQLite connection, even after a panic while another
    /// query held it.
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
    /// Count `datasets`' rows by their scope values, stopping between
    /// records once `stop` fires.
    pub fn count(def: &Definition, datasets: &[&[u8]], stop: &Stop) -> Result<Self, TableError> {
        let columns = def
            .scope
            .values()
            .map(|name| {
                def.column(name)
                    .ok_or_else(|| TableError::MissingHeader(name.clone()))
            })
            .collect::<Result<Vec<&Column>, _>>()?;
        let mut counts: HashMap<Vec<Option<String>>, u64> = HashMap::new();
        let mut read = 0i64;
        for data in datasets {
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(true)
                .from_reader(*data);
            let headers = reader.headers()?.clone();
            let index = header_positions(&headers, columns.iter().copied())?;
            for record in reader.records() {
                let record = record?;
                read += 1;
                if read % RECORDS_PER_CHECK == 0 {
                    stop.check()?;
                }
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
        let counts = ScopeCounts::count(&def, &datasets, &soon()).unwrap();
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
        let table = Table::build(&def, &datasets, &scope, &soon()).unwrap();
        assert_eq!(
            allowed.iter().map(|c| c.rows).sum::<u64>(),
            table.rows as u64
        );
        assert_eq!(kept_out, [&combination("Bank B", None, 1)]);
        assert!(counts.split(&Scope::All).1.is_empty());
    }

    fn target(key: &str, value: &str) -> Target {
        Target {
            key: key.into(),
            value: value.into(),
        }
    }

    #[test]
    fn targets_name_one_declared_key_and_an_exact_value_each() {
        let def = awards_report();
        let group_a = target("employer_group", "Group A");
        let refused = |targets: &[Target]| check_targets(&def, targets).unwrap_err();
        assert!(refused(&[]).contains("1 to 100"));
        let many: Vec<Target> = (0..=MAX_TARGETS)
            .map(|i| target("employer", &format!("Bank {i}")))
            .collect();
        assert!(refused(&many).contains("1 to 100"));
        assert!(refused(&[group_a.clone(), group_a.clone()]).contains("repeats"));
        assert!(refused(&[target("region", "Region E")]).contains("isn't a scope key"));
        for value in ["", " Group A", "Group A ", "Group\tA", &"x".repeat(257)] {
            let e = refused(&[target("employer_group", value)]);
            assert!(e.contains("1 to 256 bytes"), "{value:?}: {e}");
        }
        // A target holds one key and one value; anything more is refused.
        let compound = serde_json::json!({ "key": "employer", "value": "Bank A",
            "employer_group": "Group A" });
        assert!(serde_json::from_value::<Target>(compound).is_err());

        // The same name under two keys is two targets.
        let both = [
            target("employer", "Lender D"),
            target("employer_group", "Lender D"),
        ];
        assert_eq!(check_targets(&def, &both).unwrap().len(), 2);
    }

    #[test]
    fn a_grant_sees_the_rows_of_any_of_its_targets_each_once() {
        let def = awards_report();
        let csv = format!(
            "{AWARDS_HEADER}\n\
             1,M1,Mx,Sam,Alpha,01/01/1990,Bank A,Group A,Certificate,Pass,01/01/2026\n\
             2,M2,Mx,Sam,Bravo,01/01/1990,Bank A Network,Group A,Certificate,Pass,02/01/2026\n\
             3,M3,Mx,Sam,Charlie,01/01/1990,Bank B,Group B,Certificate,Pass,03/01/2026\n\
             4,M4,Mx,Sam,Delta,01/01/1990,Lender D,None,Certificate,Pass,04/01/2026\n\
             5,M5,Mx,Sam,Echo,01/01/1990,Bank E,Lender D,Certificate,Pass,05/01/2026\n"
        );
        let rows = |targets: &[Target]| {
            let scope = Scope::of(&check_targets(&def, targets).unwrap());
            Table::build(&def, &[csv.as_bytes()], &scope, &soon())
                .unwrap()
                .rows
        };
        let group_a = target("employer_group", "Group A");
        let network = target("employer", "Bank A Network");
        let bank_b = target("employer", "Bank B");
        // Several employers, several groups, a mix, and an employer inside
        // a group it's granted with: each row counts once.
        assert_eq!(rows(&[network.clone(), bank_b.clone()]), 2);
        assert_eq!(
            rows(&[group_a.clone(), target("employer_group", "Group B")]),
            3
        );
        assert_eq!(rows(&[group_a.clone(), bank_b]), 3);
        assert_eq!(rows(&[group_a, network]), 2, "the employer is in the group");
        // An employer and a group of the same name are different rows.
        assert_eq!(rows(&[target("employer", "Lender D")]), 1);
        assert_eq!(rows(&[target("employer_group", "Lender D")]), 1);
        // "None" is a value like any other, never a wildcard.
        assert_eq!(rows(&[target("employer_group", "None")]), 1);
    }

    #[test]
    fn tables_keep_temporary_files_in_memory() {
        let csv = format!(
            "{AWARDS_HEADER}\n1,M1,Mx,Sam,Alpha,01/01/1990,Bank A,Group A,Certificate,Pass,01/01/2026\n"
        );
        let table =
            Table::build(&awards_report(), &[csv.as_bytes()], &Scope::All, &soon()).unwrap();
        let temp_store: i64 = table
            .connection()
            .pragma_query_value(None, "temp_store", |row| row.get(0))
            .unwrap();
        assert_eq!(temp_store, 2, "PRAGMA temp_store is MEMORY");
    }

    #[test]
    fn sqlite_keeps_no_memory_statistics() {
        let csv = format!(
            "{AWARDS_HEADER}\n1,M1,Mx,Sam,Alpha,01/01/1990,Bank A,Group A,Certificate,Pass,01/01/2026\n"
        );
        let table =
            Table::build(&awards_report(), &[csv.as_bytes()], &Scope::All, &soon()).unwrap();
        assert_eq!(table.rows, 1);
        // SAFETY: reads a counter; SQLite is initialised by the build above.
        #[allow(unsafe_code)]
        let used = unsafe { rusqlite::ffi::sqlite3_memory_used() };
        assert_eq!(
            used, 0,
            "SQLite was built without SQLITE_DEFAULT_MEMSTATUS=0"
        );
    }

    pub(crate) fn soon() -> Stop {
        Stop::after(std::time::Duration::from_secs(5))
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
