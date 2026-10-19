# drt-examples

Approved analyses that a pool's Execute DRT can pin. Each one is a single
static file: a TOML definition holding the pool's columns, the filters a
request may use, what a page returns, and the SQL the worker runs inside
the TEE.

## Layout

| Analysis | Filters beyond staff and membership numbers | Default sort (descending) |
|---|---|---|
| Awards | Exam Board Date, Award | Exam Board Date |
| Modules | Programme, MCC Module, Module, Registration Mode, Registration Date, Exam Date | Registration Date |
| MCC Categories | Designation, Category Date Accredited | Category Date Accredited |
| Exam Modules | None | Exam Date |
| CPD | CPD Year, Designation, Designation Status | CPD Year |
| Designation Status | Designation, Current Status, Previous Status, Status Update Date, Reason for Change | Status Update Date |
| CPD Audit | Audit Year, Audit Outcome | Audit Year |

Each definition accepts exactly the headers in its columns, returns them in
its output order, and declares employer and employer-group grant targets.
Admins see every row; other callers need a live grant. Pages default to 100
rows, with a maximum of 500. Non-date fields remain text, including identifiers.


## Trust contract

1. The definition is committed here. Its raw GitHub URL at a commit, and
   its SHA-256, go into the pool's Execute DRT when the pool is created; the
   dashboard's DRT registry fills them in.
2. At pool creation the worker fetches the URL, which must be under
   `https://raw.githubusercontent.com/relational-network/`, refuses bytes
   that don't hash to the recorded value, checks the definition, and stores
   it by hash. Queries never fetch anything.
3. The definition's columns are the pool's schema: every upload must have
   exactly its headers, with dates as DD/MM/YYYY.
4. The SQL reads one table, which holds only the rows the caller may see:
   the worker builds it from the targets of the caller's grant, each a scope
   key the definition declares and a value, so no statement can reach other
   rows. Every statement must be read-only and may use only the parameters
   its filters define.

## Hash and URL

```bash
sha256sum *-v1.toml
```

```
https://raw.githubusercontent.com/relational-network/relational-tee/<commit>/drt-examples/awards-report-v1.toml
```

Any change to a definition changes its hash. Pools registered with the old
hash keep the old analysis; new pools need the new hash in the dashboard's
registry.

## Definition SHA-256 values

Hashes cover the exact file bytes. Update this table whenever a definition
changes; set dashboard URLs and hashes after publication and merge.

| File | SHA-256 |
|---|---|
| [awards-report-v1.toml](awards-report-v1.toml) | `707fffa5c459559693a645d1629d535db06264cfcb2aeb5140ed0316e66084d2` |
| [cpd-audit-v1.toml](cpd-audit-v1.toml) | `888222526ccdd4504bedc5d12b3a5fe604f84de5a15d563b7fba9e130a736f2f` |
| [cpd-report-v1.toml](cpd-report-v1.toml) | `ad5a0873766d29b043db8e1b89950ce85534d467badd8e5263ede47eacc4dfb7` |
| [designation-status-v1.toml](designation-status-v1.toml) | `300f06f6c4f7379e9ce087a56bb6905b08961aa9ca56b4e0b69a5d0562ddcc47` |
| [exam-modules-v1.toml](exam-modules-v1.toml) | `78ae975d3a4d3c147e688d9b081396f8cf163120bf33625e573c41532b8077e2` |
| [mcc-categories-v1.toml](mcc-categories-v1.toml) | `4f3c859df4fecfa859fe0056441b05ad6daa6a050f84eca7c368c768bcf52c0f` |
| [modules-report-v1.toml](modules-report-v1.toml) | `1b42cdeb673dfb92024610eff3d19ddad62b8b173070333f70e250e041c42165` |

## The format

| Key | Meaning |
|---|---|
| `analysis_id` | Lowercase letters, digits and hyphens; also the Execute DRT's name |
| `display_name` | What the dashboard shows |
| `relation` | The table name the SQL reads |
| `[columns]` | `name = { header = "CSV header", type = "text" \| "date" }`. Dates are DD/MM/YYYY in the CSV and in the API, and `YYYY-MM-DD` inside SQLite, so ranges and sorting work |
| `[scope]` | `key = "column"`: the scope keys a grant's targets may name, each with the text column it restricts (the Awards Report's are `employer` and `employer_group`). A target `{ key, value }` gives the rows whose column for its key holds its value exactly, and a grant sees the rows of any of its targets, so a new row-level field is a new key here, with no code change. Keys are lowercase SQL names other than `group_id` and `label`, and requests can't filter on these columns |
| `[filters]` | `name = kind`. `date_range` binds `:name_from` and `:name_to`; `multi_select` and `search_select` bind `:name` as a JSON array of values. NULL means all; a multi-select value `""` selects empty cells |
| `[output]` | `columns` returned in order, `default_sort`, and `page_size` (`default`, `max`). Any output column may be sorted on |
| `sql.rows` | Every matching row, selecting `_record_id` and every output column, with each filter as `(:param IS NULL OR …)`. It is the reference for pages: the worker builds each page from `relation`, the output columns and only the filters a request sets, so SQLite can read it from the table's indexes, then sorts (then `_record_id`), pages and counts. A test holds those pages to the Awards Report's query; a definition whose rows query does more than select its columns under its filters needs a worker change, and a test of its own, first |
| `sql.options.<filter>` | For a `date_range`, one row of `min` and `max`; for a `multi_select`, `value` and `count`; for a `search_select`, `value`, using `:search` (a prefix, already escaped for `LIKE ... ESCAPE '\'`) and `:limit`. Each runs as written: once per table, and on the rows the other filters a request sets match, which the worker gives it as `relation` in a `WITH` of its own, so an option query may not start with `WITH`. A filter's parameters may not be `:search` or `:limit`, nor another filter's |

## Adding an analysis

A new use case, or another deployment's report, needs one TOML file here,
named for what it does, not for whom: its `analysis_id` is also a name
on-chain. Describe it in this README and add tests with small invented rows
and the export's exact headers. Tests use made-up values only (Bank A, Group A,
Subject A and so on), never a real organisation or person. After publication
and review, the dashboard's registry takes its URL at the merged commit and
its hash. Append a future registry entry after the existing views to place
its tab on the right.

The worker needs a change only when a definition needs something the format
can't express, such as a new filter kind, or a rows query that does more
than select its columns under its filters. Such a change extends the format
for every definition, with tests of its own. How the worker grants and runs
an analysis is in [docs/analyses.md](../docs/analyses.md).

## Blank multi-select values

An empty CSV cell is SQL NULL. A multi-select can offer it as `value = ""`,
with a count, displayed as **(Blank)**. Select it alone with
`{ "mode": "selected", "values": [""] }`, or combine it with named values.
An empty values array is invalid; `mode = "all"` still applies no condition.
Searchable identifier selects require non-empty values.

The new definitions' option queries return `coalesce(column, '') AS value`
and group by the column. Their reference rows queries use
`coalesce(column, '') IN (SELECT value FROM json_each(:filter))`. The worker's
generated queries add `OR column IS NULL` only when a blank is selected, so
ordinary nonblank queries keep their indexed lookup. Keep reference and
page semantics aligned when adding another definition.
