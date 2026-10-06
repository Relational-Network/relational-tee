# drt-examples

Approved analyses that a pool's Execute DRT can pin. Each one is a single
static file: a TOML definition holding the pool's columns, the filters a
request may use, what a page returns, and the SQL the worker runs inside
the TEE.

## Layout

```
drt-examples/
├── README.md                          (this file)
└── awards-report/
    ├── README.md
    ├── awards-report-v1.toml          the Awards Report
    └── fixtures/awards-synthetic.csv  synthetic rows with the export's headers
```

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
   the worker builds it for the caller's employer scope, so no statement can
   reach other employers' rows. Every statement must be read-only and may use
   only the parameters its filters define.

## Hash and URL

```bash
sha256sum awards-report/awards-report-v1.toml
```

```
https://raw.githubusercontent.com/relational-network/relational-tee/<commit>/drt-examples/awards-report/awards-report-v1.toml
```

Any change to a definition changes its hash. Pools registered with the old
hash keep the old analysis; new pools need the new hash in the dashboard's
registry.

## The format

| Key | Meaning |
|---|---|
| `analysis_id` | Lowercase letters, digits and hyphens; also the Execute DRT's name |
| `display_name` | What the dashboard shows |
| `relation` | The table name the SQL reads |
| `[columns]` | `name = { header = "CSV header", type = "text" \| "date" }`. Dates are DD/MM/YYYY in the CSV and in the API, and `YYYY-MM-DD` inside SQLite, so ranges and sorting work |
| `[scope]` | `key = "column"`: the scope keys the employer-scope mapping may name, each with the text column it restricts (the Awards Report's are `employer` and `employer_group`). A mapping entry grants the rows whose columns hold all its values, so a new row-level field is a new key here, with no code change. Keys are lowercase SQL names other than `group_id` and `label`, and requests can't filter on these columns |
| `[filters]` | `name = kind`. `date_range` binds `:name_from` and `:name_to`; `multi_select` and `search_select` bind `:name` as a JSON array of values. NULL means all |
| `[output]` | `columns` returned in order, `default_sort`, and `page_size` (`default`, `max`). Any output column may be sorted on |
| `sql.rows` | Every matching row, selecting `_record_id` and every output column, with each filter as `(:param IS NULL OR …)`. It is the reference for pages: the worker builds each page from `relation`, the output columns and only the filters a request sets, so SQLite can read it from the table's indexes, then sorts (then `_record_id`), pages and counts. A test holds those pages to the Awards Report's query; a definition whose rows query does more than select its columns under its filters needs a worker change, and a test of its own, first |
| `sql.options.<filter>` | For a `date_range`, one row of `min` and `max`; for a `multi_select`, `value` and `count`; for a `search_select`, `value`, using `:search` (a prefix, already escaped for `LIKE ... ESCAPE '\'`) and `:limit`. Each runs as written: once per table, and on the rows the other filters a request sets match, which the worker gives it as `relation` in a `WITH` of its own, so an option query may not start with `WITH`. A filter's parameters may not be `:search` or `:limit`, nor another filter's |
