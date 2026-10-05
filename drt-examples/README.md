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
| `[scope]` | The columns holding the employer and the employer group, which the caller's scope is applied to |
| `[filters]` | `name = kind`. `date_range` binds `:name_from` and `:name_to`; `multi_select` and `search_select` bind `:name` as a JSON array of values. NULL means all |
| `[output]` | `columns` returned in order, `default_sort`, and `page_size` (`default`, `max`). Any output column may be sorted on |
| `sql.rows` | Every matching row, selecting `_record_id` and every output column. The worker adds the sort (then `_record_id`), `LIMIT` and `OFFSET`, and counts the same query |
| `sql.options.<filter>` | For a `date_range`, one row of `min` and `max`; for a `multi_select`, `value` and `count`; for a `search_select`, `value`, using `:search` (a prefix, already escaped for `LIKE ... ESCAPE '\'`) and `:limit` |
