# drt-examples

Approved analyses that a pool's Execute DRT can pin. Each one is a single
static file: a TOML definition holding the pool's columns, the filters a
request may use, what a page returns, and the SQL the worker runs inside
the TEE.

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
https://raw.githubusercontent.com/relational-network/relational-tee/<commit>/drt-examples/<analysis-id>.toml
```

Any change to a definition changes its hash. Existing pools keep their pinned
definition; new pools need the corresponding URL and hash.

## Definition SHA-256 values

Hashes cover the exact file bytes. Update this table whenever a definition
changes; set dashboard URLs and hashes after publication and merge.

| File | SHA-256 |
|---|---|
| [awards-report-v1.toml](awards-report-v1.toml) | `6c521e7e0fb829cc0927aa443f65ec066bc5a46795890bdbfe12a3f60c3434e0` |
| [cpd-audit-v1.toml](cpd-audit-v1.toml) | `74839dfeec772020035cbd62dc44747a6438548153710d65e5872691a5dbc72c` |
| [cpd-report-v1.toml](cpd-report-v1.toml) | `7d5cd182ba4991278cfbac8dab8c8872293dce9e11cceb9f9440d8631d7b9c03` |
| [designation-status-v1.toml](designation-status-v1.toml) | `c5dc9bbbb34f0dd6ed46f9ed2ceecdf5754e5d37dac8f7b8c99efb75bfa6b34b` |
| [exam-modules-v1.toml](exam-modules-v1.toml) | `5ab9fe2312f32780b3f5041fb99e2dbf7684e5dfd6bbeb9b11f863cc5533c6de` |
| [mcc-categories-v1.toml](mcc-categories-v1.toml) | `cc50edcc4999215737a72b3e797667e72800e6e597a4c9f21ca1d9f5c82ce020` |
| [modules-report-v1.toml](modules-report-v1.toml) | `240301dd815c7ea8fa83e60e4ad269975f4947bd04ba27969d7cdb9e8235540d` |
| [orders-report-v1.toml](orders-report-v1.toml) | `efafa68c74ff8056c21297ec996b0296a27512ac85c92d273761ee52f2188754` |

## Definition overview

| Key | Purpose |
|---|---|
| `analysis_id`, `display_name` | Stable identifier and display name |
| `relation` | The table the analysis reads |
| `[columns]` | CSV headers and column types |
| `[scope]` | Scope keys and the columns used to apply grant targets |
| `[filters]` | Supported request filters |
| `[output]` | Result columns, default sort and page limits |
| `sql.rows`, `sql.options` | Read-only reference and filter-option queries |

Each TOML file defines its own schema and analysis behaviour. For the shared
access and query contract, including blank selections, see
[the analysis reference](../docs/analyses.md).

## Adding an analysis

Add a TOML file named for what it does and include its SHA-256 above. Add
meaningful tests using small invented rows to verify its schema, filters,
access restrictions and query results; a standalone fixture CSV is optional.
Use no real organisations, people or deployment details in documentation or
test data. After publication and review, clients can pin the definition's
commit URL and hash.

Extend the shared engine only when the definition format cannot express the
required behaviour, and cover that extension with tests.
