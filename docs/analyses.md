# Analyses

A pool's Execute DRT pins an approved analysis: a TOML definition from [`drt-examples/`](../drt-examples/), starting with the Awards Report. The worker fetches it from `https://raw.githubusercontent.com/relational-network/` when the pool is created, checks it against the hash the DRT records on-chain, and stores it as `scripts/{sha256}`; subsequent reads use that stored copy. Before creating a pool, a client can call `POST /v1/drt/analyses/preview` with the same URL and hash to obtain the checked definition's identity and columns. Preview uses an existing stored copy or fetches the definition without storing it, creating a pool or sending a transaction. Its columns are the pool's schema, so uploads must have exactly its headers, with DD/MM/YYYY dates. The pool is created with `analysis.supply` Execute DRTs, one per analyst grant. The definition format is in [`drt-examples/README.md`](../drt-examples/README.md).

## Who sees what

Admins see every row, with no grant. An analyst needs an active grant, which the pool's owner makes by burning an Execute DRT, and sees only the rows of the grant's targets: each a scope key the analysis declares in its `[scope]` table and a value, such as `{ "key": "employer_group", "value": "Group A" }` or `{ "key": "employer", "value": "Bank B" }`, matched exactly. A grant sees the rows of any of its targets, each row once; the same name under two keys is two targets. A row-level field a later analysis needs is a new key in its definition, with no code change.

The owner changes a grant's targets with `POST …/grant-scope`, naming the grant and the `scope_revision` the edit started from, so an edit made before the analyst was granted again never lands on the later grant; it burns nothing, and every setting is kept in the grant's `scope_history`. `POST …/scope-check` lists each key's values in the pool's data with their rows and counts what a draft's targets give, flagging a value no row holds with the data's nearest spellings; it decides rows with the same code as analysts' tables.

A definition may also declare a filter on a scope column: it
narrows the caller's already scoped table. Selecting an ungranted value returns
no rows and never expands the grant. This applies to pages, counts, options
and searches; ignoring a facet's own selection still retains the grant scope.
Admins can filter any value, including blanks where the definition offers
them. Queries cannot supply or replace grant targets.

No grant, a grant with no targets, or targets the analysis can't apply is `403`; targets no row holds get an empty page. Only rows are restricted: every caller sees every column.

## Grants

A grant is recorded in the pool document once its burn is finalized; granting an analyst with an active grant burns nothing. A revocation ends access as soon as the document records it, then closes the Grant PDA, whose rent returns to the pool's owner; the analyst can't be granted again until that close is recorded, so each Grant PDA belongs to one grant at a time. A burn that lands after a revocation, or that no request recorded, never restores access.

## The chain must show the grant

Each analyst request also needs the program's Grant at the grant's PDA, for the pool's Execute DRT config, which the worker reads on demand: a reading younger than 5 minutes is used as it is, an older one while the pool is read again in the background, and a grant with no reading, or one over 24 hours old, is read before answering (`503 rpc_unavailable` if the RPC can't answer). A pool is read once at a time, and every request waiting for that read gets its outcome; after a failed read the next waits 2 seconds, doubling to a minute, and requests that need a read meanwhile get the failure at once. A grant the chain doesn't show is `403 grant_not_live`. Readings are kept, sealed, so a restarted worker has them.

A pool's Execute DRTs can't be sent from its owner's wallet (`400 drt_not_transferable`), so every such Grant is one the worker made. That holds before the pool's document is written too: a pool's creation stages its document before it sends the transaction that creates its mints, and a send reads its token's mint before it checks the pools, refusing one that doesn't exist yet.

## The chain must show the pool's latest document

### Why

A Grant PDA proves that a grant is live, not which of the pool document's versions is current: a document restored from before a revocation, a narrower grant made again under the same PDA, a scope edit or a credential revocation would pass that check.

### The pool's counter

So every such change (recording a grant or its revocation, changing a grant's targets, revoking credentials) makes the document's next generation, and mints one token of the pool's counter: an SPL Token mint at an address derived from the owner's wallet and the pool (`create_with_seed`), which only that wallet can create or mint, whose tokens stay in the owner's token account, and whose supply no worker operation lowers. The first change creates the mint, funded by the owner's wallet with the rent of the mint and its token account; each change costs a transaction fee and carries a memo naming its generation.

### Settling

The change is written first, with the signed transaction that mints its token; until that lands the pool is settling, and any worker finishes it under the stored-transaction rule: the next change, an analyst request that finds the pool settling, or the reconciler. The transaction stays in the document until the next change, so a worker that comes late resends it rather than signing another.

### How an analyst request checks it

An analyst request is answered only while the document's generation is what the counter shows, read with the grant PDAs in the same call and trusted for as long as they are: a document behind the counter is `503 pool_records_stale`, logged with `alert = "pool_records_stale"`, until an operator restores the latest version; one a change ahead is `503 pool_settling` with `Retry-After`.

An analyst request checks the stored document once more before it answers: if the pool has made a change since the request read it, it gets `503 pool_settling` too, and its retry runs on the latest document, so a revocation recorded while a request ran holds for its answer. For the same reason, a counter ahead of a request's document means a restore only if the stored document is behind it as well. A reading behind the document is read again before it counts, since it may predate the change; one ahead of it needs no read, since the counter never goes down.

### Restored documents

So a restored document is refused once the counter has been read after the change it predates: within the 5 minutes readings are trusted while the RPC answers, and within the 24 hours of grace while it doesn't. Whether a revocation came after a grant was staged is decided by their generations, which no worker's clock moves; entries from before generations were counted are compared by their times. Pools whose grants predate counters are anchored from their next change.

## How it runs

### Tables and indexes

For each pool version (the uploads that count; revoked ones don't) and scope, the worker builds an in-memory SQLite table of only the rows that scope allows, so no statement can reach other rows. It then indexes every output and filter column in the order pages sort it, and each select filter's column again for exact lookups, and computes the filter options once.

### Filters and options

A filter's options under the other filters a request sets, and a search, run the definition's own option query on the rows those filters match, by naming them like the table in a `WITH`; a filter's own selection never narrows its own options. The definition's SQL was checked read-only when the pool was created, and the table is read-only once built.

A request names only the definition's filters, whose values are bound as parameters, sorts on one output column and then a stable row key, and pages within the definition's limits; anything else, such as a scope, is refused. A page's statement holds only the filters the request sets, so SQLite reads it from the indexes, and with no filter set the total is the table's row count; a test holds these statements to the Awards Report's own `rows` query. A request may also name up to four output columns in `distinct`; the page then says how many distinct non-empty values each holds in every matching row, such as people by an ID column, counted under the same filters and scope.

Opening an analysis is one request: `GET …/analyses/{analysis_id}?include=page` returns its description, every filter's options but the searches' from all the caller's rows (the options the table was built with, so nothing is computed), the page a query with no filters returns, in the default sort at the default page size, with the counts its `distinct` names, and each search filter's first values, as a search with no prefix returns them. All of it comes from one table, so it can't mix two versions of the pool, and it succeeds or fails as a whole. It is authorised as a query is, counts against the per-user limit as a non-`GET` request does, and is recorded once, as an `open` holding the query it ran. A plain `GET` is the description alone, which runs no page and records nothing. Filter changes, sorting, paging and searches keep their own requests.

### Limits and timeouts

A statement stops after 10 seconds, and building a table or counting a pool's scope values after 30 (`422 analysis_timeout`); work whose request has gone, timed out or disconnected, stops too, between CSV records and inside SQLite, and gives its thread back. A multi-select lists at most 1,000 options, in its option query's order: a column with more values suits a search.

### Caches and memory

Decrypted datasets are cached by upload and tables by version and scope, each loaded once and kept within a cache budget (512 MiB of datasets, 1 GiB of tables, indexes included, and at most 1,024 of each), so a warm query reads no dataset and a new upload loads only its own. Each also holds its memory in the worker's budget while it's cached or in use, reserved before it loads; a load that fails or is abandoned leaves nothing cached.

### Concurrency

About one table build, page or search per CPU runs at a time, and a table runs one request's work at a time, which waits for its turn before it takes a thread, so requests queued for a busy table never hold the threads other tables need; one that can't start within a second gets `503 analysis_busy` with `Retry-After`. A request's other CPU-heavy steps, such as opening a sealed upload, hashing it, validating its CSV and sealing it for storage, run off the threads that serve requests, so health checks and other requests keep being answered.

### Selecting blank values

A select may return an option with `value: ""`, meaning an empty CSV
cell (SQL NULL). Send `{ "mode": "selected", "values": [""] }` to select
only blanks, or include named values in the same array to select their union.
The option's count and all dependent options, searches and distinct counts
follow the same filters and grant scope. An empty array remains invalid;
`mode: "all"` removes the filter. Identifier searches can return `""` as
**(Blank)** when the search prefix is empty and matching rows have empty
identifiers. A non-empty prefix searches populated identifiers; a chosen
blank remains selected alongside any named values. The definition's options
SQL decides which choices it offers;
existing pinned definitions remain unchanged.

## Dates

DD/MM/YYYY in the CSV and the API, in filters, options and rows; `YYYY-MM-DD` only inside SQLite, so ranges and sorting work.

## Exports

`POST …/analyses/{analysis_id}/export { format, filters, sort }` returns every row the caller sees that the filters match, in the sort asked for (the definition's default when there's none), as one file of the definition's output columns, in order, under their headers. `format` is `csv` or `xlsx`. It's authorised as a query is, and its filters and sort are checked as a query's are; a page, `distinct`, a scope or any other field is refused (`400 invalid_query`). No matching rows is a file of the header alone.

- **Cells.** Text exactly as stored, dates as DD/MM/YYYY, as the API returns them, and an empty cell as nothing. A CSV is UTF-8 with a byte order mark and CRLF line ends, quoting only the values that need it. An XLSX file has one sheet, named after the analysis, with a bold, frozen header row, and every cell is literal text: never a number, a date, a formula or a link, so identifiers keep their leading zeroes and Excel doesn't flag them.
- **Formulas.** A CSV value, or header, that a spreadsheet would read as a formula (one starting with `=`, `+`, `-`, `@`, a tab or a carriage return) gets a leading `'`, unless it's a plain amount: a sign and a currency symbol (€, £ or $) in either order, then digits, in comma-separated threes if grouped, and an optional decimal part, such as `-25.00`, `-€1,234.50` or `+353`. XLSX cells are text, so they need no prefix.
- **Limits.** An export holds at most 100,000 rows and 50 MiB, and fails whole rather than returning part of its rows. The rows are counted before any is written, and more is `422 export_too_many_rows`, which gives the count; a file that would pass 50 MiB, or an XLSX cell over Excel's 32,767 characters, is `422 export_too_large`. Counting and writing each stop after 10 seconds (`422 analysis_timeout`).
- **Memory and concurrency.** The file is built in memory, never on disk. An export waits up to 5 seconds for one of the export slots, half as many as the analysis threads and at least one (`503 analysis_busy` with `Retry-After`), and counts and writes its rows under the table's turn, as a page does. Before writing, it reserves twice the largest file it may make from the worker's memory budget (`503 worker_busy` or `422 too_large_for_memory`, as other reservations), then shrinks that to the file's allocation, which can be up to twice its length. The file is sent 64 KiB at a time and holds that memory until the last of its bytes has been sent or dropped, including any a connection still buffers. A file not sent within 5 minutes, the largest at about 170 KiB/s, has its connection closed, and with it any other request on that connection, so a client that stops reading can't hold the memory longer.
- **Cancellation.** An export runs in a task of its own. A client that goes away stops it wherever it is: waiting for a slot, the table, a thread or memory, or counting and writing, between rows and inside SQLite. Its record says `cancelled`.

The response has `Content-Type` `text/csv; charset=utf-8` or the XLSX type, `Content-Disposition: attachment; filename="{analysis_id}-{YYYYMMDD-HHMMSS}.{csv|xlsx}"` (the UTC time it was asked for), `Cache-Control: no-store`, and `X-Export-Id`, the ID its records in the analysis log share. As with every analyst request, a change the pool records while an analyst's export runs, such as a revocation, gives `503 pool_settling` and no file.

## The analysis log

Every open, options, search, query and export request is recorded, sealed and create-only, at `audit/analyses/{pda}/{date}/{event_id}.json`, under an ID the worker generates for the request (its `X-Request-Id`, which a caller may choose, is kept in the record): who asked, through which grant, the filters, the sort and page it ran with, how many rows went back, and the outcome. A success whose record can't be stored returns `503 analysis_log_unavailable` instead of its rows. Admins read it with `GET /v1/admin/analysis-log`.

An export has two records, which share `export.export_id` and are both filed under the day it was asked for. The first, with outcome `requested`, holds the request as sent and is stored before any work: if it can't be, the export gets `503 analysis_log_unavailable` and nothing runs. The second is stored when the export ends, with its `result` (`success`, `refused`, `failed`, `timeout` or `cancelled`), the sort it ran with, its rows, the file's bytes and how long it took. A file is sent only once its success is stored; that write is tried twice, and if both fail the export gets `503 analysis_log_unavailable` and no file. So a `requested` record with no second means no file was sent: the worker stopped before the export ended, or neither write of the second record succeeded, which is logged with `alert = "analysis_log"` and the export's ID.

Analysis requests and responses travel over the worker's TLS like the rest of the API; they aren't sealed end to end yet.
