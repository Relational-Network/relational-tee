# Analyses

A pool's Execute DRT pins an approved analysis: a TOML definition from [`drt-examples/`](../drt-examples/), starting with the Awards Report. The worker fetches it from `https://raw.githubusercontent.com/relational-network/` when the pool is created, checks it against the hash the DRT records on-chain, and stores it as `scripts/{sha256}`; nothing fetches it again. Its columns are the pool's schema, so uploads must have exactly its headers, with DD/MM/YYYY dates. The pool is created with `analysis.supply` Execute DRTs, one per analyst grant. The definition format is in [`drt-examples/README.md`](../drt-examples/README.md).

## Who sees what

Admins see every row, with no grant. An analyst needs an active grant, which the pool's owner makes by burning an Execute DRT, and sees only the rows of the grant's targets: each a scope key the analysis declares in its `[scope]` table and a value, such as `{ "key": "employer_group", "value": "Group A" }` or `{ "key": "employer", "value": "Bank B" }`, matched exactly. A grant sees the rows of any of its targets, each row once; the same name under two keys is two targets. A row-level field a later analysis needs is a new key in its definition, with no code change.

The owner changes a grant's targets with `POST …/grant-scope`, naming the grant and the `scope_revision` the edit started from, so an edit made before the analyst was granted again never lands on the later grant; it burns nothing, and every setting is kept in the grant's `scope_history`. `POST …/scope-check` lists each key's values in the pool's data with their rows and counts what a draft's targets give, flagging a value no row holds with the data's nearest spellings; it decides rows with the same code as analysts' tables.

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

A request names only the definition's filters, whose values are bound as parameters, sorts on one output column and then a stable row key, and pages within the definition's limits; anything else, such as a scope, is refused. A page's statement holds only the filters the request sets, so SQLite reads it from the indexes, and with no filter set the total is the table's row count; a test holds these statements to the Awards Report's own `rows` query.

### Limits and timeouts

A statement stops after 10 seconds, and building a table or counting a pool's scope values after 30 (`422 analysis_timeout`); work whose request has gone, timed out or disconnected, stops too, between CSV records and inside SQLite, and gives its thread back. A multi-select lists at most 1,000 options, in its option query's order: a column with more values suits a search.

### Caches and memory

Decrypted datasets are cached by upload and tables by version and scope, each loaded once and kept within a cache budget (512 MiB of datasets, 1 GiB of tables, indexes included, and at most 1,024 of each), so a warm query reads no dataset and a new upload loads only its own. Each also holds its memory in the worker's budget while it's cached or in use, reserved before it loads; a load that fails or is abandoned leaves nothing cached.

### Concurrency

About one table build, page or search per CPU runs at a time, and a table runs one request's work at a time, which waits for its turn before it takes a thread, so requests queued for a busy table never hold the threads other tables need; one that can't start within a second gets `503 analysis_busy` with `Retry-After`. A request's other CPU-heavy steps, such as opening a sealed upload, hashing it, validating its CSV and sealing it for storage, run off the threads that serve requests, so health checks and other requests keep being answered.

## Dates

DD/MM/YYYY in the CSV and the API, in filters, options and rows; `YYYY-MM-DD` only inside SQLite, so ranges and sorting work.

## The analysis log

Every options, search and query request is recorded, sealed and create-only, at `audit/analyses/{pda}/{date}/{event_id}.json`, under an ID the worker generates for the request (its `X-Request-Id`, which a caller may choose, is kept in the record): who asked, through which grant, the filters, the sort and page it ran with, how many rows went back, and the outcome. A success whose record can't be stored returns `503 analysis_log_unavailable` instead of its rows. Admins read it with `GET /v1/admin/analysis-log`.

Analysis requests and responses travel over the worker's TLS like the rest of the API; they aren't sealed end to end yet.
