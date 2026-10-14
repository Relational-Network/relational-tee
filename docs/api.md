# API

The worker's HTTPS API. Builds with the `swagger-ui` feature (`just dev`) serve Swagger UI at `/docs` and the OpenAPI document at `/api-doc/openapi.json`; `just openapi` prints the document, and CI publishes it with every run.

## Conventions

### Headers

Every response carries `Strict-Transport-Security: max-age=63072000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` and `Cache-Control: no-store`, and no `Server` header.

### CORS

Only `DASHBOARD_ORIGIN`, with methods GET, POST, PUT, PATCH and DELETE, request headers `Authorization`, `Content-Type` and `Idempotency-Key`, exposed headers `Idempotent-Replayed`, `Retry-After` and `X-Request-Id`, and a preflight max age of a day. No credentials: the dashboard sends a bearer token.

### Rate limits

In memory per worker, so the effective limits grow with the worker count: per client IP on every request (the peer address; the load balancer keeps the client's), and per user on mutations once the token is validated. Excess requests get `429 rate_limited` with `Retry-After`.

### Request limits

- **Sizes.** Bodies may be 1 MiB, or 50 MiB on the upload routes (`POST …/initialize` and `…/issue`); larger ones get `413 payload_too_large`. A pool's uploads may hold 200 MiB of CSV together, and an issuance past that gets `413 pool_full`; a CSV value may be 4 KiB.
- **Memory.** Uploads, decrypted datasets and analysis tables reserve their memory from the worker's budget (`MEMORY_BUDGET_MIB`) before they allocate it and hold it while anything uses them: an upload reserves three times its `Content-Length` (the largest upload's, without one) before its body is read. What can't reserve within a few seconds gets `503 worker_busy` with `Retry-After`, and what needs more than the whole budget `422 too_large_for_memory`.
- **Upstream responses.** Responses the worker reads from Storage, Solana RPC, Entra ID's keys and the key release service are bounded too, each by what its largest legitimate answer holds.
- **Time.** A request may run for 60 seconds, or 300 on the upload routes; one still running gets `408 request_timeout` and stops where it was, as if the worker had died there. A retry with the same `Idempotency-Key` returns the stored response if there is one, and otherwise runs the request again, reusing its staged saga and resending any transaction it stored, so it finishes what the first attempt started (see [Idempotency](#idempotency)). Pool creation waits up to 60 seconds for `finalized`, so under a slow RPC it can end in a `408` that a retry finishes.
- **Headers and connections.** A request head (HTTP/1.1), or header list (HTTP/2), may be 16 KiB, and an HTTP/1.1 request may carry 100 header fields; beyond either it gets `431`. An HTTP/1.1 connection has 10 seconds to send each request's headers, idle keep-alive time included, and a TLS handshake has 10 seconds; past either, the connection is closed. An HTTP/2 connection whose client has been silent for 20 seconds gets a ping, and is closed if the ping goes unanswered for another 20, and it may have 64 requests open at once. A worker serves at most 1,024 connections at once, and closes any more as they arrive, before their TLS handshake, logging it at most once a minute. Clients that answer pings but send nothing still hold their places: a per-IP connection limit would be the next step.

### Request IDs

Every response carries `X-Request-Id`: the client's value if it's a valid UUID, otherwise a new one. The same ID is on the request's log lines and on its audit event.

### Logs

With `LOG_FORMAT=json` (release builds' default) each line is one JSON object: `timestamp`, `level`, `target`, `message` and the event's own fields at the top level, and inside a request a `span` object with `method`, `path`, `request_id`, and once known the `route` template and the caller's `user_id`. The line that ends a request, `Finished the request`, adds `status` and `latency_ms`, so log-based metrics can count requests, errors and latency by route. People appear only as `user_id`: no line carries a token, an email or an Entra object ID.

### Audit events

Every mutation, failed mutation, admin read, definition preview and analysis request (options, search or query) logs exactly one event with target `audit` when it completes, for operators to query in Azure Monitor. An event carries only `event` (for example `credential_issued`), `outcome` (`success` or `failure`), `code` on failure, `request_id`, `user_id`, and where relevant `pool`, `record_id`, `wallet_id`, `rows` and `signature`; never CSV content, emails, free-text reasons, keys or client IP addresses. The output leaves the TEE through the host, so these events are diagnostics: the pool's own records, the sealed analysis log and the chain are the audit trail users rely on.

### Errors

Every error, including unknown routes and malformed bodies, has one body shape: `{ "error": "<message>", "code": "<snake_case code>", "request_id": "<id>" }`. Clients branch on `code`; `error` is for people.

| Status | Codes |
|---|---|
| 400 | `bad_request`, `idempotency_key_required`, `invalid_cursor`, `validation_failed`, `sealed_payload_invalid`, `transaction_rejected`, `supply_exhausted`, `invalid_query`, `invalid_scope`, `grant_mismatch`, `receipt_taken`, `drt_not_transferable` |
| 401 | `unauthorized` |
| 403 | `forbidden`, `no_grant`, `no_employer_scope`, `invalid_grant_scope`, `grant_not_live` |
| 404 | `not_found`, `no_grant` (revoking or changing a grant nobody has) |
| 405 | `method_not_allowed` |
| 408 | `request_timeout` |
| 409 | `conflict`, `wallet_exists`, `email_taken`, `version_conflict`, `revocation_pending`, `grant_superseded`, `grant_settling`, `grant_active`, `grant_not_active`, `grant_pda_taken` |
| 413 | `payload_too_large`, `pool_full` |
| 415 | `unsupported_media_type` |
| 422 | `unprocessable_entity`, `idempotency_mismatch`, `analysis_timeout`, `too_large_for_memory` |
| 429 | `rate_limited` (with `Retry-After`) |
| 500 | `internal_error`, `integrity_error` |
| 502 | `transfer_outcome_unknown` |
| 503 | `service_unavailable`, `storage_unavailable`, `rpc_unavailable`, `attestation_unavailable`, `reference_values_unavailable`, `pool_records_stale`, `analysis_log_unavailable`; with `Retry-After`: `analysis_busy`, `worker_busy`, `pool_settling`, and `rpc_unavailable` when the RPC rate-limits a grant read |

A lost compare-and-swap, or an initialisation another upload beat, is a plain `conflict` (409).

`transaction_rejected` means Solana's preflight check refused the transaction for a reason resending can't cure, such as a wallet short of SOL for the fee or rent, and `error` carries Solana's reason; a retry with the same key succeeds once the cause is fixed. A transaction the RPC couldn't check, or whose blockhash it didn't know, is `503 rpc_unavailable`.

Two outcomes of a transfer get codes of their own, because neither retry helps them: `receipt_taken` means another transaction holds the transfer's receipt address, so the transfer didn't happen and no retry with the same key can make it (send it as a new transfer), and `transfer_outcome_unknown` means the transfer's receipt exists but no Solana node reports its transaction, so check the wallet's history on an explorer before sending again.

`grant_mismatch` means the request's `grant_id` names another analyst's or another analysis's grant.

### Sealed uploads

`POST …/initialize` and `POST …/issue` take a multipart form with the parts `v` (`1`), `kid`, `enc` and `ct`: the CSV sealed with RFC 9180 HPKE in base mode (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the transport key `GET /v1/attestation` returns, with `info` `relational-tee/hpke/v1`. `kid` is that key's RFC 7638 thumbprint, `enc` the encapsulated key in unpadded base64url, and `ct` the ciphertext, as a binary part.

The AAD is these UTF-8 lines joined by `\n`, with no trailing newline: `relational-tee/req/v1`, the method, the request path as sent (percent-encoded, without the query), the `Idempotency-Key` in canonical lowercase form, the `kid`, and the caller's `user_id` from `GET /v1/users/me`. A ciphertext therefore opens only for the pool, route, key and user it was sealed for.

The worker opens it after authentication and before the idempotency check. Any failure is `400 sealed_payload_invalid`, with no detail (the worker logs the reason); a plaintext `file` part is refused with `400 bad_request`.

### Idempotency

Every mutating route requires an `Idempotency-Key` header: a UUID the client generates for one user action and reuses on every retry of it. Without one the request fails with `400 idempotency_key_required`; `POST …/estimate` and an analysis's `POST …/query` are read-only and need none.

A retry of a completed request returns the stored status and body with `Idempotent-Replayed: true`, on any worker; the same key with a different method, path or body returns `422 idempotency_mismatch`. The fingerprint of a sealed upload covers the decrypted CSV, so a retry sealed afresh still matches. Keys are scoped to the user. There's no in-progress state: attempts running at once all run, converge on one effect, and return the first stored response. Failures aren't stored, so a retry after one runs again.

IDs derive from the user and the key (the pool UUID and its right IDs, the upload and issuance record ID, the wallet ID, the grant and revocation IDs), and a chain write stores its signed transaction in the record before sending it, so every retry resends that transaction and a request never creates two pools or burns two DRTs. A transfer also creates a receipt, an account with no data at an address derived from the wallet and the request, which Solana lets exist once: no second copy of the transfer can succeed, and a retry learns from the receipt whether the transfer happened, even once no RPC remembers its transaction. The receipt holds a deposit (see `POST …/estimate`), which goes back to the wallet after 8 days.

A storage lifecycle rule deletes records after 7 days, so retries are accepted for 7 days. JSON bodies must be sent as `application/json`.

### Pagination

Lists take `cursor` and `limit` and return `next_cursor` when there's another page (see [Pagination](architecture.md#pagination)).

## Endpoints

### Health

`GET /health/live` answers 200 while the process runs. `GET /health/ready` answers 200 only when the worker is ready to serve (see [Health and shutdown](architecture.md#health-and-shutdown)). `GET /health` returns details for operators: keys held, the transport key versions uploads open with, certificate expiry, canary age, key cache age, Solana RPC status (checked every 30 seconds), version and host data. It's public, so a failed canary or RPC check shows only as failed; why it failed is in the worker's log.

### Attestation

`GET /v1/attestation` returns `{ maa_token, transport_jwk, kid }`: an MAA token whose `x-ms-runtime.keys[0]` is the transport public key, and the key's RFC 7638 thumbprint. The worker requests the token at startup, refreshes it at 80% of its lifetime and serves it from memory; it answers 503 until the first token arrives. Clients seal uploads to that key once they have verified the token against the reference values.

### Reference values

`GET /v1/reference-values` returns the environment's signed manifest of approved workloads (the attestation claims, transport key IDs and `tls-key` SPKI hashes clients may trust) as a compact JWS (ES256), with `Content-Type: application/jose`. The manifest is signed outside the worker and kept in the public `reference-values` container as `{ENVIRONMENT}/{sequence}.jws`, the current one also as `{ENVIRONMENT}/latest.jws`. Workers serve the latest as it is, looking for it every 10 seconds until one loads, then every 5 minutes, and answer `503 reference_values_unavailable` until then. A worker logs `alert = "reference_values_mismatch"` if the manifest doesn't list its transport key, because clients then refuse to seal uploads to it. The manifest's `keys.transport` entries with a `version` also decide which other transport key versions the worker opens uploads with (see [Keys](architecture.md#keys)); `GET /health` lists them as `transport_kids`.

Clients verify the signature against the manifest key pinned for the environment, the validity window, and that the sequence never goes down. [`deploy/reference-values.schema.json`](../deploy/reference-values.schema.json) (JSON Schema 2020-12) describes the payload: everything workers and the dashboard read is required, claim sets can't name a claim clients don't check, and outside `dev` a manifest must also name the images, tools and provenance that rebuild the release, with an `https` MAA authority. Dev-build tests hold the schema to the dev manifest.

### Users

`GET /v1/users/me` returns `{ user_id, email, display_name, roles, permissions }`. `GET /v1/users` (`users:read`) lists everyone who has signed in, `{ users: [{ user_id, email, display_name, roles, first_seen, last_seen }], next_cursor }`, sorted by email; `GET /v1/users?email=` is an exact, case-insensitive match returning `{ user_id, email, display_name }`, or 404.

`POST /v1/users { entra_object_id, email, display_name }` (`Admin`) registers someone found in Entra before their first sign-in, as `pending`, under the `user_id` their first sign-in with that object ID then has, so they can be granted at once (`409 email_taken` if another user holds the email). An email belongs to the first identity to claim it, by a create-only write, so of two registrations of one email exactly one succeeds; someone who signs in with an email another identity holds still signs in, by their Entra IDs, but a lookup by that email finds the other. A sign-in or registration that died between its two writes is completed by the next one.

### Wallets

`GET` and `POST /v1/wallets`; `GET` and `DELETE /v1/wallets/{id}`; `GET …/balance`; `POST …/estimate` and `…/send`; `GET …/transactions` and `…/transactions/{signature}`.

### Pools

`POST /v1/drt/analyses/preview` (`pools:create`) takes `{ code_repo_url, code_hash_hex }` and returns `{ analysis_id, display_name, fields: [{ name, field_type, nullable }] }`. It checks the same URL allowlist, nonzero SHA-256 and definition format as pool creation, allowing a client to validate a CSV before creating a pool. It needs neither a wallet nor an `Idempotency-Key`, stores no definition or pool, and sends no transaction. Invalid inputs return 400; a temporarily unavailable definition returns 503.

`POST /v1/drt/pools/malta` takes `{ wallet_id, pool_name, append_supply, analysis: { code_repo_url, code_hash_hex, supply } }`; `GET /v1/drt/pools/list`; `GET …/schema`, the analysis's columns; `POST …/initialize`, `…/issue` and `…/revoke`; `GET …/revocations`, `…/summary` and `…/issuance-log`. The summary, issuance log and revocations together are the pool's audit trail: who created it and when, with the creation signature; the initial upload; each issuance with its burn signature; and each revocation with who, when and why.

The pool list accepts `search` (case-insensitive pool name), `state` (`ready` or `needs_init`), `sort`, `limit` and `cursor`. Sorts are `created_desc` (default), `created_asc`, `name_asc`, `name_desc`, `credentials_desc` and `credentials_asc`; credential sorts count uploaded rows. Ties use the pool address. Keep the same filters and sort when following `next_cursor`, and reset the cursor when either changes.

### Grants

`POST …/grant` (`pools:write` and pool ownership) takes `{ analyst_user_id, analysis_id, scope: [{ key, value }] }`, `…/revoke-grant` `{ analyst_user_id, analysis_id, grant_id? }`, which revokes only the named grant when there is one, and `…/grant-scope` `{ grant_id, analyst_user_id, analysis_id, revision, scope }` changes an active grant's targets; `GET …/grants` (`pools:read`) lists them, newest first, as `active`, `revoking` or `revoked`, with their targets, their history and what the chain shows at their Grant PDAs; `POST …/analyses/{analysis_id}/scope-check { scope }` (`pools:read`) counts what targets give in the pool; `GET /v1/drt/me/analyses` (`analyses:run`) lists the analyses the caller may run.

### Analyses

Under `/v1/drt/pools/{pda}/analyses/{analysis_id}` (`analyses:run`, and for an analyst an active grant): `GET` describes the analysis and the caller's rows; `POST …/options { filters }` and `…/options/{filter} { search, limit, filters }` list filter values from those rows that the other filters match; `POST …/query` returns `{ rows, total_matched, limit, offset }`. See [Analyses](analyses.md).

### Admin

`GET /v1/admin/wallet-stats` and `/v1/admin/wallets`; `POST /v1/admin/wallets/{id}/suspend` and `…/activate`; `GET /v1/admin/analysis-log?pool_pda=&date=`.

### Docs

Builds with the `swagger-ui` feature (`just dev`) serve Swagger UI at `/docs` and the OpenAPI document at `/api-doc/openapi.json`; release builds serve neither. `just openapi` prints the document, and CI publishes it with every run.
