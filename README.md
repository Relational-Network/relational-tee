# relational-tee

The worker behind IOB MicRes: an Axum server that runs Use Case 1 credential pools on Solana (create a Malta pool, upload its schema, initialise it, issue and revoke credentials, read the issuance log and audit trail) and custodial Solana wallets (create, balance, fee estimate, send, history, admin suspend and activate).

> **Migration in progress.** This repo was imported from `relational-sdk`, a Gramine SGX enclave, and is being moved to Azure Confidential Containers (AMD SEV-SNP). Gramine, RA-TLS, the SGX build and the old SSH deployment are gone, and the server now builds and runs natively. Still to come: key release and attestation on real Azure hardware, idempotent mutations, Entra ID sign-in, and in-app edge controls. Until then, parts of the server are interim, as described below.

## What works today, and what's interim

- **Transport.** The worker serves HTTPS (TLS 1.3, rustls with aws-lc-rs) with `tls-key`, which is released only to attested workers and never written anywhere. Its certificate chain is `{spki_sha256}/chain.pem` in the public `tls` container, where `spki_sha256` is the hex SHA-256 of the key's SubjectPublicKeyInfo, so clients can pin the key across renewals. While there's no chain, any worker writes a CSR for `API_HOSTNAME`, signed with `tls-key`, to `{spki_sha256}/csr.pem`, create-only, for the certificate job to sign; workers look for the chain every 10 seconds until they have one, then every 5 minutes, and swap renewals in without a restart. A chain whose leaf isn't `tls-key`'s is ignored and logged with `alert = "tls_chain_mismatch"`. Readiness requires a loaded, unexpired chain. Release builds have no plain HTTP path; dev builds serve plain HTTP on `127.0.0.1:8443` unless `TRANSPORT=https`, and `just dev-cert` is their certificate job.
- **Keys.** At startup the worker obtains four P-256 keys, `transport-key`, `storage-root`, `tls-key` and `commitment-key`, and keeps them in memory only. Release builds get them from Microsoft's SKR sidecar on localhost (`KEY_PROVIDER=skr`), which releases a key only to a confidential container group whose attested policy matches the key's release policy. Dev builds default to `KEY_PROVIDER=local`, which reads dev keys from `dev/keys/` (`just dev-keys` creates them); release builds don't contain that provider and refuse `KEY_PROVIDER=local`. Uploads are sealed to `transport-key`, which every worker shares.
- **Storage.** All durable state lives in Azure Blob Storage as documents sealed inside the worker with a key derived from `storage-root` (see [Storage](#storage)); workers keep nothing on local disk. Dev builds default to the same sealed objects in local files under `./data`.
- **Auth.** Protected endpoints take Entra ID access tokens for the worker's API app registration. A token must be RS256, signed by a key from the pinned tenant's JWKS (`https://login.microsoftonline.com/{tid}/discovery/v2.0/keys`, cached for 24 hours, fetched by one request at a time, and refetched for an unknown `kid` at most once a minute), with that tenant's exact `iss` and `tid`, the API's client ID as `aud`, an allowed client as `azp`, and `access_as_user` in `scp`; `exp` and `nbf` allow 60 seconds of skew. jsonwebtoken verifies RS256 through aws-lc-rs, so the `rsa` crate stays out. A caller's `(tid, oid)` maps to an internal `user_id`, created at their first sign-in; every stored reference to a person uses it. The `Admin` app role grants the permissions `pools:read`, `pools:create`, `pools:write`, `wallets:read` and `users:read`, and is itself required for wallet creation, deletion and sends and for `/v1/admin/…`; a caller with no role can call only `/v1/users/me` and the pool list. Pool writes also need pool ownership, and wallet routes wallet ownership.
- **Dev tokens.** Dev builds also trust one more key, the dev token signing key `dev/keys/entra-signing-key.pem` (`just dev-keys` creates it), so tests, scripts and CI can call the API offline: `just dev-token` prints a token for it (see [Running it locally](#running-it-locally)). Release builds contain none of this code and refuse `DEV_TOKEN_KEY`.
- **Solana.** The public devnet RPC by default. It is rate-limited and has no SLA, and the server warns about it at startup.

## Develop locally

You need [Nix](https://nixos.org) with flakes, and Docker for the image builds.

```bash
nix develop     # pinned Rust, cargo-nextest, cargo-audit, bacon, just, sccache,
                # Azurite, mkcert, actionlint
just            # list the recipes
```

| Recipe | What it does |
|---|---|
| `just dev` | Run the dev build natively on `127.0.0.1:8443`, with Swagger UI at `/docs` (creates missing dev keys first) |
| `just dev-keys` | Create any missing dev keys in `dev/keys/`: one private JWK per key, the dev MAA signing key and the dev token signing key; existing keys are kept |
| `just dev-token` | Print a token signed with the dev token signing key: `Admin` by default; `--roles`, `--oid`, `--tid`, `--email`, `--name` and `--azp` change it, and `--bad expired\|not-yet-valid\|audience\|tenant\|client\|scope` makes one the worker must refuse |
| `just skr` | Run the fake SKR sidecar on `127.0.0.1:9000`; start the worker with `KEY_PROVIDER=skr` to use it |
| `just dev-cert` | The local certificate job: sign each pending CSR in `data/tls/` with mkcert's local CA (`TRANSPORT=https just dev` writes one; run `mkcert -install` once so browsers trust it) |
| `just test` | Run the tests with cargo-nextest, in the release and dev configurations; storage tests use local files in temporary directories |
| `just azurite` | Start Azurite's Blob service, the Azure Storage emulator, in Docker on `127.0.0.1:10000`, data in memory; `just azurite-stop` stops it |
| `just test-azurite` | Run the store conformance tests against Azurite, starting it first if needed |
| `just check` | Run every gate: rustfmt, clippy (`-D warnings`, with and without all features), the tests, the banned-crate check and `cargo audit` |
| `just spa` | Run the dashboard dev server from `../iob-pilot` (override with `IOB_PILOT_DIR`), using the host's Node and pnpm |
| `just image` | Build the canonical x86_64-linux image with Nix and load it into Docker as `relational-tee:latest` |
| `just image-dev` | Build the aarch64-linux dev image and load it into Docker as `relational-tee:dev` |
| `just stack-up` | Start the local stack (needs `just image-dev`): Azurite, the fake SKR sidecar, three workers and a round-robin proxy on `127.0.0.1:8443`; `just stack-down` stops it |

`just image` and `just image-dev` run Nix in a `nixos/nix` container with a cached `/nix` volume, so a Mac needs no separate Linux builder. On Apple Silicon the x86_64 image runs under emulation.

### The fake SKR sidecar

Dev builds include `relational-tee fake-skr`, a stand-in for Microsoft's SKR sidecar. It serves `POST /key/release` and `POST /attest/maa` with the sidecar's request and response shapes, answering from the dev keys, so the production client code path runs unchanged. It signs attestation tokens RS256 with the dev MAA key, with MAA's claim names and a fixed dev host data value, and serves that key's public half at `GET /certs` (with `Access-Control-Allow-Origin: *`), as MAA does: a dashboard can use `http://localhost:9000` as its attestation authority. A key without a dev key file gets 403, like a release policy mismatch.

| Variable | Default | Purpose |
|---|---|---|
| `FAKE_SKR_ADDR` | `127.0.0.1:9000` | Listening address |
| `FAKE_MAA_ISSUER` | `http://localhost:{port}` | The tokens' `iss`, and where `/certs` is served |
| `FAKE_MAA_TOKEN_SECS` | `28800` (8 hours) | Token lifetime |
| `DEV_KEYS_DIR` | `dev/keys` | Dev keys to release and sign with |

Not there yet: a fault-injection suite for the idempotency work, and a debug-mode sandbox on Azure.

### Running it locally

- **Fastest:** `just dev` uses dev keys (`KEY_PROVIDER=local`) and sealed local files under `./data` (`STORAGE_BACKEND=files`), which survive restarts, and needs nothing else running.
- **Production code paths:** `just skr` and `just azurite` in other terminals, then `KEY_PROVIDER=skr STORAGE_BACKEND=azurite just dev`. The worker then releases keys and attests through the SKR client, and stores everything in Azurite through the Azure client, signing with Azurite's well-known Shared Key.
- **Several workers:** `just image-dev` once, then `just stack-up` ([`compose.yaml`](compose.yaml)). Three workers share Azurite and one fake SKR sidecar behind HAProxy on `127.0.0.1:8443`, which round-robins at layer 4 and probes `/health/ready` like the Azure load balancer. The fake sidecar's `/certs` is on `127.0.0.1:9000`.

**Calling the API.** Dev builds accept tokens from the dev app registrations in Relational's tenant, and from the dev token signing key:

```bash
# A real token, as a user with the Admin role in the dev registration
TOKEN=$(az account get-access-token \
  --scope api://aa827d93-d487-40bf-8956-b6872ed55290/access_as_user \
  --query accessToken -o tsv)
# Or offline, signed with the dev key (also in the compose stack)
TOKEN=$(just dev-token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/v1/users/me
```

Never print, log or commit a real token.

### Configuration

| Variable | Dev default | Release default | Purpose |
|---|---|---|---|
| `ENVIRONMENT` | `dev` | required | The environment's name (lowercase letters, digits and hyphens); it names the environment's reference values in storage |
| `BIND_ADDR` | `127.0.0.1` | `0.0.0.0` | Listening IP address |
| `PORT` | `8443` | `8443` | Listening port |
| `TRANSPORT` | `http` | `https` (the only one) | `https` serves `tls-key` with its chain from the `tls` container |
| `API_HOSTNAME` | `localhost` | required | The name the CSR asks for (`localhost` also gets `127.0.0.1` and `::1`) |
| `KEY_PROVIDER` | `local` | `skr` (the only one) | Where keys come from: the SKR sidecar, or dev key files |
| `DEV_KEYS_DIR` | `dev/keys` | n/a | Dev key files for `KEY_PROVIDER=local` |
| `SKR_ENDPOINT` | `http://localhost:9000` | same, loopback only | SKR sidecar address |
| `MAA_ENDPOINT` | `sharedweu.weu.attest.azure.net` | same | Attestation authority the sidecar uses |
| `KEY_VAULT_URL` | a placeholder | required | Key Vault the sidecar releases keys from |
| `KEY_NAMES` | `transport-key,storage-root,tls-key,commitment-key` | same | Key Vault names of the four keys, in that order |
| `STORAGE_BACKEND` | `files` | `azure` (the only one) | `azure`, `azurite` (Azurite's dev account) or `files` (local files) |
| `STORAGE_BLOB_URL` | Azurite's, for `azurite` | required, `https://` | Blob endpoint |
| `DATA_DIR` | `./data` | n/a | Where `files` keeps its containers |
| `MANAGED_IDENTITY_CLIENT_ID` | unset | the worker identity | Which managed identity to request storage tokens for |
| `SOLANA_RPC_URL` | `https://api.devnet.solana.com` | same | Solana RPC endpoint |
| `SOLANA_NETWORK` | `devnet` | same | `devnet` or `mainnet`, for explorer links |
| `ENTRA_TENANT_ID` | the dev tenant `7e3e38e3-…` | required | The tenant whose tokens are accepted |
| `ENTRA_API_CLIENT_ID` | the dev API `aa827d93-…` | required | The API app registration: tokens' `aud` |
| `ENTRA_ALLOWED_CLIENT_IDS` | the dev dashboard `e2d026c4-…` and the Azure CLI | required; the Azure CLI is refused | Comma-separated client IDs allowed as `azp` |
| `DEV_TOKEN_KEY` | `{DEV_KEYS_DIR}/entra-signing-key.pem`, trusted if it exists | refused | The dev token signing key |
| `DASHBOARD_ORIGIN` | `http://localhost:5173` (Vite) | required, `https://` | The one origin CORS allows |
| `RATE_LIMIT_IP_PER_SECOND`, `RATE_LIMIT_IP_BURST` | `20`, `40` | same | Requests per client IP, per worker |
| `RATE_LIMIT_USER_MUTATIONS_PER_SECOND` | `10` | same | POST, PUT, PATCH and DELETE requests per user, per worker |
| `RUST_LOG` | `info` | `info` | Log filter |

Dev builds are the ones with the `dev` Cargo feature (`just dev`, or `cargo run --features dev`).

## Storage

Everything durable is an object in one store with four operations: get (conditional on a cached ETag), create-only put, compare-and-swap put, and list. There's no delete or append. `AzureBlob` implements it with three Blob REST calls over the worker's own hyper and rustls client, authenticated with Entra tokens from the managed identity endpoint (the account has shared keys disabled); `LocalFiles` implements it on local files for development and tests. One conformance suite runs against both.

- **Sealing.** Every object in the `state` container is sealed inside the worker: `"RTS1"` ‖ a random 96-bit nonce ‖ AES-256-GCM ciphertext, under `storage-key-v1`, with associated data binding the container and path, so a moved or copied object fails to open. `storage-key-v1` and `index-hmac-v1` are HKDF-SHA256 over `storage-root`'s private scalar, salt `relational-tee/storage-root`. `index-hmac-v1` names identity objects, so Entra object IDs and emails never appear in object names.
- **Layout.** `pools/{pda}.json` is one document per pool: its metadata, schema, who created it with the creation signature, the initial upload, the issuance log with each burn's signature, and the revocations. That document is the pool's audit trail, and its totals are computed from it. Each uploaded CSV is `pools/{pda}/datasets/{upload_id}`, create-only. `wallets/{id}.json` and `wallets/{id}/keypair` hold a wallet, and `owners/{user_id}.json` points each user at their one wallet. `identities/…` map Entra identities to internal user IDs. `idempotency/{user_id}/{hash}.json` holds each idempotent request's record (see [API conventions](#api-conventions)), and `staged/{op_id}.json` holds what a pool creation or issuance will write, staged before its transaction is sent. `canary/{worker_id}` is the readiness canary.
- **The reconciler.** Every worker lists `staged/` every 5 minutes. For each saga older than 10 minutes whose effect is on chain at `finalized` (the pool account, or the issuance's Grant PDA) but missing from its document, it writes the pool document or adds the issuance entry, with the signature from the saga's idempotency record. So a request that died after its transaction, and was never retried, still lands in the documents. It never deletes or undoes anything, and running it on every worker at once is safe.
- **Writes.** Every write is create-only or a compare-and-swap, so no worker needs a lock. A lost compare-and-swap retries three times with jitter, then the request fails with `409 conflict`.
- **The cache.** Each worker keeps decrypted objects in a bounded LRU with their ETags. A read sends the cached ETag and costs no body or decryption when nothing changed; a list returns every ETag, so only changed objects are fetched. Keypairs are never revalidated, and datasets aren't cached.
- **Wallet history** isn't stored: it's read from Solana on demand (`getSignaturesForAddress`, then `getTransaction`), with SOL amounts from balance changes and SPL amounts from token-balance changes. Its cursor is the last signature of the previous page. Each worker caches pages for 30 seconds and parsed transactions by signature.
- **Pagination.** Lists are filtered, sorted and paged in memory. A cursor is the key of the previous page's last item, so any worker continues it; one that names no item returns `400 invalid_cursor`. Lists don't take `offset` or return totals.

The worker creates the `state`, `tls` and `reference-values` containers at startup if they're missing. `STORAGE_BACKEND=azurite` signs with Azurite's well-known dev account key (dev builds only).

## Build and release

`flake.nix` pins nixpkgs and builds with crane, taking the toolchain from `rust-toolchain.toml`:

- `packages.x86_64-linux.server`: the release binary, statically linked against musl, with mimalloc as its allocator. `SOURCE_DATE_EPOCH` comes from the commit, and build paths are remapped out of the binary.
- `packages.x86_64-linux.image`: an OCI image containing only the binary, a pinned CA bundle and an `/etc/passwd` entry for the non-root user 65532. It has no shell, package manager or Nix. The entrypoint is `/bin/relational-tee`, on port 8443.
- `packages.aarch64-linux.image-dev`: the same image with the `dev` feature, for local container stacks on Apple Silicon.
- `checks`: rustfmt, clippy and nextest, run by `nix flake check`.

CI (`.github/workflows/ci.yml`) runs `just check` in the dev shell, `nix flake check`, and the x86_64 image build on every pull request and push to `main`. It fails if the `rsa` crate (RUSTSEC-2023-0071) or OpenSSL enters the dependency graph. Nothing is pushed or deployed yet.

## API conventions

- **Headers.** Every response carries `Strict-Transport-Security: max-age=63072000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` and `Cache-Control: no-store`, and no `Server` header.
- **CORS.** Only `DASHBOARD_ORIGIN`, with methods GET, POST, PUT, PATCH and DELETE, request headers `Authorization`, `Content-Type` and `Idempotency-Key`, exposed headers `Idempotent-Replayed`, `Retry-After` and `X-Request-Id`, and a preflight max age of a day. No credentials: the dashboard sends a bearer token.
- **Rate limits.** In memory per worker, so the effective limits grow with the worker count: per client IP on every request (the peer address; the load balancer keeps the client's), and per user on mutations once the token is validated. Excess requests get `429 rate_limited` with `Retry-After`.
- **Request IDs.** Every response carries `X-Request-Id`: the client's value if it's a valid UUID, otherwise a new one. The same ID is on the request's log lines and on its audit event.
- **Audit events.** Every mutation, failed mutation and admin read logs exactly one event with target `audit` when it completes, for operators to query in Azure Monitor. An event carries only `event` (for example `credential_issued`), `outcome` (`success` or `failure`), `code` on failure, `request_id`, `user_id`, and where relevant `pool`, `record_id`, `wallet_id`, `rows` and `signature`; never CSV content, emails, free-text reasons, keys or client IP addresses. The output leaves the TEE through the host, so these events are diagnostics: the pool's own records and the chain are the audit trail users rely on.
- **Errors.** Every error, including unknown routes and malformed bodies, has one body shape: `{ "error": "<message>", "code": "<snake_case code>", "request_id": "<id>" }`. Clients branch on `code`; `error` is for people. Codes by status: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `method_not_allowed`, `request_timeout`, `conflict`, `payload_too_large`, `unsupported_media_type`, `unprocessable_entity`, `rate_limited`, `internal_error`, `service_unavailable`. More specific codes: `idempotency_key_required`, `invalid_cursor` and `validation_failed` (400), `wallet_exists` (409), `idempotency_mismatch` (422), `integrity_error` (500), `storage_unavailable`, `rpc_unavailable`, `attestation_unavailable` and `reference_values_unavailable` (503). A lost compare-and-swap, or an initialisation another upload beat, is a plain `conflict` (409).
- **Idempotency.** Every mutating route requires an `Idempotency-Key` header: a UUID the client generates for one user action and reuses on every retry of it. Without one the request fails with `400 idempotency_key_required`; `POST …/estimate` is read-only and needs none. A retry of a completed request returns the stored status and body with `Idempotent-Replayed: true`, on any worker; the same key with a different method, path or body returns `422 idempotency_mismatch`. The fingerprint of a sealed upload covers the decrypted CSV, so a retry sealed afresh still matches. Keys are scoped to the user. There's no in-progress state: attempts running at once all run, converge on one effect, and return the first stored response. Failures aren't stored, so a retry after one runs again. IDs derive from the user and the key (the pool UUID and its right IDs, the upload and issuance record ID, the wallet ID), and a chain write stores its signed transaction in the record before sending it, so every retry resends that transaction and a request never creates two pools, burns two DRTs or sends a transfer twice. A storage lifecycle rule deletes records after 7 days. JSON bodies must be sent as `application/json`.
- **Pagination.** Lists take `cursor` and `limit` and return `next_cursor` when there's another page (see [Storage](#storage)).

## Endpoints

- **Health:** `GET /health/live` answers 200 while the process runs. `GET /health/ready` answers 200 only when the worker holds its four keys, has a valid certificate (or serves plain HTTP in a dev build), its storage canary (a read and a conditional write of the sealed `state/canary/{worker_id}`, every 20 seconds) succeeded within 60 seconds, and it isn't draining. It reads cached state only and never depends on Solana RPC. `GET /health` returns details for operators: keys held, certificate expiry, canary age, key cache age, Solana RPC status (checked every 30 seconds), version and host data. On SIGTERM the worker fails readiness at once, keeps serving for 10 seconds so the load balancer notices, then stops accepting connections and gives in-flight requests up to 40 seconds; Ctrl-C skips the 10 seconds, and a second Ctrl-C exits at once.
- **Attestation:** `GET /v1/attestation` returns `{ maa_token, transport_jwk, kid }`: an MAA token whose `x-ms-runtime.keys[0]` is the transport public key, and the key's RFC 7638 thumbprint. The worker requests the token at startup, refreshes it at 80% of its lifetime and serves it from memory; it answers 503 until the first token arrives. `GET /v1/attestation/public-key` still returns the bare transport public key, which the dashboard seals uploads to.
- **Reference values:** `GET /v1/reference-values` returns the environment's signed manifest of approved workloads (the attestation claims, transport key IDs and `tls-key` SPKI hashes clients may trust) as a compact JWS (ES256), with `Content-Type: application/jose`. The manifest is signed outside the worker and kept in the public `reference-values` container as `{ENVIRONMENT}/{sequence}.jws`, the current one also as `{ENVIRONMENT}/latest.jws`. Workers serve the latest as it is, looking for it every 10 seconds until one loads, then every 5 minutes, and answer `503 reference_values_unavailable` until then. A worker logs `alert = "reference_values_mismatch"` if the manifest doesn't list its transport key, because clients then refuse to seal uploads to it. Clients verify the signature against the manifest key pinned for the environment, the validity window, and that the sequence never goes down.
- **Users:** `GET /v1/users/me` returns `{ user_id, email, display_name, roles, permissions }`. `GET /v1/users` (`users:read`) lists everyone who has signed in, `{ users: [{ user_id, email, display_name, roles, first_seen, last_seen }], next_cursor }`, sorted by email; `GET /v1/users?email=` is an exact, case-insensitive match returning `{ user_id, email, display_name }`, or 404.
- **Wallets:** `GET` and `POST /v1/wallets`; `GET` and `DELETE /v1/wallets/{id}`; `GET …/balance`; `POST …/estimate` and `…/send`; `GET …/transactions` and `…/transactions/{signature}`.
- **Pools:** `POST /v1/drt/pools/malta`; `GET /v1/drt/pools/list`, `/v1/drt/pools/{pda}`, `…/drt/{name}` and `/v1/drt/pools/by-wallet/{wallet_id}`; `POST` and `GET …/schema`; `POST …/initialize`, `…/issue` and `…/revoke`; `GET …/revocations`, `…/summary` and `…/issuance-log`. The summary, issuance log and revocations together are the pool's audit trail: who created it and when, with the creation signature; the initial upload; each issuance with its burn signature; and each revocation with who, when and why.
- **Admin:** `GET /v1/admin/status`, `/v1/admin/wallet-stats` and `/v1/admin/wallets`; `POST /v1/admin/wallets/{id}/suspend` and `…/activate`.
- **Docs:** `GET /api-doc/openapi.json`; Swagger UI at `/docs` in builds with the `swagger-ui` feature.

Analyst grants, DRT script execution and the data query were removed from this server and will be rebuilt on the new stack. `drt-examples/` keeps an example DRT script for that work.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
