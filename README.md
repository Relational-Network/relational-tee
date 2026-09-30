# relational-tee

The worker behind IOB MicRes: an Axum server that runs Use Case 1 credential pools on Solana (create a Malta pool, upload its schema, initialise it, issue and revoke credentials, read the issuance log and audit trail) and custodial Solana wallets (create, balance, fee estimate, send, history, admin suspend and activate).

> **Migration in progress.** This repo was imported from `relational-sdk`, a Gramine SGX enclave, and is being moved to Azure Confidential Containers (AMD SEV-SNP). Gramine, RA-TLS, the SGX build and the old SSH deployment are gone, and the server now builds and runs natively. Still to come: key release and attestation on real Azure hardware. Until then, parts of the server are interim, as described below.

## What works today, and what's interim

- **Transport.** The worker serves HTTPS (TLS 1.3, rustls with aws-lc-rs) with `tls-key`, which is released only to attested workers and never written anywhere. Its certificate chain is `{spki_sha256}/chain.pem` in the public `tls` container, where `spki_sha256` is the hex SHA-256 of the key's SubjectPublicKeyInfo, so clients can pin the key across renewals. While there's no chain, any worker writes a CSR for `API_HOSTNAME`, signed with `tls-key`, to `{spki_sha256}/csr.pem`, create-only, for the certificate job to sign; workers look for the chain every 10 seconds until they have one, then every 5 minutes, and swap renewals in without a restart. A chain whose leaf isn't `tls-key`'s is ignored and logged with `alert = "tls_chain_mismatch"`. Readiness requires a loaded, unexpired chain. Release builds have no plain HTTP path; dev builds serve plain HTTP on `127.0.0.1:8443` unless `TRANSPORT=https`, and `just dev-cert` is their certificate job.
- **Keys.** At startup the worker obtains four P-256 keys, `transport-key`, `storage-root`, `tls-key` and `commitment-key`, and keeps them in memory only. Release builds get them from Microsoft's SKR sidecar on localhost (`KEY_PROVIDER=skr`), which releases a key only to a confidential container group whose attested policy matches the key's release policy. Dev builds default to `KEY_PROVIDER=local`, which reads dev keys from `dev/keys/` (`just dev-keys` creates them); release builds don't contain that provider and refuse `KEY_PROVIDER=local`. Uploads are sealed to `transport-key`, which every worker shares. Besides its current version, a worker opens uploads sealed to any version the reference-values manifest lists with a Key Vault `version`: it releases that version through its key provider (as `transport-key/{version}`), checks that its thumbprint is the listed `kid`, and drops it once a manifest no longer lists it. During a rotation the manifest lists both versions, so every worker opens uploads sealed to either, whichever it started with; the old one stops opening when CD publishes the manifest that retires it, after its 24-hour soak. `KEY_PROVIDER=local` and the fake sidecar know one other version, `previous` (`transport-key.previous.jwk`).
- **Storage.** All durable state lives in Azure Blob Storage as documents sealed inside the worker with a key derived from `storage-root` (see [Storage](#storage)); workers keep nothing on local disk. Dev builds default to the same sealed objects in local files under `./data`.
- **Grant commitments.** An issuance burns an append DRT into a Grant PDA derived from its commitment: HMAC-SHA256 over the issuance's record ID, the pool UUID and the append DRT's right ID, under a key derived from `commitment-key` with HKDF-SHA256 (salt `relational-tee/commitment`, info `k-commit-v1`). Only a worker holds that key, so only a worker can tell which Grant PDA belongs to which record. `commitment-key` never changes within an environment, because every Grant PDA depends on it. A retried issuance burns under the commitment its first attempt staged.
- **Auth.** Protected endpoints take Entra ID access tokens for the worker's API app registration. A token must be RS256, signed by a key from the pinned tenant's JWKS (`https://login.microsoftonline.com/{tid}/discovery/v2.0/keys`, cached for 24 hours, fetched by one request at a time, and refetched for an unknown `kid` at most once a minute), with that tenant's exact `iss` and `tid`, the API's client ID as `aud`, an allowed client as `azp`, and `access_as_user` in `scp`; `exp` and `nbf` allow 60 seconds of skew. jsonwebtoken verifies RS256 through aws-lc-rs, so the `rsa` crate stays out. A caller's `(tid, oid)` maps to an internal `user_id`, created at their first sign-in; every stored reference to a person uses it. The `Admin` app role grants the permissions `pools:read`, `pools:create`, `pools:write`, `wallets:read` and `users:read`, and is itself required for wallet creation, deletion and sends and for `/v1/admin/…`; a caller with no role can call only `/v1/users/me` and the pool list. Pool writes also need pool ownership, and wallet routes wallet ownership.
- **Dev tokens.** Dev builds also trust one more key, the dev token signing key `dev/keys/entra-signing-key.pem` (`just dev-keys` creates it), so tests, scripts and CI can call the API offline: `just dev-token` prints a token for it (see [Running it locally](#running-it-locally)). Release builds contain none of this code and refuse `DEV_TOKEN_KEY`.
- **Dev manifest.** Dev builds can sign a dev reference-values manifest with the dev manifest key `dev/keys/manifest-signing-key.jwk` (`just dev-keys` creates it), so a dashboard that pins that key verifies local workers as it verifies real ones (see [The dev manifest](#the-dev-manifest)). Release builds contain no signing code; their manifests come from CD.
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
| `just dev-keys` | Create any missing dev keys in `dev/keys/`: one private JWK per key, the dev MAA signing key, the dev token signing key and the dev manifest key; existing keys are kept |
| `just dev-token` | Print a token signed with the dev token signing key: `Admin` by default; `--roles`, `--oid`, `--tid`, `--email`, `--name` and `--azp` change it, and `--bad expired\|not-yet-valid\|audience\|tenant\|client\|scope` makes one the worker must refuse |
| `just dev-manifest` | Sign a dev reference-values manifest and store it where dev workers serve it (see [The dev manifest](#the-dev-manifest)); `--public-key` prints the key a dashboard pins, `--sequence` and `--days` change the manifest, and `--bad expired\|host-data\|transport-key\|signature` makes one a dashboard must refuse |
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
| `just faults` | Run the idempotency fault-injection suite against the local stack, which it (re)starts with fault injection on and a fast reconciler (see [Fault injection](#fault-injection)); `--runs N` sets the randomised runs |

`just image` and `just image-dev` run Nix in a `nixos/nix` container with a cached `/nix` volume, so a Mac needs no separate Linux builder. On Apple Silicon the x86_64 image runs under emulation.

### The fake SKR sidecar

Dev builds include `relational-tee fake-skr`, a stand-in for Microsoft's SKR sidecar. It serves `POST /key/release` and `POST /attest/maa` with the sidecar's request and response shapes, answering from the dev keys, so the production client code path runs unchanged. It signs attestation tokens RS256 with the dev MAA key, with MAA's claim names and a fixed dev host data value, and serves that key's public half at `GET /certs` (with `Access-Control-Allow-Origin: *`), as MAA does: a dashboard can use `http://localhost:9000` as its attestation authority. A key without a dev key file gets 403, like a release policy mismatch.

| Variable | Default | Purpose |
|---|---|---|
| `FAKE_SKR_ADDR` | `127.0.0.1:9000` | Listening address |
| `FAKE_MAA_ISSUER` | `http://localhost:{port}` | The tokens' `iss`, and where `/certs` is served |
| `FAKE_MAA_TOKEN_SECS` | `28800` (8 hours) | Token lifetime |
| `FAKE_MAA_DEBUGGABLE` | `off` | `on` makes tokens say the workload is debuggable, which clients must refuse |
| `DEV_KEYS_DIR` | `dev/keys` | Dev keys to release and sign with |

Not there yet: a debug-mode sandbox on Azure.

### Fault injection

A dev worker started with `FAULT_INJECTION=on` honours an `X-Fault-Exit` request header naming a point in a request: `staged` (a pool creation or issuance staged its saga), `tx_stored` (a chain step stored its signed transaction), `tx_sent`, `tx_confirmed`, or `recorded` (the request's last document write is done, its response isn't stored). When the request reaches that point, the process exits at once with status 137, as if it had been killed. Release builds contain none of this and refuse `FAULT_INJECTION`.

`just faults` starts the local stack with `dev/compose.faults.yaml` layered on (fault injection on, and the reconciler running every 15 seconds for sagas older than 45 seconds), then runs `relational-tee faults` against the proxy. The suite calls the API as dev-token users, seals uploads to the stack's transport key, and crashes workers mid-request; compose restarts them, and the suite retries with the same `Idempotency-Key`. It checks that:
- a replay returns the stored response and creates nothing, and a reused key with another body gets `422`;
- two concurrent attempts with one key have one effect and one response;
- a worker killed after each step of an issuance or a pool creation, with the request retried on another, burns one DRT, adds one issuance entry, and leaves one pool document;
- after a crash between the burn and the pool document, with no retry, the reconciler adds the entry;
- two users with one key get different IDs;
- randomised runs across issue, pool creation, wallet creation, send and revoke, with duplicates, concurrent attempts and crashes, leave no double burn, double transfer, lost update or second wallet.

Chain steps run on devnet, so the suite user's wallet in the stack needs about 0.2 devnet SOL; the suite stops at once and names the address if it holds less. The stack keeps its data in memory, so move any SOL left in that wallet elsewhere before `just stack-down`.

### The dev manifest

`just dev-manifest` signs a reference-values manifest (ES256) with the dev manifest key and stores it as `reference-values/{ENVIRONMENT}/{sequence}.jws` and `latest.jws` in the storage the environment names (`STORAGE_BACKEND`, `DATA_DIR`; by default `./data/reference-values/dev/`), where dev workers pick it up within 10 seconds. It approves what dev workers present: the fake MAA's claim set (attestation type `sevsnpvm`, compliance status `azure-compliant-uvm`, not debuggable, VMPL 0, the fixed dev host data) with `FAKE_MAA_ISSUER` (default `http://localhost:9000`) as its authority, the dev transport key's thumbprint (and the previous version's, with `version` `previous`, if `transport-key.previous.jwk` exists), and the SHA-256 of the dev `tls-key`'s SPKI. It is valid for 30 days, its commit is the checkout's, and its sequence is the current Unix time, or one more than the latest manifest's, so a browser that remembers the highest sequence it saw keeps accepting new ones. It prints `VITE_MANIFEST_PUBLIC_KEY=…`, the public key a dashboard's dev build pins.

To run the dashboard's attestation checks against a local worker: `just skr` (it serves the fake MAA's keys at `http://localhost:9000/certs`), `just dev-manifest`, `just dev`, then `just spa` with `VITE_MANIFEST_PUBLIC_KEY` set to the printed key and `VITE_MAA_AUTHORITY=http://localhost:9000`. Sign a new manifest after 30 days, after deleting `./data`, or after changing the dev keys.

To rehearse a transport key rotation: move `dev/keys/transport-key.jwk` to `transport-key.previous.jwk`, run `just dev-keys` (a new current version) and `just dev-manifest` (which lists both), and restart the worker; `GET /health` then shows both in `transport_kids`. To retire the previous version, delete `transport-key.previous.jwk` and run `just dev-manifest` again: workers stop opening uploads sealed to it at their next manifest check (within 5 minutes, or at once after a restart), and refuse them with `400 sealed_payload_invalid`.

### Running it locally

- **Fastest:** `just dev` uses dev keys (`KEY_PROVIDER=local`) and sealed local files under `./data` (`STORAGE_BACKEND=files`), which survive restarts, and needs nothing else running.
- **Production code paths:** `just skr` and `just azurite` in other terminals, then `KEY_PROVIDER=skr STORAGE_BACKEND=azurite just dev`. The worker then releases keys and attests through the SKR client, and stores everything in Azurite through the Azure client, signing with Azurite's well-known Shared Key.
- **Several workers:** `just image-dev` once, then `just stack-up` ([`compose.yaml`](compose.yaml)). Three workers share Azurite and one fake SKR sidecar behind HAProxy on `127.0.0.1:8443`, which round-robins at layer 4 and probes `/health/ready` like the Azure load balancer. The fake sidecar's `/certs` is on `127.0.0.1:9000`. Once the stack is up, `just stack-up` signs a dev manifest into its storage (the one-shot `manifest` service), so a dashboard with the usual dev `.env.local` verifies the stack's workers and seals uploads to them.

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
| `RECONCILER_INTERVAL_SECS`, `RECONCILER_MIN_AGE_SECS` | `300`, `600` | refused | How often the reconciler runs, and how old a saga must be to finish |
| `FAULT_INJECTION` | `off` | refused | `on` honours `X-Fault-Exit` (see [Fault injection](#fault-injection)) |
| `RUST_LOG` | `info` | `info` | Log filter |
| `LOG_FORMAT` | `text` | `json` | `json` writes one JSON object per line (see [Logs](#api-conventions)); `text` writes readable lines |

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
- **Request limits.** Bodies may be 1 MiB, or 50 MiB on the upload routes (`POST …/initialize` and `…/issue`); larger ones get `413 payload_too_large`. A request may run for 60 seconds, or 300 on the upload routes; one still running gets `408 request_timeout` and stops where it was, as if the worker had died there, so a retry with the same `Idempotency-Key` resumes it. Pool creation waits up to 60 seconds for `finalized`, so under a slow RPC it can end in a `408` that a retry finishes. A request head (HTTP/1.1), or header list (HTTP/2), may be 16 KiB, and an HTTP/1.1 request may carry 100 header fields; beyond either it gets `431`. An HTTP/1.1 connection has 10 seconds to send each request's headers, idle keep-alive time included, and a TLS handshake has 10 seconds; past either, the connection is closed. An HTTP/2 connection whose client has been silent for 20 seconds gets a ping, and is closed if the ping goes unanswered for another 20. A worker serves at most 1,024 connections at once, and closes any more as they arrive, before their TLS handshake, logging it at most once a minute. Clients that answer pings but send nothing still hold their places: a per-IP connection limit would be the next step.
- **Request IDs.** Every response carries `X-Request-Id`: the client's value if it's a valid UUID, otherwise a new one. The same ID is on the request's log lines and on its audit event.
- **Logs.** With `LOG_FORMAT=json` (release builds' default) each line is one JSON object: `timestamp`, `level`, `target`, `message` and the event's own fields at the top level, and inside a request a `span` object with `method`, `path`, `request_id`, and once known the `route` template and the caller's `user_id`. The line that ends a request, `Finished the request`, adds `status` and `latency_ms`, so log-based metrics can count requests, errors and latency by route. People appear only as `user_id`: no line carries a token, an email or an Entra object ID.
- **Audit events.** Every mutation, failed mutation and admin read logs exactly one event with target `audit` when it completes, for operators to query in Azure Monitor. An event carries only `event` (for example `credential_issued`), `outcome` (`success` or `failure`), `code` on failure, `request_id`, `user_id`, and where relevant `pool`, `record_id`, `wallet_id`, `rows` and `signature`; never CSV content, emails, free-text reasons, keys or client IP addresses. The output leaves the TEE through the host, so these events are diagnostics: the pool's own records and the chain are the audit trail users rely on.
- **Errors.** Every error, including unknown routes and malformed bodies, has one body shape: `{ "error": "<message>", "code": "<snake_case code>", "request_id": "<id>" }`. Clients branch on `code`; `error` is for people. Codes by status: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `method_not_allowed`, `request_timeout`, `conflict`, `payload_too_large`, `unsupported_media_type`, `unprocessable_entity`, `rate_limited`, `internal_error`, `service_unavailable`. More specific codes: `idempotency_key_required`, `invalid_cursor`, `validation_failed`, `sealed_payload_invalid` and `transaction_rejected` (400), `wallet_exists` (409), `idempotency_mismatch` (422), `integrity_error` (500), `storage_unavailable`, `rpc_unavailable`, `attestation_unavailable` and `reference_values_unavailable` (503). A lost compare-and-swap, or an initialisation another upload beat, is a plain `conflict` (409). `transaction_rejected` means Solana's preflight check refused the transaction for a reason resending can't cure, such as a wallet short of SOL for the fee or rent, and `error` carries Solana's reason; a retry with the same key succeeds once the cause is fixed. A transaction the RPC couldn't check, or whose blockhash it didn't know, is `503 rpc_unavailable`.
- **Sealed uploads.** `POST …/initialize` and `POST …/issue` take a multipart form with the parts `v` (`1`), `kid`, `enc` and `ct`: the CSV sealed with RFC 9180 HPKE in base mode (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the transport key `GET /v1/attestation` returns, with `info` `relational-tee/hpke/v1`. `kid` is that key's RFC 7638 thumbprint, `enc` the encapsulated key in unpadded base64url, and `ct` the ciphertext, as a binary part. The AAD is these UTF-8 lines joined by `\n`, with no trailing newline: `relational-tee/req/v1`, the method, the request path as sent (percent-encoded, without the query), the `Idempotency-Key` in canonical lowercase form, the `kid`, and the caller's `user_id` from `GET /v1/users/me`. A ciphertext therefore opens only for the pool, route, key and user it was sealed for. The worker opens it after authentication and before the idempotency check. Any failure is `400 sealed_payload_invalid`, with no detail (the worker logs the reason); a plaintext `file` part is refused with `400 bad_request`.
- **Idempotency.** Every mutating route requires an `Idempotency-Key` header: a UUID the client generates for one user action and reuses on every retry of it. Without one the request fails with `400 idempotency_key_required`; `POST …/estimate` is read-only and needs none. A retry of a completed request returns the stored status and body with `Idempotent-Replayed: true`, on any worker; the same key with a different method, path or body returns `422 idempotency_mismatch`. The fingerprint of a sealed upload covers the decrypted CSV, so a retry sealed afresh still matches. Keys are scoped to the user. There's no in-progress state: attempts running at once all run, converge on one effect, and return the first stored response. Failures aren't stored, so a retry after one runs again. IDs derive from the user and the key (the pool UUID and its right IDs, the upload and issuance record ID, the wallet ID), and a chain write stores its signed transaction in the record before sending it, so every retry resends that transaction and a request never creates two pools, burns two DRTs or sends a transfer twice. A storage lifecycle rule deletes records after 7 days. JSON bodies must be sent as `application/json`.
- **Pagination.** Lists take `cursor` and `limit` and return `next_cursor` when there's another page (see [Storage](#storage)).

## Endpoints

- **Health:** `GET /health/live` answers 200 while the process runs. `GET /health/ready` answers 200 only when the worker holds its four keys, has a valid certificate (or serves plain HTTP in a dev build), its storage canary (a read and a conditional write of the sealed `state/canary/{worker_id}`, every 20 seconds) succeeded within 60 seconds, and it isn't draining. It reads cached state only and never depends on Solana RPC. `GET /health` returns details for operators: keys held, the transport key versions uploads open with, certificate expiry, canary age, key cache age, Solana RPC status (checked every 30 seconds), version and host data. On SIGTERM the worker fails readiness at once, keeps serving for 10 seconds so the load balancer notices, then stops accepting connections and gives in-flight requests up to 40 seconds; Ctrl-C skips the 10 seconds, and a second Ctrl-C exits at once.
- **Attestation:** `GET /v1/attestation` returns `{ maa_token, transport_jwk, kid }`: an MAA token whose `x-ms-runtime.keys[0]` is the transport public key, and the key's RFC 7638 thumbprint. The worker requests the token at startup, refreshes it at 80% of its lifetime and serves it from memory; it answers 503 until the first token arrives. Clients seal uploads to that key once they have verified the token against the reference values.
- **Reference values:** `GET /v1/reference-values` returns the environment's signed manifest of approved workloads (the attestation claims, transport key IDs and `tls-key` SPKI hashes clients may trust) as a compact JWS (ES256), with `Content-Type: application/jose`. The manifest is signed outside the worker and kept in the public `reference-values` container as `{ENVIRONMENT}/{sequence}.jws`, the current one also as `{ENVIRONMENT}/latest.jws`. Workers serve the latest as it is, looking for it every 10 seconds until one loads, then every 5 minutes, and answer `503 reference_values_unavailable` until then. A worker logs `alert = "reference_values_mismatch"` if the manifest doesn't list its transport key, because clients then refuse to seal uploads to it. The manifest's `keys.transport` entries with a `version` also decide which other transport key versions the worker opens uploads with (see [Keys](#what-works-today-and-whats-interim)); `GET /health` lists them as `transport_kids`. Clients verify the signature against the manifest key pinned for the environment, the validity window, and that the sequence never goes down. [`deploy/reference-values.schema.json`](deploy/reference-values.schema.json) (JSON Schema 2020-12) describes the payload: everything workers and the dashboard read is required, claim sets can't name a claim clients don't check, and outside `dev` a manifest must also name the images, tools and provenance that rebuild the release, with an `https` MAA authority. Dev-build tests hold the schema to the dev manifest.
- **Users:** `GET /v1/users/me` returns `{ user_id, email, display_name, roles, permissions }`. `GET /v1/users` (`users:read`) lists everyone who has signed in, `{ users: [{ user_id, email, display_name, roles, first_seen, last_seen }], next_cursor }`, sorted by email; `GET /v1/users?email=` is an exact, case-insensitive match returning `{ user_id, email, display_name }`, or 404.
- **Wallets:** `GET` and `POST /v1/wallets`; `GET` and `DELETE /v1/wallets/{id}`; `GET …/balance`; `POST …/estimate` and `…/send`; `GET …/transactions` and `…/transactions/{signature}`.
- **Pools:** `POST /v1/drt/pools/malta`; `GET /v1/drt/pools/list`, `/v1/drt/pools/{pda}`, `…/drt/{name}` and `/v1/drt/pools/by-wallet/{wallet_id}`; `POST` and `GET …/schema`; `POST …/initialize`, `…/issue` and `…/revoke`; `GET …/revocations`, `…/summary` and `…/issuance-log`. The summary, issuance log and revocations together are the pool's audit trail: who created it and when, with the creation signature; the initial upload; each issuance with its burn signature; and each revocation with who, when and why.
- **Admin:** `GET /v1/admin/status`, `/v1/admin/wallet-stats` and `/v1/admin/wallets`; `POST /v1/admin/wallets/{id}/suspend` and `…/activate`.
- **Docs:** `GET /api-doc/openapi.json`; Swagger UI at `/docs` in builds with the `swagger-ui` feature.

Analyst grants, DRT script execution and the data query were removed from this server and will be rebuilt on the new stack. `drt-examples/` keeps an example DRT script for that work.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
