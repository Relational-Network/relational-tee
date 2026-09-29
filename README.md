# relational-tee

The worker behind IOB MicRes: an Axum server that runs Use Case 1 credential pools on Solana (create a Malta pool, upload its schema, initialise it, issue and revoke credentials, read the issuance log and audit trail) and custodial Solana wallets (create, balance, fee estimate, send, history, admin suspend and activate).

> **Migration in progress.** This repo was imported from `relational-sdk`, a Gramine SGX enclave, and is being moved to Azure Confidential Containers (AMD SEV-SNP). Gramine, RA-TLS, the SGX build and the old SSH deployment are gone, and the server now builds and runs natively. Still to come: key release and attestation on Azure, Azure Blob and Table storage with encryption at rest, idempotent mutations, Entra ID sign-in, and in-app edge controls. Until then, parts of the server are interim, as described below.

## What works today, and what's interim

- **Transport.** Dev builds serve plain HTTP on `127.0.0.1:8443`, or HTTPS with a local mkcert certificate. Release builds have no plain HTTP path: they read a PEM certificate and key from `TLS_CERT_PATH` and `TLS_KEY_PATH`, and refuse to start without them.
- **Keys.** At startup the worker obtains four P-256 keys, `transport-key`, `storage-root`, `tls-key` and `commitment-key`, and keeps them in memory only. Release builds get them from Microsoft's SKR sidecar on localhost (`KEY_PROVIDER=skr`), which releases a key only to a confidential container group whose attested policy matches the key's release policy. Dev builds default to `KEY_PROVIDER=local`, which reads dev keys from `dev/keys/` (`just dev-keys` creates them); release builds don't contain that provider and refuse `KEY_PROVIDER=local`. Uploads are sealed to `transport-key`, which every worker shares.
- **Storage.** All durable state lives in Azure Blob and Table storage, encrypted inside the worker with keys derived from `storage-root` (see [Storage](#storage)); workers keep nothing on local disk. Dev builds default to an in-memory store.
- **Auth.** Protected endpoints still validate ES256 tokens from the Attestation Verification Service (AVS). The AVS only issues tokens to an SGX enclave it has attested, so authenticated endpoints can't be exercised locally until Entra ID validation replaces it. Public endpoints (`/health*`, `/v1/attestation/public-key`, `/docs`) work.
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
| `just dev-keys` | Create any missing dev keys in `dev/keys/`: one private JWK per key, and the dev MAA signing key; existing keys are kept |
| `just skr` | Run the fake SKR sidecar on `127.0.0.1:9000`; start the worker with `KEY_PROVIDER=skr` to use it |
| `just cert` | Create a locally trusted mkcert certificate in `dev/certs/`; `just dev` then serves HTTPS |
| `just test` | Run the tests with cargo-nextest, in the release and dev configurations; storage tests use the in-memory backend |
| `just azurite` | Start Azurite, the Azure Storage emulator, in Docker (Blob on `127.0.0.1:10000`, Table on `:10002`, data in memory); `just azurite-stop` stops it |
| `just test-azurite` | Run the storage conformance tests against Azurite, starting it first if needed |
| `just check` | Run every gate: rustfmt, clippy (`-D warnings`, with and without all features), the tests, the banned-crate check and `cargo audit` |
| `just spa` | Run the dashboard dev server from `../iob-pilot` (override with `IOB_PILOT_DIR`), using the host's Node and pnpm |
| `just image` | Build the canonical x86_64-linux image with Nix and load it into Docker |
| `just image-dev` | Build the aarch64-linux dev image and load it into Docker |

`just image` and `just image-dev` run Nix in a `nixos/nix` container with a cached `/nix` volume, so a Mac needs no separate Linux builder. On Apple Silicon the x86_64 image runs under emulation.

### The fake SKR sidecar

Dev builds include `relational-tee fake-skr`, a stand-in for Microsoft's SKR sidecar. It serves `POST /key/release` and `POST /attest/maa` with the sidecar's request and response shapes, answering from the dev keys, so the production client code path runs unchanged. It signs attestation tokens RS256 with the dev MAA key, with MAA's claim names and a fixed dev host data value, and serves that key's public half at `GET /certs` (with `Access-Control-Allow-Origin: *`), as MAA does: a dashboard can use `http://localhost:9000` as its attestation authority. A key without a dev key file gets 403, like a release policy mismatch.

| Variable | Default | Purpose |
|---|---|---|
| `FAKE_SKR_ADDR` | `127.0.0.1:9000` | Listening address |
| `FAKE_MAA_ISSUER` | `http://localhost:{port}` | The tokens' `iss`, and where `/certs` is served |
| `FAKE_MAA_TOKEN_SECS` | `28800` (8 hours) | Token lifetime |
| `DEV_KEYS_DIR` | `dev/keys` | Dev keys to release and sign with |

Not there yet: a container stack with several replicas and local fakes for storage and key release, a fault-injection suite for the idempotency work, and a debug-mode sandbox on Azure.

### Configuration

| Variable | Dev default | Release default | Purpose |
|---|---|---|---|
| `BIND_ADDR` | `127.0.0.1` | `0.0.0.0` | Listening IP address |
| `PORT` | `8443` | `8443` | Listening port |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | unset: plain HTTP | required | PEM certificate chain and private key |
| `KEY_PROVIDER` | `local` | `skr` (the only one) | Where keys come from: the SKR sidecar, or dev key files |
| `DEV_KEYS_DIR` | `dev/keys` | n/a | Dev key files for `KEY_PROVIDER=local` |
| `SKR_ENDPOINT` | `http://localhost:9000` | same, loopback only | SKR sidecar address |
| `MAA_ENDPOINT` | `sharedweu.weu.attest.azure.net` | same | Attestation authority the sidecar uses |
| `KEY_VAULT_URL` | a placeholder | required | Key Vault the sidecar releases keys from |
| `KEY_NAMES` | `transport-key,storage-root,tls-key,commitment-key` | same | Key Vault names of the four keys, in that order |
| `STORAGE_BACKEND` | `memory` | `azure` (the only one) | `azure`, `azurite` (Azurite's dev account) or `memory` (lost on exit) |
| `STORAGE_BLOB_URL`, `STORAGE_TABLE_URL` | Azurite's, for `azurite` | required, `https://` | Blob and Table endpoints |
| `MANAGED_IDENTITY_CLIENT_ID` | unset | the worker identity | Which managed identity to request storage tokens for |
| `SOLANA_RPC_URL` | `https://api.devnet.solana.com` | same | Solana RPC endpoint |
| `SOLANA_NETWORK` | `devnet` | same | `devnet` or `mainnet`, for explorer links |
| `AVS_JWKS_URL` | `http://127.0.0.1:9100/.well-known/jwks.json` | same | AVS signing keys |
| `RUST_LOG` | `info` | `info` | Log filter |

Dev builds are the ones with the `dev` Cargo feature (`just dev`, or `cargo run --features dev`).

## Storage

The worker reaches Azure Storage over its own hyper and rustls client, with Entra tokens from the managed identity endpoint (the account has shared keys disabled). It encrypts everything before it leaves the process, so storage sees only ciphertext and hashed identifiers:

- **Keys.** HKDF-SHA256 over `storage-root`'s private scalar, salt `relational-tee/storage-root`, with a versioned label per purpose: `blob-kek-v1`, `table-payload-v1`, `index-hmac-v1`, `audit-hmac-v1`, `log-enc-v1` and `cursor-hmac-v1`.
- **Blobs** get a fresh AES-256-GCM data key each, wrapped (RFC 3394) under the blob key. The additional authenticated data binds each object to its container and path.
- **Table rows** carry their fields in one encrypted `payload` property, bound to the table and the row's keys. Plaintext properties are copies of filter fields; the worker trusts only the payload. User IDs appear in keys only as `h(x)`, an HMAC under the index key.
- **Audit events** carry an HMAC tag under `audit-hmac-v1`, so every worker can verify every event. Each is appended encrypted to the worker's hourly append blob, then indexed by pool and by day. Reads verify each event and return failures with `hmac_valid: false` instead of dropping them.
- **Pools** are rows changed only by ETag compare-and-swap, so no worker needs a lock. Their totals are computed from committed records and revocations, and cached per worker until the pool's newest record changes.
- **Datasets** are staged (a record row claims the ID, then the create-only blob is written), then committed in one atomic batch, and made immutable for 7 days. The dataset's data key lives only in its record row, so deleting it there erases the blob. If an append-DRT burn never reaches the chain, the staged dataset is removed; if it was sent but not confirmed, the record stays staged for reconciliation.
- **Revocations** are appended to an encrypted, HMAC-tagged log (the authoritative record), then indexed per pool.
- **Pagination** uses signed cursors: pass a response's `next_cursor` back as `cursor`, with the same filters. Any worker accepts any worker's cursor. Lists no longer take `offset` or return totals.

Tables and containers are created at startup if they're missing. `STORAGE_BACKEND=azurite` uses Azurite's well-known dev account key (dev builds only); `memory` keeps everything in the process. Azurite doesn't implement immutability policies (it answers 501), so dataset commits there log a warning.

## Build and release

`flake.nix` pins nixpkgs and builds with crane, taking the toolchain from `rust-toolchain.toml`:

- `packages.x86_64-linux.server`: the release binary, statically linked against musl, with mimalloc as its allocator. `SOURCE_DATE_EPOCH` comes from the commit, and build paths are remapped out of the binary.
- `packages.x86_64-linux.image`: an OCI image containing only the binary, a pinned CA bundle and an `/etc/passwd` entry for the non-root user 65532. It has no shell, package manager or Nix. The entrypoint is `/bin/relational-tee`, on port 8443.
- `packages.aarch64-linux.image-dev`: the same image with the `dev` feature, for local container stacks on Apple Silicon.
- `checks`: rustfmt, clippy and nextest, run by `nix flake check`.

CI (`.github/workflows/ci.yml`) runs `just check` in the dev shell, `nix flake check`, and the x86_64 image build on every pull request and push to `main`. It fails if the `rsa` crate (RUSTSEC-2023-0071) or OpenSSL enters the dependency graph. Nothing is pushed or deployed yet.

## API conventions

- **Request IDs.** Every response carries `X-Request-Id`: the client's value if it's a valid UUID, otherwise a new one. The same ID is on the request's log lines and is the `correlation_id` of every audit event the request causes.
- **Errors.** Every error, including unknown routes and malformed bodies, has one body shape: `{ "error": "<message>", "code": "<snake_case code>", "request_id": "<id>" }`. Clients branch on `code`; `error` is for people. Codes by status: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `method_not_allowed`, `request_timeout`, `conflict`, `payload_too_large`, `unsupported_media_type`, `unprocessable_entity`, `rate_limited`, `internal_error`, `service_unavailable`. More specific codes: `invalid_cursor` and `validation_failed` (400), `wallet_exists` and `initialization_in_progress` (409), `integrity_error` (500), `storage_unavailable`, `rpc_unavailable` and `attestation_unavailable` (503).
- **Pagination.** Lists take `cursor` and `limit` and return `next_cursor` when there's another page (see [Storage](#storage)).

## Endpoints

- **Health:** `GET /health/live` answers 200 while the process runs. `GET /health/ready` answers 200 only when the worker holds its four keys, has a valid certificate (or serves plain HTTP in a dev build), its storage canary (a read and a conditional write of `leases/canary/{worker_id}`, every 20 seconds) succeeded within 60 seconds, and it isn't draining. It reads cached state only and never depends on Solana RPC. `GET /health` returns details for operators: keys held, certificate expiry, canary age, key cache age, Solana RPC status (checked every 30 seconds), version and host data. On SIGTERM the worker fails readiness at once, keeps serving for 10 seconds so the load balancer notices, then stops accepting connections and gives in-flight requests up to 40 seconds; Ctrl-C skips the 10 seconds, and a second Ctrl-C exits at once.
- **Attestation:** `GET /v1/attestation` returns `{ maa_token, transport_jwk, kid }`: an MAA token whose `x-ms-runtime.keys[0]` is the transport public key, and the key's RFC 7638 thumbprint. The worker requests the token at startup, refreshes it at 80% of its lifetime and serves it from memory; it answers 503 until the first token arrives. `GET /v1/attestation/public-key` still returns the bare transport public key, which the dashboard seals uploads to.
- **Users:** `GET /v1/users/me`.
- **Wallets:** `GET` and `POST /v1/wallets`; `GET` and `DELETE /v1/wallets/{id}`; `GET …/balance`; `POST …/estimate` and `…/send`; `GET …/transactions` and `…/transactions/{signature}`.
- **Pools:** `POST /v1/drt/pools/malta`; `GET /v1/drt/pools/list`, `/v1/drt/pools/{pda}`, `…/drt/{name}` and `/v1/drt/pools/by-wallet/{wallet_id}`; `POST` and `GET …/schema`; `POST …/initialize`, `…/issue` and `…/revoke`; `GET …/revocations`, `…/audit`, `…/summary` and `…/issuance-log`.
- **Admin:** `GET /v1/admin/status`, `/v1/admin/wallet-stats`, `/v1/admin/wallets` and `/v1/admin/audit/events`; `POST /v1/admin/wallets/{id}/suspend` and `…/activate`; `POST /v1/admin/log-role-change`.
- **Docs:** `GET /api-doc/openapi.json`; Swagger UI at `/docs` in builds with the `swagger-ui` feature.

Analyst grants, DRT script execution and the data query were removed from this server and will be rebuilt on the new stack. `drt-examples/` keeps an example DRT script for that work.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
