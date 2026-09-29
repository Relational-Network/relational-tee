# relational-tee

The worker behind IOB MicRes: an Axum server that runs Use Case 1 credential pools on Solana (create a Malta pool, upload its schema, initialise it, issue and revoke credentials, read the issuance log and audit trail) and custodial Solana wallets (create, balance, fee estimate, send, history, admin suspend and activate).

> **Migration in progress.** This repo was imported from `relational-sdk`, a Gramine SGX enclave, and is being moved to Azure Confidential Containers (AMD SEV-SNP). Gramine, RA-TLS, the SGX build and the old SSH deployment are gone, and the server now builds and runs natively. Still to come: key release and attestation on Azure, Azure Blob and Table storage with encryption at rest, idempotent mutations, Entra ID sign-in, and in-app edge controls. Until then, parts of the server are interim, as described below.

## What works today, and what's interim

- **Transport.** Dev builds serve plain HTTP on `127.0.0.1:8443`, or HTTPS with a local mkcert certificate. Release builds have no plain HTTP path: they read a PEM certificate and key from `TLS_CERT_PATH` and `TLS_KEY_PATH`, and refuse to start without them.
- **Storage.** State lives under `DATA_DIR` as JSON files plus a redb database, **unencrypted on disk**. Use synthetic data only; the server warns about this at startup.
- **Auth.** Protected endpoints still validate ES256 tokens from the Attestation Verification Service (AVS). The AVS only issues tokens to an SGX enclave it has attested, so authenticated endpoints can't be exercised locally until Entra ID validation replaces it. Public endpoints (`/health*`, `/v1/attestation/public-key`, `/docs`) work.
- **Solana.** The public devnet RPC by default. It is rate-limited and has no SLA, and the server warns about it at startup.

## Develop locally

You need [Nix](https://nixos.org) with flakes, and Docker for the image builds.

```bash
nix develop     # pinned Rust, cargo-nextest, cargo-audit, bacon, just, sccache,
                # Node 24, pnpm 10, Azurite, mkcert, actionlint
just            # list the recipes
```

| Recipe | What it does |
|---|---|
| `just dev` | Run the dev build natively on `127.0.0.1:8443`, with Swagger UI at `/docs` |
| `just cert` | Create a locally trusted mkcert certificate in `dev/certs/`; `just dev` then serves HTTPS |
| `just test` | Run the tests with cargo-nextest, in the release and dev configurations |
| `just check` | Run every gate: rustfmt, clippy (`-D warnings`, with and without all features), the tests, the banned-crate check and `cargo audit` |
| `just spa` | Run the dashboard dev server from `../iob-pilot` (override with `IOB_PILOT_DIR`) |
| `just image` | Build the canonical x86_64-linux image with Nix and load it into Docker |
| `just image-dev` | Build the aarch64-linux dev image and load it into Docker |

`just image` and `just image-dev` run Nix in a `nixos/nix` container with a cached `/nix` volume, so a Mac needs no separate Linux builder. On Apple Silicon the x86_64 image runs under emulation.

Not there yet: a container stack with several replicas and local fakes for storage and key release, a fault-injection suite for the idempotency work, and a debug-mode sandbox on Azure.

### Configuration

| Variable | Dev default | Release default | Purpose |
|---|---|---|---|
| `BIND_ADDR` | `127.0.0.1` | `0.0.0.0` | Listening IP address |
| `PORT` | `8443` | `8443` | Listening port |
| `DATA_DIR` | `data` | `/data` | Local storage directory |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | unset: plain HTTP | required | PEM certificate chain and private key |
| `SOLANA_RPC_URL` | `https://api.devnet.solana.com` | same | Solana RPC endpoint |
| `SOLANA_NETWORK` | `devnet` | same | `devnet` or `mainnet`, for explorer links |
| `AVS_JWKS_URL` | `http://127.0.0.1:9100/.well-known/jwks.json` | same | AVS signing keys |
| `RUST_LOG` | `info` | `info` | Log filter |

Dev builds are the ones with the `dev` Cargo feature (`just dev`, or `cargo run --features dev`).

## Build and release

`flake.nix` pins nixpkgs and builds with crane, taking the toolchain from `rust-toolchain.toml`:

- `packages.x86_64-linux.server`: the release binary, statically linked against musl, with mimalloc as its allocator. `SOURCE_DATE_EPOCH` comes from the commit, and build paths are remapped out of the binary.
- `packages.x86_64-linux.image`: an OCI image containing only the binary, a pinned CA bundle and an `/etc/passwd` entry for the non-root user 65532. It has no shell, package manager or Nix. The entrypoint is `/bin/relational-tee`, on port 8443.
- `packages.aarch64-linux.image-dev`: the same image with the `dev` feature, for local container stacks on Apple Silicon.
- `checks`: rustfmt, clippy and nextest, run by `nix flake check`.

CI (`.github/workflows/ci.yml`) runs `just check` in the dev shell, `nix flake check`, and the x86_64 image build on every pull request and push to `main`. It fails if the `rsa` crate (RUSTSEC-2023-0071) or OpenSSL enters the dependency graph. Nothing is pushed or deployed yet.

## Endpoints

- **Health:** `GET /health`, `/health/live`, `/health/ready`.
- **Attestation:** `GET /v1/attestation/public-key` returns the per-process P-256 key that the dashboard seals uploads to.
- **Users:** `GET /v1/users/me`.
- **Wallets:** `GET` and `POST /v1/wallets`; `GET` and `DELETE /v1/wallets/{id}`; `GET …/balance`; `POST …/estimate` and `…/send`; `GET …/transactions` and `…/transactions/{signature}`.
- **Pools:** `POST /v1/drt/pools/malta`; `GET /v1/drt/pools/list`, `/v1/drt/pools/{pda}`, `…/drt/{name}` and `/v1/drt/pools/by-wallet/{wallet_id}`; `POST` and `GET …/schema`; `POST …/initialize`, `…/issue` and `…/revoke`; `GET …/revocations`, `…/audit`, `…/summary` and `…/issuance-log`.
- **Admin:** `GET /v1/admin/status`, `/v1/admin/wallet-stats`, `/v1/admin/wallets` and `/v1/admin/audit/events`; `POST /v1/admin/wallets/{id}/suspend` and `…/activate`; `POST /v1/admin/log-role-change`.
- **Docs:** `GET /api-doc/openapi.json`; Swagger UI at `/docs` in builds with the `swagger-ui` feature.

Analyst grants, DRT script execution and the data query were removed from this server and will be rebuilt on the new stack. `drt-examples/` keeps an example DRT script for that work.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
