# Relational-SDK

SGX enclave server with RA-TLS, JWT validation, and role-based access control (RBAC).

## Features

- **RA-TLS (DCAP)**: TLS certificates bound to SGX attestation
- **JWT Validation**: Validates AVS-issued tokens with JWKS caching
- **RBAC**: Role-based access control (admin, user, analyst, read_only)
- **WebCrypto Ready**: Exposes P-256 public key for browser-side encryption
- **Custodial Wallets**: Create/manage Solana wallets (1 per user, enforced via redb index)
- **DRT Pools**: Create, buy, redeem, and close Data Rights Token pools on-chain
- **Credential Issuance**: Upload schemas, issue/revoke credentials, full issuance log
- **Audit Trail**: HMAC-signed JSONL events + redb-indexed dual-write for O(k) queries
- **Embedded Database**: 13 redb tables for wallets, pools, issuance, revocations, and audit
- **Pagination**: All list endpoints support `limit`/`offset` query parameters
- **Swagger UI**: Auto-generated OpenAPI docs at `/docs`

---

## Build

### Requirements

⚠️ **IMPORTANT:** `aws-lc-rs` requires **clang** on Ubuntu 20.04. GCC 9.4 has a memcmp bug
that aws-lc-rs refuses to compile against. The Docker build already uses clang.

```bash
sudo apt-get install -y clang
```

### Native (requires SGX hardware + Gramine)

```bash
# Debug build (allows GDB, memory inspection — dev only)
CC=clang CXX=clang++ make RA_TYPE=dcap SGX_DEBUG=1
gramine-sgx relational-sdk

# Production build
CC=clang CXX=clang++ make RA_TYPE=dcap SGX_DEBUG=0
gramine-sgx relational-sdk
```

### Docker (no SGX hardware needed to build)

The image is pre-signed at build time — no signing key is needed at runtime.

```bash
# Build (signs enclave at build time via BuildKit secret)
make docker-build
# or with a custom key:
make docker-build SGX_SIGNING_KEY=/path/to/enclave-key.pem

# Run (requires SGX hardware)
make docker-run

# Stop
make docker-stop
```

Manual Docker run:

```bash
docker run --rm -d \
  --name relational-sdk-sgx \
  --network host \
  --device /dev/sgx/enclave \
  --device /dev/sgx/provision \
  -e AVS_JWKS_URL=http://127.0.0.1:9100/.well-known/jwks.json \
  -e SECRET_PROVISION_SERVERS=127.0.0.1:4433 \
  relationalnetwork/relational-sdk:focal
```

---

## Local Development (Full Stack)

Requires SGX hardware (Azure DCsv3 or bare-metal) and AVS running.

### Quick Start (3 terminals)

**Terminal 1 — AVS:**
```bash
cd ../attestation-verification-service
AVS_SIGNING_KEY_PATH="$(pwd)/secrets/avs-signing-key.pem" \
AVS_ALLOW_DEBUG_ENCLAVE=1 \
AVS_ALLOW_OUTDATED_TCB=1 \
RUST_LOG=info \
./target/release/attestation-verification-service
```

**Terminal 2 — Enclave:**
```bash
CC=clang CXX=clang++ make RA_TYPE=dcap SGX_DEBUG=1
gramine-sgx relational-sdk
```

**Terminal 3 — Test:**
```bash
curl -s http://127.0.0.1:9100/health
curl -sk https://127.0.0.1:8080/health
curl -sk https://127.0.0.1:8080/v1/attestation/public-key | jq
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AVS_JWKS_URL` | `http://127.0.0.1:9100/.well-known/jwks.json` | AVS JWKS endpoint |
| `SECRET_PROVISION_SERVERS` | — | Secret provisioning server (e.g. `127.0.0.1:4433`) |
| `RUST_LOG` | `info` | Log level |

---

## Enclave Measurements & Reproducibility

The MRENCLAVE hash uniquely identifies the enclave binary and trusted files. [`measurements.toml`](measurements.toml)
is the committed source of truth and pins the full build contract (base image SHA, Ubuntu snapshot,
Gramine and Rust versions, SIGSTRUCT date, and the expected `[enclave]` block).

```bash
# Print [enclave] block from a locally built image (in measurements.toml layout)
make docker-sigstruct

# Rebuild --no-cache and verify mr_enclave matches measurements.toml
make verify-mrenclave
```

**When MRENCLAVE changes** (code, Gramine/SGX packages, Rust toolchain, or trusted files change):
1. Run `make docker-build && make docker-sigstruct` — prints the new `[enclave]` block
2. Paste the new block into `measurements.toml`
3. Commit code change + `measurements.toml` together in the same PR

CI fails if the built `mr_enclave` differs from `measurements.toml`, preventing silent changes.
The signing key is consumed at build time only and is never present in any image layer or on the staging VM.

| Factor | MRENCLAVE | MRSIGNER |
|--------|:---------:|:--------:|
| Source code | ✅ | ❌ |
| Gramine / SGX package versions | ✅ | ❌ |
| Rust toolchain | ✅ | ❌ |
| `SGX_DEBUG` | ✅ | ❌ |
| Signing key | ❌ | ✅ |

---

## Deployment

### CI/CD Overview

- **CI** (`ci.yml`): Lint, test, build + sign Docker image, push to GHCR, verify MRENCLAVE matches `measurements.toml`, fail on `debug_enclave != False`, print deploy-by-digest reference to the run summary
- **CD** (`cd-staging.yml`): Pull pre-built image from GHCR, deploy to staging VM

The staging VM does **not** build or sign — it only runs the pre-built image from GHCR.

**Image tags:**
- `sha-<commit>` — every push (canonical, used by CD)
- `staging-latest` — latest `staging` branch push
- `latest` — latest `main` branch push

### Staging Deployment

**Live URL:** https://iob-staging.duckdns.org
**VM:** Azure DCsv3 (`iob-staging` in resource group `iob`)

```bash
# Push to staging branch — triggers CI (build + sign) then CD (pull + deploy)
git checkout staging
git merge main
git push origin staging
```

### Systemd Service

```bash
sudo systemctl start enclave
sudo systemctl status enclave
sudo journalctl -u enclave -f
```

### Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `STAGING_HOST` | Staging VM IP |
| `STAGING_USER` | SSH user |
| `STAGING_SSH_KEY` | SSH private key for staging VM |
| `GHCR_TOKEN` | PAT with `read:packages`, `write:packages` |
| `ENCLAVE_SIGNING_KEY` | PEM content of enclave signing key (`cat enclave-key.pem`) |

### Signing Key Setup (one-time)

The enclave is signed at CI build time via `--mount=type=secret`. The key is never stored
in any Docker layer or on the staging VM.

```bash
# Generate signing key
openssl genrsa -out ~/.config/gramine/enclave-key.pem -3 3072

# Add to GitHub secret ENCLAVE_SIGNING_KEY
cat ~/.config/gramine/enclave-key.pem
```

---

## Endpoints

Health endpoints are unversioned; all others use `/v1/` prefix.

### Health
- `GET /health` — readiness summary (200 or 503)
- `GET /health/live` — liveness
- `GET /health/ready` — readiness

### Attestation
- `GET /v1/attestation/public-key` — enclave public key (JWK)

### Data
- `POST /v1/data/query` — analyst-only; runs a verified DRT (WASM) script against the granted pool's dataset

### User & Wallet
- `GET  /v1/users/me` — current user identity
- `POST /v1/wallets` — create wallet (one per user)
- `GET  /v1/wallets` — list caller's wallets
- `GET  /v1/wallets/{id}` — get wallet
- `DELETE /v1/wallets/{id}` — soft-delete wallet

### Balance & Transactions
- `GET  /v1/wallets/{id}/balance` — SPL token + SOL balance
- `POST /v1/wallets/{id}/estimate` — estimate transaction fee
- `POST /v1/wallets/{id}/send` — send SOL/SPL
- `GET  /v1/wallets/{id}/transactions` — list transactions
- `GET  /v1/wallets/{id}/transactions/{sig}` — transaction status

### DRT Pools (digital_rights_tokens program)
- `POST /v1/drt/pools/malta` — create Malta (CSV-driven) pool
- `POST /v1/drt/pools/iob-erp` — create IOB ERP (Jitterbit-driven) pool
- `GET  /v1/drt/pools/{pda}` — pool info
- `GET  /v1/drt/pools/{pda}/drt/{name}` — on-chain DRT inspection
- `GET  /v1/drt/events/{sig}` — decoded transaction events

### DRT Grants (pool owner ↔ analyst)
- `POST /v1/drt/pools/{pda}/grant` — burn 1 admin DRT, write Grant PDA for analyst
- `POST /v1/drt/pools/{pda}/revoke-grant` — close Grant PDA
- `GET  /v1/drt/pools/{pda}/grant/{analyst_id}/{drt_name}` — live on-chain grant status
- `GET  /v1/drt/pools/{pda}/grants` — local mirror (pool owner only): active + revoked
- `GET  /v1/drt/me/grants` — caller's grants grouped by pool

### Credentials (pool owner)
- `POST /v1/drt/pools/{pda}/schema` — upload pool schema
- `GET  /v1/drt/pools/{pda}/schema` — fetch pool schema
- `POST /v1/drt/pools/{pda}/initialize` — seed initial dataset
- `POST /v1/drt/pools/{pda}/issue` — issue credentials (redeems an append DRT)
- `POST /v1/drt/pools/{pda}/revoke` — revoke credentials
- `GET  /v1/drt/pools/{pda}/revocations` — list revocations (paginated)
- `GET  /v1/drt/pools/{pda}/audit` — pool-scoped audit log (paginated, filterable)
- `GET  /v1/drt/pools/{pda}/summary` — pool metadata + on-chain state
- `GET  /v1/drt/pools/{pda}/issuance-log` — issuance records (paginated)
- `GET  /v1/drt/pools/by-wallet/{id}` — pools by wallet (paginated)
- `GET  /v1/drt/pools/list` — all pools (marketplace discovery)

### Admin
- `GET  /v1/admin/status` — admin role check + uptime
- `GET  /v1/admin/wallet-stats` — aggregate wallet stats
- `GET  /v1/admin/wallets` — list all wallets (paginated)
- `GET  /v1/admin/audit/events` — query audit log by date (paginated)
- `POST /v1/admin/wallets/{id}/suspend` — suspend wallet
- `POST /v1/admin/wallets/{id}/activate` — reactivate wallet
- `POST /v1/admin/log-role-change` — record a role change in the audit trail

### Docs
- `GET /docs` — Swagger UI (built with `--features swagger-ui`)
- `GET /api-doc/openapi.json` — OpenAPI spec

---

## JWT Authentication

1. Client calls AVS `POST /v1/attest` with enclave URL → receives signed JWT
2. Client sends JWT in `Authorization: Bearer <token>`
3. Enclave validates JWT against AVS JWKS

**Required claims:** `iss`, `sub`, `aud` (`relational-sdk`), `exp`, `role` (`admin`/`user`/`analyst`/`read_only`), `enclave_public_key` (JWK — mandatory, must match the live enclave key)

**Role hierarchy:** `admin` ⊃ `user` ⊃ `analyst` ⊃ `read_only`

`sub` and `role` are derived by AVS from the verified Clerk session — the dashboard does not pass them in the `/v1/attest` body.

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:9100/v1/attest \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $CLERK_TOKEN" \
  -d '{"enclave_url":"https://127.0.0.1:8080"}' \
  | jq -r '.token')

curl -sk https://127.0.0.1:8080/v1/users/me     -H "Authorization: Bearer $TOKEN"
curl -sk https://127.0.0.1:8080/v1/admin/status -H "Authorization: Bearer $TOKEN"
```

---

## Testing Attestation

A C-based RA-TLS client in `attestation-client/` verifies the SGX quote in the TLS certificate.

```bash
make test-attest        # basic attestation test
make test-attest-all    # includes negative tests (wrong MRENCLAVE/MRSIGNER)
make show-measurements  # print current enclave measurements from .sig
```

See [`attestation-client/README.md`](attestation-client/README.md) for details.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AVS_JWKS_URL` | `http://127.0.0.1:9100/.well-known/jwks.json` | AVS JWKS endpoint |
| `SECRET_PROVISION_SERVERS` | — | Secret provisioning server |
| `RUST_LOG` | `info` | Log level |
| `TLS_CERT_PATH` | `/tmp/ra-tls.crt.pem` | RA-TLS certificate |
| `TLS_KEY_PATH` | `/tmp/ra-tls.key.pem` | RA-TLS private key |
| `DATA_DIR` | — | If set, readiness checks this directory exists |

## Module Structure

| Module | Description |
|--------|-------------|
| `main.rs` | Entry point, router setup, CORS, security headers, OpenAPI |
| `config.rs` | Configuration constants, env var helpers (CORS, Solana, storage) |
| `auth.rs` | JWT validation, JWKS caching (10s timeout), RBAC extractors |
| `crypto.rs` | Enclave keypair, JWK/JWKS types |
| `data_validation.rs` | CSV schema validation |
| `error.rs` | Unified ApiError type |
| `handlers.rs` | Core HTTP handlers (public key, admin, data stubs) |
| `health.rs` | /health, /health/live, /health/ready |
| `state.rs` | AppState (JWKS cache, storage, Solana client, tx DB) |
| `tls.rs` | RA-TLS PEM loading + normalization |
| `indexer/` | Background Solana transaction poller with sync cooldown |
| `api/mod.rs` | Router assembly, shared pagination, wallet lookup helpers |
| `api/admin.rs` | Wallet stats, list all (paginated), audit query, suspend/activate |
| `api/balance.rs` | SPL token + native SOL balance |
| `api/credentials.rs` | Credential issuance, revocation, pool discovery (paginated) |
| `api/pools.rs` | DRT pool CRUD: create/get/buy/redeem/close |
| `api/transactions.rs` | Estimate fee, send, list, status |
| `api/users.rs` | GET /v1/me — user identity |
| `api/wallets.rs` | Create/list/get/delete wallet (1-wallet-per-user enforced) |
| `blockchain/` | SolanaClient, signing, SPL token ops, DRT contract |
| `storage/audit.rs` | Audit event log with HMAC integrity + redb dual-write |
| `storage/pool_metadata.rs` | PoolMetadata struct + PoolState lifecycle enum |
| `storage/tx_database.rs` | redb-backed durable store (13 tables: wallets, pools, audit, etc.) |
| `storage/tx_cache.rs` | LRU cache (128 entries, 30s TTL) |
| `storage/repository/` | Typed read/write for wallets, transactions |

## License

AGPL-3.0-or-later — see LICENSE.
