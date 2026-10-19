# Development

## The dev shell

You need [Nix](https://nixos.org) with flakes, and Docker for the image builds.

```bash
nix develop     # pinned Rust, cargo-nextest, cargo-audit, osv-scanner, bacon, just,
                # sccache, Azurite, mkcert, actionlint, Surfpool
just            # list the recipes
```

`just image` and `just image-dev` run Nix in a `nixos/nix` container with a cached `/nix` volume, so a Mac needs no separate Linux builder. On Apple Silicon the x86_64 image runs under emulation.

## Recipes

### Running

| Recipe | What it does |
|---|---|
| `just dev` | Run the dev build natively on `127.0.0.1:8443`, with Swagger UI at `/docs` (creates missing dev keys first) |
| `just dev-keys` | Create any missing dev keys in `dev/keys/`: one private JWK per key, the dev MAA signing key, the dev token signing key, the dev manifest key and the fake SKR sidecar's credential; existing keys are kept |
| `just dev-token` | Print a token signed with the dev token signing key: `Admin` by default; `--roles`, `--oid`, `--tid`, `--email`, `--name` and `--azp` change it, and `--bad expired\|not-yet-valid\|audience\|tenant\|client\|scope` makes one the worker must refuse |
| `just dev-manifest` | Sign a dev reference-values manifest and store it where dev workers serve it (see [The dev manifest](#the-dev-manifest)); `--public-key` prints the key a dashboard pins, `--sequence` and `--days` change the manifest, and `--bad expired\|host-data\|transport-key\|signature` makes one a dashboard must refuse |
| `just skr` | Run the fake SKR sidecar on `127.0.0.1:9000`; start the worker with `KEY_PROVIDER=skr` to use it |
| `just dev-cert` | The local certificate job: sign each pending CSR in `data/tls/` with mkcert's local CA (`TRANSPORT=https just dev` writes one; run `mkcert -install` once so browsers trust it) |
| `just spa` | Run the dashboard dev server from `../dashboard` (override with `DASHBOARD_DIR`), using the host's Node and pnpm |
| `just openapi` | Print the OpenAPI document (`relational-tee openapi`), which CI publishes as each run's `openapi` artifact |

### Tests and gates

| Recipe | What it does |
|---|---|
| `just test` | Run the tests with cargo-nextest, in the release and dev configurations; storage tests use local files in temporary directories |
| `just azurite` | Start Azurite's Blob service, the Azure Storage emulator, in Docker on `127.0.0.1:10000`, data in memory; `just azurite-stop` stops it |
| `just test-azurite` | Run the store conformance tests against Azurite, starting it first if needed |
| `just test-blob` | Run the store conformance tests against a real storage account, in a container of their own that they delete afterwards: `CONFORMANCE_BLOB_URL` is the account's Blob endpoint, and the token comes from `az account get-access-token --resource https://storage.azure.com/` (the signed-in user needs Storage Blob Data Contributor) unless `CONFORMANCE_STORAGE_TOKEN` holds one |
| `just scale` | Upload a pilot-sized dataset (100,000 rows of 30 fields, about 30 MiB) as a pool's initial upload and as an issuance, in an optimised build, and print its size against the 50 MiB upload limit and how long each upload took; then time pages that count up to four columns' distinct values over a 100,000-row analysis table |
| `just grant-guard` | Check on devnet that the DRT program refuses a second `grant_right` under one commitment: it simulates a landed grant again, which fails because its Grant PDA exists, and the same grant under a fresh commitment, which passes; and that a transfer's receipt is created once and refused the second time. It needs no keys and spends nothing; `GRANT_GUARD_POOL` picks another pool |
| `just chain-test` | Run the tests named `surfnet_` against a local Surfpool network, offline, which runs the real System, SPL Token, token account and Memo programs: a pool's counter rising by exactly one per change, with lamports at its address beforehand, and a transfer's receipt made once and swept. The fake chain the other tests use is the fault model (transactions that never land or expire, an RPC that refuses or forgets); these check the programs it stands in for |
| `just check` | Run every gate: rustfmt, clippy (`-D warnings`, with and without all features), the tests, the banned-crate check, `cargo audit` and OSV-Scanner |
| `just osv` | Scan `Cargo.lock` with OSV-Scanner, for GitHub's advisories that RustSec lacks (needs network) |

### Images and the stack

| Recipe | What it does |
|---|---|
| `just image` | Build the canonical x86_64-linux image with Nix and load it into Docker as `relational-tee:latest` |
| `just image-dev` | Build the aarch64-linux dev image and load it into Docker as `relational-tee:dev` |
| `just stack-up` | Start the local stack (needs `just image-dev`): Azurite, the fake SKR sidecar, three workers and a round-robin proxy on `127.0.0.1:8443`; `just stack-down` stops it |
| `just faults` | Run the idempotency fault-injection suite against the local stack, which it (re)starts with fault injection on and a fast reconciler (see [Fault injection](#fault-injection)); `--runs N` sets the randomised runs |
| `just load` | Load the stack's first worker, held to a deployed worker's CPU and memory, with queries, uploads and an overload, and report latencies, refusals and its peak memory (see [The load run](#the-load-run)) |

## Running locally

- **Fastest:** `just dev` uses dev keys (`KEY_PROVIDER=local`) and sealed local files under `./data` (`STORAGE_BACKEND=files`), which survive restarts, and needs nothing else running.
- **Production code paths:** `just skr` and `just azurite` in other terminals, then `KEY_PROVIDER=skr STORAGE_BACKEND=azurite just dev`. The worker then releases keys and attests through the SKR client, and stores everything in Azurite through the Azure client, signing with Azurite's well-known Shared Key.
- **Several workers:** `just image-dev` once, then `just stack-up` ([`compose.yaml`](../compose.yaml)). Three workers share Azurite and one fake SKR sidecar behind HAProxy on `127.0.0.1:8443`, which round-robins at layer 4 and probes `/health/ready` like the Azure load balancer. The fake sidecar's `/certs` is on `127.0.0.1:9000`. Once the stack is up, `just stack-up` signs a dev manifest into its storage (the one-shot `manifest` service), so a dashboard with the usual dev `.env.local` verifies the stack's workers and seals uploads to them.

### Local HTTPS

Release builds have no plain HTTP path; dev builds serve plain HTTP on `127.0.0.1:8443` unless `TRANSPORT=https`, also trust the last certificate a chain carries, so a local CA's chain serves, and `just dev-cert` is their certificate job, appending mkcert's root to each chain it writes.

`TRANSPORT=https just dev` writes a CSR for `API_HOSTNAME` to `data/tls/`; `just dev-cert` signs it with mkcert's local CA, and the worker picks up the chain within 10 seconds. Run `mkcert -install` once so browsers trust it.

## Calling the API

Dev builds accept tokens from the dev app registrations in Relational's tenant, and from the dev token signing key:

```bash
# A real token, as a user with the Admin role in the dev registration
TOKEN=$(az account get-access-token \
  --scope api://aa827d93-d487-40bf-8956-b6872ed55290/access_as_user \
  --query accessToken -o tsv)
# Or offline, signed with the dev key (also in the compose stack)
TOKEN=$(just dev-token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/v1/users/me
```

Dev builds also trust one more key, the dev token signing key `dev/keys/entra-signing-key.pem` (`just dev-keys` creates it), so tests, scripts and CI can call the API offline: `just dev-token` prints a token for it. Release builds contain none of this code and refuse `DEV_TOKEN_KEY`.

To act as an analyst, sign in once with an analyst's token, then grant them a pool's analysis as its owner, naming the rows they see:

```bash
ANALYST=$(just dev-token --roles '' --oid d0000000-0000-4000-8000-0000000000a1 --email analyst@relational.invalid)
ANALYST_ID=$(curl -s -H "Authorization: Bearer $ANALYST" http://127.0.0.1:8443/v1/users/me | jq -r .user_id)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" http://127.0.0.1:8443/v1/drt/pools/$POOL/grant \
  -d "{\"analyst_user_id\": \"$ANALYST_ID\", \"analysis_id\": \"awards-report-v1\", \"scope\": [{\"key\": \"employer_group\", \"value\": \"Group A\"}]}"
```

The grant burns one of the pool's Execute DRTs; from then on the analyst's queries see only Group A's rows.

## The fake SKR sidecar

Dev builds include `relational-tee fake-skr`, a stand-in for Microsoft's SKR sidecar. It serves `POST /key/release` and `POST /attest/maa` with the sidecar's request and response shapes, answering from the dev keys, so the production client code path runs unchanged. It signs attestation tokens RS256 with the dev MAA key, with MAA's claim names and a fixed dev host data value, and serves that key's public half at `GET /certs` (with `Access-Control-Allow-Origin: *`), as MAA does: a dashboard can use `http://localhost:9000` as its attestation authority. A key without a dev key file gets 403, like a release policy mismatch.

Microsoft's sidecar is reachable only from its own container group, but any user on a machine can reach a loopback port. So the fake's two `POST` routes answer only a request with `Authorization: Bearer` and the credential in `skr-token` beside the dev keys, which `just dev-keys` creates readable by its owner only; others get `401`. Dev workers send it from `DEV_SKR_TOKEN`, by default `skr-token` in `DEV_KEYS_DIR` when that file exists. `GET /certs` and `GET /status` stay open.

| Variable | Default | Purpose |
|---|---|---|
| `FAKE_SKR_ADDR` | `127.0.0.1:9000` | Listening address |
| `FAKE_MAA_ISSUER` | `http://localhost:{port}` | The tokens' `iss`, and where `/certs` is served |
| `FAKE_MAA_TOKEN_SECS` | `28800` (8 hours) | Token lifetime |
| `FAKE_MAA_DEBUGGABLE` | `off` | `on` makes tokens say the workload is debuggable, which clients must refuse |
| `DEV_KEYS_DIR` | `dev/keys` | Dev keys to release and sign with, and the credential callers must present (`skr-token`) |

## The dev manifest

Dev builds can sign a dev reference-values manifest with the dev manifest key `dev/keys/manifest-signing-key.jwk` (`just dev-keys` creates it), so a dashboard that pins that key verifies local workers as it verifies real ones. Release builds contain no signing code; their manifests come from CD.

`just dev-manifest` signs a reference-values manifest (ES256) with the dev manifest key and stores it as `reference-values/{ENVIRONMENT}/{sequence}.jws` and `latest.jws` in the storage the environment names (`STORAGE_BACKEND`, `DATA_DIR`; by default `./data/reference-values/dev/`), where dev workers pick it up within 10 seconds. It approves what dev workers present: the fake MAA's claim set (attestation type `sevsnpvm`, compliance status `azure-compliant-uvm`, not debuggable, VMPL 0, the fixed dev host data) with `FAKE_MAA_ISSUER` (default `http://localhost:9000`) as its authority, the dev transport key's thumbprint (and the previous version's, with `version` `previous`, if `transport-key.previous.jwk` exists), and the SHA-256 of the dev `tls-key`'s SPKI. It is valid for 30 days, its commit is the checkout's, and its sequence is the current Unix time, or one more than the latest manifest's, so a browser that remembers the highest sequence it saw keeps accepting new ones. It prints `VITE_MANIFEST_PUBLIC_KEY=…`, the public key a dashboard's dev build pins.

To run the dashboard's attestation checks against a local worker: `just skr` (it serves the fake MAA's keys at `http://localhost:9000/certs`), `just dev-manifest`, `just dev`, then `just spa` with `VITE_MANIFEST_PUBLIC_KEY` set to the printed key and `VITE_MAA_AUTHORITY=http://localhost:9000`. Sign a new manifest after 30 days, after deleting `./data`, or after changing the dev keys.

### Rehearsing a transport key rotation

To rehearse a transport key rotation: move `dev/keys/transport-key.jwk` to `transport-key.previous.jwk`, run `just dev-keys` (a new current version) and `just dev-manifest` (which lists both), and restart the worker; `GET /health` then shows both in `transport_kids`. To retire the previous version, delete `transport-key.previous.jwk` and run `just dev-manifest` again: workers stop opening uploads sealed to it at their next manifest check (within 5 minutes, or at once after a restart), and refuse them with `400 sealed_payload_invalid`.

## Fault injection

A dev worker started with `FAULT_INJECTION=on` honours an `X-Fault-Exit` request header naming a point in a request: `staged` (a pool creation, issuance or grant staged its saga, a grant's revocation was recorded, or a scope edit opened its idempotency record), `tx_stored` (a chain step stored its signed transaction), `tx_sent`, `tx_confirmed`, or `recorded` (the request's last document write is done, its response isn't stored). When the request reaches that point, the process exits at once with status 137, as if it had been killed. Release builds contain none of this and refuse `FAULT_INJECTION`.

`just faults` starts the local stack with `dev/compose.faults.yaml` layered on (fault injection on, and the reconciler running every 15 seconds for sagas older than 45 seconds), then runs `relational-tee faults` against the proxy. The suite calls the API as dev-token users, seals uploads to the stack's transport key, and crashes workers mid-request; compose restarts them, and the suite retries with the same `Idempotency-Key`. It checks that:
- a replay returns the stored response and creates nothing, and a reused key with another body gets `422`;
- two concurrent attempts with one key have one effect and one response;
- a worker killed after each step of an issuance or a pool creation, with the request retried on another, burns one DRT, adds one issuance entry, and leaves one pool document;
- a worker killed after each step of a grant burns one Execute DRT and leaves one active grant, and one killed after each step of its revocation burns nothing and leaves it revoked;
- after a crash between the burn and the pool document, with no retry, the reconciler adds the entry;
- two users with one key get different IDs;
- a scope edit killed after storing its anchor, with no retry, leaves the analyst with `503 pool_settling`, never the old rows, until a worker or the reconciler lands the pool's counter; the analyst then sees the new rows, the counter has risen by one, and a late retry of the edit mints nothing more;
- randomised runs across issue, pool creation, wallet creation, send, credential revocation, grants, scope edits and grant revocations, with duplicates, concurrent attempts and crashes, leave no double burn, double transfer, lost update, second wallet or undone revocation, and move a grant's scope revision by exactly one per edit.

A transfer whose transaction no node reports any more isn't in the suite, because devnet can't be made to forget one; the fake chain's unit tests cover it (`chain::tests::an_expired_transfer_that_no_node_reports_is_judged_by_its_receipt`).

Chain steps run on devnet, so the suite user's wallet in the stack needs about 0.2 devnet SOL; the suite stops at once and names the address if it holds less. Its pools take the Awards Report from a published commit on GitHub, with its URL and SHA-256 pinned together in `src/faults.rs`. The pair stays usable when the local definition moves or changes; update both together when adopting a newer published definition. The stack keeps its data in memory, so move any SOL left in that wallet elsewhere before `just stack-down`.

### Against a deployment

Release builds can't inject faults, so against a deployment the suite runs without kills. Set `FAULTS_API` to the deployment's API and `FAULTS_TOKEN` to an access token for it, from a user with the `Admin` role, and run `cargo run --features dev -- faults` (or the dev binary). The suite then acts as that user, with their wallet, which needs the same 0.2 devnet SOL. It runs the replays, the concurrent attempts, the reused key and the randomised runs without crashes, and skips what needs users made up on the spot (wallet creation, two users with one key). Grants go to `FAULTS_ANALYST_USER_ID`, a user the deployment already knows (the admin finds their `user_id` with `GET /v1/users?email=`); without it the randomised runs make no grants. A `429` from the deployment's per-address limit is waited out as its `Retry-After` asks. Entra access tokens last about an hour, which covers a 20-run pass.

## The load run

`just load` restarts the stack with `dev/compose.load.yaml` layered on, which holds the first worker to a deployed worker's 2 vCPU and 3 GiB (its memory budget is the default 2 GiB) and gives it a port of its own, `127.0.0.1:8444`. Every request reaches it from one address, which a deployment would rate-limit as a single client, so the overlay raises its per-address limits: the run loads the worker, not the limiter. Then `relational-tee load`, as the fault suite's user:
1. creates a pool, uploads `--rows` synthetic rows (100,000) spread over eight employer groups, and grants `--analysts` analysts (3) one group each, so each sees a table of their own;
2. for `--seconds` (120) runs, all at once, `--clients` clients (32) opening and querying the analysis as the admin or an analyst with random filters, sorts and pages; `--uploaders` clients (2) issuing `--upload-rows` rows (50,000) at a time, each of which makes every table build again; and a probe of `/health/ready` five times a second;
3. then, with the probe still running, opens `--slow` uploads (24) at once that each declare the largest body and send it a byte every half second, more than the memory budget holds, so those it can't hold must get `503 worker_busy`.

It prints each kind's outcomes, with one message of each refusal, and latency percentiles, and fails if a request got anything but an answer or a defined refusal (`503 worker_busy`, `analysis_busy`, `pool_settling` or `rpc_unavailable`, `422 too_large_for_memory`, `413 pool_full`, `409 conflict`, a `429`), if a health probe failed or its p99 passed a second, or if the overload got no `503 worker_busy`. The recipe samples the container's memory every second, prints the peak, and fails if the worker was killed for its memory or restarted. Its pool creation, grants and uploads run on devnet, so it needs the suite's wallet funded, as `just faults` does. A Mac's cores are faster than a deployment's, so the latencies flatter it; the memory and the refusals are what carry over.
