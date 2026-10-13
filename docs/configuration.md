# Configuration

Dev builds are the ones with the `dev` Cargo feature (`just dev`, or `cargo run --features dev`).

## Environment variables

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
| `SOLANA_RPC_URL` | `https://api.devnet.solana.com`; `https://`, or `http://` on loopback | same, `https://` only | Solana RPC endpoint. Its answers decide whether a transaction is signed again and who owns a pool, so it is never read in the clear over a network |
| `SOLANA_NETWORK` | `devnet` | same | `devnet` or `mainnet`, for explorer links |
| `ENTRA_TENANT_ID` | the dev tenant `7e3e38e3-…` | required | The tenant whose tokens are accepted |
| `ENTRA_API_CLIENT_ID` | the dev API `aa827d93-…` | required | The API app registration: tokens' `aud` |
| `ENTRA_ALLOWED_CLIENT_IDS` | the dev dashboard `e2d026c4-…` and the Azure CLI | required; the Azure CLI is refused | Comma-separated client IDs allowed as `azp` |
| `DEV_TOKEN_KEY` | `{DEV_KEYS_DIR}/entra-signing-key.pem`, trusted if it exists | refused | The dev token signing key |
| `DEV_SKR_TOKEN` | `{DEV_KEYS_DIR}/skr-token`, sent if it exists | refused | The fake SKR sidecar's credential, for `KEY_PROVIDER=skr` (see [The fake SKR sidecar](development.md#the-fake-skr-sidecar)) |
| `DASHBOARD_ORIGIN` | `http://localhost:5173` (Vite) | required, `https://` | The one origin CORS allows |
| `RATE_LIMIT_IP_PER_SECOND`, `RATE_LIMIT_IP_BURST` | `20`, `40` | same | Requests per client IP, per worker |
| `RATE_LIMIT_USER_MUTATIONS_PER_SECOND` | `10` | same | POST, PUT, PATCH and DELETE requests per user, per worker |
| `MEMORY_BUDGET_MIB` | `2048` | set to about two thirds of the worker's memory limit; at least `512` | What uploads, decrypted datasets and analysis tables may hold at once (see [Request limits](api.md#request-limits)) |
| `RECONCILER_INTERVAL_SECS`, `RECONCILER_MIN_AGE_SECS` | `300`, `600` | refused | How often the reconciler runs, and how old a saga must be to finish |
| `FAULT_INJECTION` | `off` | refused | `on` honours `X-Fault-Exit` (see [Fault injection](development.md#fault-injection)) |
| `RUST_LOG` | `info` | `info` | Log filter |
| `LOG_FORMAT` | `text` | `json` | `json` writes one JSON object per line (see [Logs](api.md#logs)); `text` writes readable lines |

## What release builds refuse

Release builds refuse to start with any of:

- `KEY_PROVIDER=local`: keys come only from the SKR sidecar;
- a `STORAGE_BACKEND` other than `azure`;
- plain HTTP: `TRANSPORT=https` is the only transport;
- `DEV_TOKEN_KEY` or `DEV_SKR_TOKEN`;
- `FAULT_INJECTION`;
- `RECONCILER_INTERVAL_SECS` or `RECONCILER_MIN_AGE_SECS`.

They also leave out the code behind them: the dev key provider, dev token verification, the fake SKR sidecar, dev manifest signing, fault injection and Swagger UI.
