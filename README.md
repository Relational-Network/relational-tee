# relational-tee

A confidential worker for credential pools on Solana. It runs in Azure Confidential Containers (AMD SEV-SNP) as an Axum server, and serves an HTTPS API that:

- creates credential pools from an approved analysis, takes sealed CSV uploads, issues and revokes credentials, and keeps each pool's issuance log and audit trail;
- grants analysts an analysis of a pool's data, naming the rows each one sees, and runs it inside the worker;
- holds custodial Solana wallets: create, balance, fee estimate, send, history, and admin suspend and activate.

Its keys are released only to an attested worker, clients seal uploads to an attested key, and everything it stores is sealed inside it. Clients check each worker against a signed manifest of reference values, and [`deploy/`](deploy/) shows how anyone can check that a deployment runs this code.

Deployments differ in data, not in code. A deployment's analyses are definitions under [`drt-examples/`](drt-examples/), each holding a pool's columns, filters, row scope and SQL; its tenant and Azure resources are its own configuration, and which rows each analyst sees is set on their grant. A new use case is a new definition; the worker changes only when a definition needs something the format can't express yet.

## Status

Every commit to `main` that changes more than documentation is published as a reproducible image. Analysis requests and responses travel over the worker's TLS like the rest of the API, but aren't yet sealed end to end.

## Quick start

You need [Nix](https://nixos.org) with flakes, and Docker for the image builds and the local stack.

```bash
nix develop     # pinned Rust and every tool the recipes use
just dev        # the dev build on http://127.0.0.1:8443, Swagger UI at /docs
just test       # the tests, in the release and dev configurations
just check      # every gate CI runs
just            # list every recipe
```

The dev build uses dev keys and sealed local files under `./data`, and accepts tokens signed with a local dev key:

```bash
TOKEN=$(just dev-token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/v1/users/me
```

[docs/development.md](docs/development.md) covers the rest: the fake SKR sidecar, Azurite, the three-worker stack, the dev manifest and fault injection.

## Documentation

| Document | Contents |
|---|---|
| [docs/development.md](docs/development.md) | Recipes, running locally, calling the API, the fake SKR sidecar, the dev manifest, fault injection |
| [docs/configuration.md](docs/configuration.md) | Environment variables, and how dev and release builds differ |
| [docs/architecture.md](docs/architecture.md) | Keys, TLS, authentication, grant commitments, sealed storage, the reconciler, health and shutdown |
| [docs/api.md](docs/api.md) | API conventions (errors, idempotency, sealed uploads, limits, logs, audit events) and the endpoints |
| [docs/analyses.md](docs/analyses.md) | How analyses are granted, checked against the chain and run |
| [docs/build-and-release.md](docs/build-and-release.md) | The Nix build, the image, CI and publishing |
| [deploy/README.md](deploy/README.md) | The measured container group profile, the manifest schema, and checking a deployment |
| [drt-examples/README.md](drt-examples/README.md) | The analysis definition format, and adding an analysis |

Dev builds serve the OpenAPI document at `/api-doc/openapi.json`, `just openapi` prints it, and CI publishes it as each run's `openapi` artifact.

## Repository layout

```
src/            the worker; `relational-tee openapi` prints the API document, and dev builds
                add `fake-skr`, `faults` and the dev key, token and manifest tools
drt-examples/   approved analysis definitions, with synthetic fixtures
deploy/         the measured container group profile and the manifest schema
dev/            the local stack's fault-injection overlay and HAProxy configuration
idl/            the DRT program's IDL, which tests hold the instruction builders to
compose.yaml    the local three-worker stack
flake.nix       the toolchain, the dev shell, the release binary and the image
justfile        every recipe
```

## Contributing

- Commits follow [Conventional Commits](https://www.conventionalcommits.org/), and changes land through pull requests that keep `just check` green.
- The worker never depends on the `rsa` crate (RUSTSEC-2023-0071) or on OpenSSL, in any configuration; CI fails if either enters the dependency graph. RSA signing exists only in dev-only code, through `aws-lc-rs`.
- Never print, log or commit a real token.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
