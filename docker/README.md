# relational-sdk — SGX Docker image

Reproducible Gramine + DCAP RA-TLS image for the relational-sdk enclave. Built and signed in CI; published to `ghcr.io/relational-network/relational-sdk:staging-latest` (and `:sha-<commit>`) with `MRENCLAVE` pinned in [`../measurements.toml`](../measurements.toml).

## Run (production)

The enclave runs under systemd on the staging VM via the deployment scripts in [`../scripts/`](../scripts/) ([STAGING-DEPLOYMENT.md](../../STAGING-DEPLOYMENT.md)). The raw `docker run` form is:

```bash
docker run --rm \
  --network host \
  --device /dev/sgx/enclave \
  --device /dev/sgx/provision \
  -v /var/lib/iob-micres/data:/data \
  -v /opt/iob-micres/secrets/avs-tls.crt:/etc/ssl/certs/avs-ca.crt:ro \
  -e AVS_JWKS_URL=http://127.0.0.1:9100/.well-known/jwks.json \
  -e SECRET_PROVISION_SERVERS=127.0.0.1:4433 \
  ghcr.io/relational-network/relational-sdk:staging-latest
```

The container starts as root only long enough to wire AESM and SGX device groups, then drops to UID/GID `10001` (`relational`) before launching `gramine-sgx`. Pre-create the data directory with that ownership:

```bash
sudo install -d -m 0750 -o 10001 -g 10001 /var/lib/iob-micres/data
```

(If the bind mount lands as `root:root` the entrypoint auto-`chown`s it to `10001:10001`; explicit creation just avoids one warning on first boot.)

The signing key is **not** required at runtime — it is consumed at Docker build time only.

## Build (locally)

Defaults to the host signing key at `$HOME/.config/gramine/enclave-key.pem` (generate with `gramine-sgx-gen-private-key` if missing). From the SDK root:

```bash
make docker-build                              # uses default key
SGX_SIGNING_KEY=/path/to/prod.pem make docker-build
```

Or directly:

```bash
cd docker
sudo SGX_SIGNING_KEY=/path/to/key.pem ./build.sh ubuntu20
```

Build context is `relational-sdk/`; see [`../.dockerignore`](../.dockerignore).

## Reproducibility

`MRSIGNER` is determined by the RSA-3072 signing key. `MRENCLAVE` is determined by binary + manifest + trusted files; the Dockerfile pins everything that affects it:

- Rust toolchain (`RUST_TOOLCHAIN`, matches `rust-toolchain.toml`)
- rustup installer (`RUSTUP_VERSION` + `RUSTUP_SHA256`, versioned `static.rust-lang.org/rustup/archive/` URL)
- Gramine + SGX AESM packages (`GRAMINE_VERSION`, `SGX_AESM_VERSION`, `SGX_DCAP_QV_VERSION`, `AZ_DCAP_VERSION`)
- GPG keyrings (`GRAMINE_KEYRING_SHA256`, `INTEL_SGX_DEB_SHA256`, `MICROSOFT_ASC_SHA256`)
- Ubuntu base image SHA256 + apt snapshot (`UBUNTU_SNAPSHOT`)
- Build platform (`linux/amd64`, enforced in `build.sh` and the Dockerfile)
- Rust reproducibility env (`SOURCE_DATE_EPOCH`, fixed `RUSTFLAGS` with `codegen-units=1`, `build-id=none`, `rng-seed=0`, `remap-path-prefix`)
- `CFLAGS`/`CXXFLAGS` redact `__DATE__`/`__TIME__`/`__TIMESTAMP__`
- Runtime UID/GID (`10001:10001`)
- SIGSTRUCT date (`--date 0000-00-00` to `gramine-sgx-sign`)
- `sgx.debug = false` hardcoded in [`relational-sdk.manifest.template`](relational-sdk.manifest.template)
- `sgx.trusted_files` rewritten to an `LC_ALL=C sort -u` list (no filesystem-order nondeterminism)
- DNS + CA bundle baked into `/app/dns/*` and `/app/ca-certificates.crt` as trusted files (host cannot substitute them at runtime)

Override the apt snapshot if needed:

```bash
UBUNTU_SNAPSHOT=20260210T000000Z make docker-build
```

## Verification

Inspect a built image's measurements:

```bash
make docker-sigstruct      # prints [enclave] block in measurements.toml field order
make verify-mrenclave      # rebuilds --no-cache and diffs against measurements.toml
```

CI ([`../.github/workflows/ci.yml`](../.github/workflows/ci.yml)) does the same on every push: builds with the `ENCLAVE_SIGNING_KEY` secret, asserts `debug_enclave = False`, `isv_prod_id = 0`, `isv_svn = 0`, and fails if `mr_enclave` drifts from `measurements.toml`. Pushes to `staging` publish the image; PRs verify only.

To roll a new release:

1. `make docker-build && make docker-sigstruct`
2. Copy the printed `[enclave]` block into [`../measurements.toml`](../measurements.toml) **in the same PR** as the source change.
3. Merge — CI re-verifies and pushes the image.

Deploy by digest, not tag, when pinning a release:

```bash
ENCLAVE_IMAGE=ghcr.io/relational-network/relational-sdk@sha256:<digest> \
  sudo systemctl restart enclave
```

CI prints the `Deploy:` line for each successful staging build in the workflow run summary.

---

SPDX-License-Identifier: AGPL-3.0-or-later · Copyright (C) 2026 Relational Network
