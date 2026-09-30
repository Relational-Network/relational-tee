# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Local development tasks. Run `nix develop` first for the pinned toolchain
# and tools, or use your own installs of the same versions.
#
# Not here yet, because what it drives doesn't exist yet: sandbox (a
# debug-mode confidential group on Azure).

set shell := ["bash", "-euo", "pipefail", "-c"]

# Dashboard checkout used by `just spa`.
pilot := env_var_or_default("IOB_PILOT_DIR", "../iob-pilot")

# Azurite, the local Azure Storage emulator (its Blob service), runs in Docker.
azurite_image := "mcr.microsoft.com/azure-storage/azurite:latest"
azurite_name := "relational-tee-azurite"

# Image builds run in a nixos/nix container, so no Linux builder is needed.
nix_image := "nixos/nix:latest"
nix_config := "experimental-features = nix-command flakes\nsandbox = false\nfilter-syscalls = false\nmax-jobs = auto"

# List the recipes.
default:
    @just --list

# Run the dev build natively on 127.0.0.1:8443: plain HTTP, or with
# TRANSPORT=https, tls-key once `just dev-cert` has signed its CSR.
[positional-arguments]
dev *args: dev-keys
    cargo run --features dev,swagger-ui -- "$@"

# Create any missing dev keys in dev/keys/; existing keys are kept.
dev-keys:
    cargo run --quiet --features dev -- dev-keys dev/keys

# Print a token signed with the dev token signing key, which dev builds trust
# (`just dev-token --help` lists the options, including deliberately bad tokens).
[positional-arguments]
dev-token *args:
    @cargo run --quiet --features dev -- dev-keys dev/keys >&2
    @cargo run --quiet --features dev -- dev-token "$@"

# Sign a dev reference-values manifest that approves the dev keys and the fake
# MAA, store it where dev workers serve it, and print the public key a
# dashboard pins (`just dev-manifest --help` lists the options, including
# deliberately bad manifests).
[positional-arguments]
dev-manifest *args:
    @cargo run --quiet --features dev -- dev-keys dev/keys >&2
    @cargo run --quiet --features dev -- dev-manifest --commit "$(git rev-parse HEAD 2>/dev/null || echo dev)" "$@"

# Run the fake SKR sidecar on 127.0.0.1:9000 (use KEY_PROVIDER=skr in the worker).
skr: dev-keys
    cargo run --features dev -- fake-skr

# The local certificate job: sign each CSR in the files store's tls
# container that has no chain yet with mkcert's local CA, writing chain.pem
# beside it. The worker picks the chain up within 10 seconds. Run
# `mkcert -install` once so browsers trust the CA.
dev-cert:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="${DATA_DIR:-./data}/tls"
    shopt -s nullglob
    signed=0
    for csr in "$dir"/*/csr.pem; do
        chain="$(dirname "$csr")/chain.pem"
        [[ -e "$chain" ]] && continue
        mkcert -csr "$csr" -cert-file "$chain.tmp"
        mv "$chain.tmp" "$chain"
        signed=$((signed + 1))
    done
    echo "Signed $signed CSR(s) in $dir"

# Run the tests in the release and dev configurations.
test *args:
    cargo nextest run {{ args }}
    cargo nextest run --features dev {{ args }}

# Start Azurite's Blob service on 127.0.0.1:10000, keeping data in memory.
azurite:
    #!/usr/bin/env bash
    set -euo pipefail
    if docker container inspect {{ azurite_name }} >/dev/null 2>&1; then
        echo "{{ azurite_name }} is already running"
        exit 0
    fi
    docker run -d --rm --name {{ azurite_name }} \
        -p 127.0.0.1:10000:10000 \
        {{ azurite_image }} \
        azurite-blob --blobHost 0.0.0.0 --inMemoryPersistence --skipApiVersionCheck
    sleep 2

# Stop Azurite; its data goes with it.
azurite-stop:
    docker stop {{ azurite_name }}

# Run the store conformance tests against Azurite, starting it first if needed.
test-azurite: azurite
    cargo nextest run --features dev --run-ignored only -E 'test(azurite)'

# Run every local gate.
check: fmt-check clippy test deny-crates audit

# Fail if the code isn't formatted.
fmt-check:
    cargo fmt --check

# Lint with all features and in the release configuration.
clippy:
    cargo clippy --all-targets --all-features -- -D warnings
    cargo clippy --all-targets -- -D warnings

# Fail if the rsa crate (RUSTSEC-2023-0071) or OpenSSL is in the dependency graph.
deny-crates:
    #!/usr/bin/env bash
    set -euo pipefail
    status=0
    for crate in rsa openssl-sys; do
        if cargo tree --locked --target all -e all -i "$crate" >/dev/null 2>&1; then
            echo "error: $crate is in the dependency graph:"
            cargo tree --locked --target all -e all -i "$crate"
            status=1
        fi
    done
    exit "$status"

# Check dependencies against the RustSec advisory database.
audit:
    cargo audit

# Print the OpenAPI document, which CI publishes; only builds with the
# swagger-ui feature (`just dev`) serve it, at /api-doc/openapi.json.
openapi:
    @cargo run --quiet -- openapi

# Run the dashboard dev server (override the path with IOB_PILOT_DIR).
spa:
    cd {{ pilot }} && pnpm install --frozen-lockfile && pnpm dev

# Start the local stack: Azurite, the fake SKR sidecar, three workers and a
# round-robin proxy on 127.0.0.1:8443, then sign a dev reference-values
# manifest into its storage. Needs `just image-dev` first.
stack-up: dev-keys
    #!/usr/bin/env bash
    set -euo pipefail
    export STACK_UID=$(id -u) STACK_GID=$(id -g) STACK_COMMIT=$(git rev-parse HEAD)
    docker compose up -d --wait
    # Azurite can take a moment to listen after it starts.
    for attempt in 1 2 3 4 5; do
        docker compose run --rm manifest && break
        [[ $attempt == 5 ]] && { echo "error: couldn't sign the stack's manifest" >&2; exit 1; }
        sleep 2
    done
    echo "workers: http://127.0.0.1:8443 (round robin)  fake SKR and MAA keys: http://127.0.0.1:9000"

# Stop the local stack; its data is in memory and goes with it.
stack-down:
    docker compose down

# Run the idempotency fault-injection suite against the local stack, which
# it (re)starts with fault injection on and a fast reconciler. Needs
# `just image-dev` first, and devnet SOL in the suite's wallet: the suite
# names the address if it has too little. `--runs N` sets the randomised
# runs (default 20).
[positional-arguments]
faults *args: dev-keys
    STACK_UID=$(id -u) STACK_GID=$(id -g) docker compose -f compose.yaml -f dev/compose.faults.yaml up -d --wait
    cargo run --features dev -- faults "$@"

# Build the canonical x86_64-linux image and load it into Docker.
image: (_nix-image "linux/amd64" "x86_64-linux" "image")

# Build the aarch64-linux dev image and load it into Docker.
image-dev: (_nix-image "linux/arm64" "aarch64-linux" "image-dev")

_nix-image platform system output:
    docker run --rm --platform {{ platform }} \
        -v relational-tee-nix-{{ system }}:/nix \
        -v "$PWD":/src:ro -w /src \
        -e NIX_CONFIG=$'{{ nix_config }}' \
        {{ nix_image }} \
        sh -c 'git config --global --add safe.directory /src && cat "$(nix build --no-link --print-out-paths .#packages.{{ system }}.{{ output }})"' \
        | docker load
