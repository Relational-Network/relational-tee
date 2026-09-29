# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Local development tasks. Run `nix develop` first for the pinned toolchain
# and tools, or use your own installs of the same versions.
#
# Not here yet, because what they drive doesn't exist yet: stack-up and
# stack-down (the container stack), faults (the idempotency fault-injection
# suite) and sandbox (a debug-mode confidential group on Azure).

set shell := ["bash", "-euo", "pipefail", "-c"]

# Dashboard checkout used by `just spa`.
pilot := env_var_or_default("IOB_PILOT_DIR", "../iob-pilot")

# Azurite, the local Azure Storage emulator, runs in Docker.
azurite_image := "mcr.microsoft.com/azure-storage/azurite:latest"
azurite_name := "relational-tee-azurite"

# Image builds run in a nixos/nix container, so no Linux builder is needed.
nix_image := "nixos/nix:latest"
nix_config := "experimental-features = nix-command flakes\nsandbox = false\nfilter-syscalls = false\nmax-jobs = auto"

# List the recipes.
default:
    @just --list

# Run the dev build natively on 127.0.0.1:8443 (HTTPS once `just cert` has run).
dev *args: dev-keys
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -f dev/certs/cert.pem && -f dev/certs/key.pem ]]; then
        export TLS_CERT_PATH="${TLS_CERT_PATH:-dev/certs/cert.pem}"
        export TLS_KEY_PATH="${TLS_KEY_PATH:-dev/certs/key.pem}"
    fi
    exec cargo run --features dev,swagger-ui -- {{ args }}

# Create any missing dev keys in dev/keys/; existing keys are kept.
dev-keys:
    cargo run --quiet --features dev -- dev-keys dev/keys

# Run the fake SKR sidecar on 127.0.0.1:9000 (use KEY_PROVIDER=skr in the worker).
skr: dev-keys
    cargo run --features dev -- fake-skr

# Create a locally trusted certificate for localhost with mkcert.
cert:
    mkdir -p dev/certs
    mkcert -install
    mkcert -cert-file dev/certs/cert.pem -key-file dev/certs/key.pem localhost 127.0.0.1 ::1

# Run the tests in the release and dev configurations.
test *args:
    cargo nextest run {{ args }}
    cargo nextest run --features dev {{ args }}

# Start Azurite (Blob on 127.0.0.1:10000, Table on :10002), keeping data in memory.
azurite:
    #!/usr/bin/env bash
    set -euo pipefail
    if docker container inspect {{ azurite_name }} >/dev/null 2>&1; then
        echo "{{ azurite_name }} is already running"
        exit 0
    fi
    docker run -d --rm --name {{ azurite_name }} \
        -p 127.0.0.1:10000:10000 -p 127.0.0.1:10002:10002 \
        {{ azurite_image }} \
        azurite --blobHost 0.0.0.0 --tableHost 0.0.0.0 --inMemoryPersistence --skipApiVersionCheck
    sleep 2

# Stop Azurite; its data goes with it.
azurite-stop:
    docker stop {{ azurite_name }}

# Run the storage tests against Azurite, starting it first if needed.
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

# Run the dashboard dev server (override the path with IOB_PILOT_DIR).
spa:
    cd {{ pilot }} && pnpm install --frozen-lockfile && pnpm dev

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
