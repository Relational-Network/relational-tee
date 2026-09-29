#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Build a deterministic, signed SGX Docker image for relational-sdk.
#
# Usage:
#   ./build.sh ubuntu20
#   SGX_SIGNING_KEY=/path/to/key.pem ./build.sh ubuntu20
#   UBUNTU_SNAPSHOT=20260210T000000Z ./build.sh ubuntu20
#
# The signing key is injected as a BuildKit --secret and is NEVER stored in any
# image layer. The resulting image has a deterministic MRENCLAVE that can be
# verified with `make verify-mrenclave`.

set -euo pipefail

usage() {
    echo "Usage: build.sh ubuntu20"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

codename=""

case "$1" in
    ubuntu20)
        codename="focal"
        ;;
    *)
        usage
        ;;
esac

# Resolve signing key. Default to $HOME/.config/gramine/enclave-key.pem. When
# running under sudo, $HOME is /root — fall back to SUDO_USER's home so the
# user's existing key is picked up automatically.
if [ -z "${SGX_SIGNING_KEY:-}" ]; then
    if [ -n "${SUDO_USER:-}" ]; then
        _home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
    else
        _home="${HOME}"
    fi
    SGX_KEY="${_home}/.config/gramine/enclave-key.pem"
else
    SGX_KEY="${SGX_SIGNING_KEY}"
fi

if [ ! -f "${SGX_KEY}" ]; then
    echo "error: SGX signing key not found at ${SGX_KEY}" >&2
    echo "Generate one with: gramine-sgx-gen-private-key" >&2
    echo "Or set SGX_SIGNING_KEY=/path/to/key" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

echo "Using SGX signing key: ${SGX_KEY}"
echo "MRENCLAVE and MRSIGNER will be baked into the image."
echo "Building for platform: linux/amd64"
if [ -n "${UBUNTU_SNAPSHOT:-}" ]; then
    echo "Using Ubuntu snapshot: ${UBUNTU_SNAPSHOT}"
fi

extra_build_args=()
if [ -n "${UBUNTU_SNAPSHOT:-}" ]; then
    extra_build_args+=(--build-arg "UBUNTU_SNAPSHOT=${UBUNTU_SNAPSHOT}")
fi

DOCKER_BUILDKIT=1 docker build \
    --platform linux/amd64 \
    --build-arg UBUNTU_CODENAME="${codename}" \
    "${extra_build_args[@]}" \
    --secret id=sgx-key,src="${SGX_KEY}" \
    -t relationalnetwork/relational-sdk:"${codename}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${PROJECT_DIR}"
