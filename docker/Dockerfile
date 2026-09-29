# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# SGX-only Docker image for relational-sdk with DCAP RA-TLS attestation.
#
# Deterministic build: the enclave is signed at BUILD TIME so MRENCLAVE and
# MRSIGNER are baked into the image and never change at runtime. The signing
# key is NOT needed to run the container.
#
# Everything that affects MRENCLAVE is pinned for reproducibility:
#   - Ubuntu base image pinned to SHA256 digest
#   - Ubuntu apt snapshot frozen via snapshot.ubuntu.com
#   - Rust toolchain pinned to exact version (matches rust-toolchain.toml)
#   - rustup pinned to exact version + SHA256 of installer
#   - Gramine + SGX + Azure DCAP packages pinned to exact versions
#   - GPG keyrings pinned to SHA256
#   - Cargo profile pinned (codegen-units=1, no debug info, stripped)
#   - RUSTFLAGS pinned (rng-seed=0, build-id=none, remap-path-prefix)
#   - SOURCE_DATE_EPOCH and TZ pinned
#   - sgx.trusted_files rewritten to LC_ALL=C sorted explicit list
#   - --date 0000-00-00 to gramine-sgx-sign

ARG UBUNTU_IMAGE=ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214
ARG UBUNTU_SNAPSHOT=20260210T000000Z
ARG CA_CERTS_VERSION=20240203~20.04.1

# ---------------------------------------------------------------------------
# Stage 1 — Rust build (pinned toolchain for reproducibility)
# ---------------------------------------------------------------------------
# hadolint ignore=DL3006
FROM ${UBUNTU_IMAGE} AS builder
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG UBUNTU_SNAPSHOT
ARG CA_CERTS_VERSION
ARG TARGETPLATFORM

RUN test "${TARGETPLATFORM}" = "linux/amd64" || \
    (echo "error: SGX image must be built for linux/amd64 (got ${TARGETPLATFORM})" >&2; exit 1)

# Install CA roots before switching to snapshot mirrors (which redirect to HTTPS).
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates=${CA_CERTS_VERSION} && \
    rm -rf /var/lib/apt/lists/*

# Freeze Ubuntu package resolution to a timestamped snapshot so transitive
# dependency versions cannot drift over time. If snapshot.ubuntu.com is
# unavailable we fall back to the standard archive; exact version pins in
# every apt-get install still guarantee reproducibility.
RUN printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99ubuntu-snapshot && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" > /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal-updates main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" >> /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal-security main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" >> /etc/apt/sources.list && \
    if ! apt-get update 2>/dev/null; then \
      echo "WARNING: snapshot.ubuntu.com unavailable — using archive.ubuntu.com" >&2; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse\n'        > /etc/apt/sources.list; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse\n' >> /etc/apt/sources.list; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse\n' >> /etc/apt/sources.list; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# Pin all builder packages for reproducibility.
# To update: run the base image and check apt-cache policy <pkg>
ARG BUILD_ESSENTIAL_VERSION=12.8ubuntu1.1
ARG CLANG_VERSION=1:10.0-50~exp1
ARG CURL_VERSION=7.68.0-1ubuntu2.25
ARG PKG_CONFIG_VERSION=0.29.1-0ubuntu4
ARG LIBSSL_DEV_VERSION=1.1.1f-1ubuntu2.24

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl=${CURL_VERSION} \
    ca-certificates=${CA_CERTS_VERSION} \
    build-essential=${BUILD_ESSENTIAL_VERSION} \
    clang=${CLANG_VERSION} \
    pkg-config=${PKG_CONFIG_VERSION} \
    libssl-dev=${LIBSSL_DEV_VERSION} && \
    rm -rf /var/lib/apt/lists/*

# Pin the exact Rust toolchain so MRENCLAVE is reproducible.
# Update this version deliberately — never use "stable". Must match rust-toolchain.toml.
ARG RUST_TOOLCHAIN=1.92.0

# Pin rustup by VERSION + SHA256 using a versioned, immutable URL.
# The /archive/ URL is stable across rustup releases; sh.rustup.rs is not.
# To update:
#   RUSTUP_VERSION=1.29.0
#   curl -sSf "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
#     -o /tmp/rustup-init && sha256sum /tmp/rustup-init
ARG RUSTUP_VERSION=1.29.0
ARG RUSTUP_SHA256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10

ENV CARGO_HOME=/opt/cargo
ENV RUSTUP_HOME=/opt/rustup
ENV PATH=/opt/cargo/bin:${PATH}
# Repo .cargo/config.toml sets rustc-wrapper = "sccache"; unset for Docker
# builds (sccache not installed; cache is not what we want for reproducibility).
ENV RUSTC_WRAPPER=
ENV SOURCE_DATE_EPOCH=1704067200
ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
# Reproducibility envs:
#   CARGO_INCREMENTAL=0           — incremental builds embed timestamps/hashes that drift
#   CODEGEN_UNITS=1               — required: parallel codegen *within* a crate is non-deterministic
#   ZERO_AR_DATE=1                — strip mtimes from ar archives
#
# We do NOT pin CARGO_BUILD_JOBS. Cargo builds *separate crates* in parallel,
# but each crate's output is fully determined by codegen-units=1, the fixed
# RUSTFLAGS below (rng-seed, remap-path-prefix, no build-id), and the locked
# Cargo.lock. Parallel jobs therefore produce byte-identical binaries.
ENV CARGO_INCREMENTAL=0
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
ENV CARGO_PROFILE_RELEASE_DEBUG=0
ENV CARGO_PROFILE_RELEASE_STRIP=symbols
ENV ZERO_AR_DATE=1
# RUSTFLAGS env wins over target.<triple>.rustflags from .cargo/config.toml,
# so the host's `link-arg=-fuse-ld=lld` setting is dropped (no lld in image).
# `--cfg rustix_use_libc` is also mirrored here (not just in .cargo/config.toml)
# precisely because this env replaces the config-file flags: it forces rustix
# (via wasmtime) onto its libc backend so DRT-execution syscalls go through
# Gramine's patched glibc instead of raw SYSCALL emulation. See the matching
# note in .cargo/config.toml.
ENV RUSTFLAGS="-Ccodegen-units=1 -Cdebuginfo=0 -Cstrip=symbols -Clink-arg=-Wl,--build-id=none -Cllvm-args=-rng-seed=0 --remap-path-prefix=/build=. --cfg rustix_use_libc"
ENV CFLAGS="-g0 -frandom-seed=relational-sdk -Wno-builtin-macro-redefined -D__DATE__=\"redacted\" -D__TIME__=\"redacted\" -D__TIMESTAMP__=\"redacted\""
ENV CXXFLAGS="-g0 -frandom-seed=relational-sdk -Wno-builtin-macro-redefined -D__DATE__=\"redacted\" -D__TIME__=\"redacted\" -D__TIMESTAMP__=\"redacted\""

RUN curl -sSf "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
        -o /tmp/rustup-init && \
    echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - && \
    chmod +x /tmp/rustup-init && \
    /tmp/rustup-init -y --profile minimal --default-toolchain ${RUST_TOOLCHAIN} && \
    rm /tmp/rustup-init

WORKDIR /build

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY src ./src
RUN cargo fetch --locked && \
    CARGO_NET_OFFLINE=true cargo build --release --locked

# ---------------------------------------------------------------------------
# Stage 2 — Signer image
# ---------------------------------------------------------------------------
# This stage carries the extra tooling needed to configure apt repos, generate
# the manifest, and sign the enclave. The final runtime image starts from a
# fresh Ubuntu base so curl/gnupg2/binutils do not ship in production.
# ---------------------------------------------------------------------------
ARG UBUNTU_CODENAME=focal

# hadolint ignore=DL3006
FROM ${UBUNTU_IMAGE} AS signer
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG UBUNTU_CODENAME=focal
ARG UBUNTU_SNAPSHOT
ARG CA_CERTS_VERSION
ARG TARGETPLATFORM
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV TZ=UTC
ENV PYTHONHASHSEED=0

RUN test "${TARGETPLATFORM}" = "linux/amd64" || \
    (echo "error: SGX image must be built for linux/amd64 (got ${TARGETPLATFORM})" >&2; exit 1)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates=${CA_CERTS_VERSION} && \
    rm -rf /var/lib/apt/lists/*

RUN printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99ubuntu-snapshot && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" > /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal-updates main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" >> /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal-security main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" >> /etc/apt/sources.list && \
    if ! apt-get update 2>/dev/null; then \
      echo "WARNING: snapshot.ubuntu.com unavailable — using archive.ubuntu.com" >&2; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse\n'        > /etc/apt/sources.list; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse\n' >> /etc/apt/sources.list; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse\n' >> /etc/apt/sources.list; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# Pin build/sign utility packages.
ARG RT_CURL_VERSION=7.68.0-1ubuntu2.25
ARG GNUPG2_VERSION=2.2.19-3ubuntu2.5
ARG BINUTILS_VERSION=2.34-6ubuntu1.11

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl=${RT_CURL_VERSION} \
    gnupg2=${GNUPG2_VERSION} \
    binutils=${BINUTILS_VERSION} && \
    rm -rf /var/lib/apt/lists/*

# Pin GPG keyrings by SHA256 so builds don't break on key rotation
# and we verify we're trusting the same keys every time.
# To update: download the file and sha256sum it.
ARG GRAMINE_KEYRING_SHA256=29c8a028a14f11e3ac3f2ca2669d6ef717656e64d375cd74617319a75db94f13
ARG INTEL_SGX_DEB_SHA256=92f96f84281031d889deb81060c44325f0481aee621ae47a15ae1df4431b4a23
ARG MICROSOFT_ASC_SHA256=2fa9c05d591a1582a9aba276272478c262e95ad00acf60eaee1644d93941e3c6

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring-${UBUNTU_CODENAME}.gpg && \
    echo "${GRAMINE_KEYRING_SHA256}  /usr/share/keyrings/gramine-keyring.gpg" | sha256sum -c - && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ '${UBUNTU_CODENAME}' main' > /etc/apt/sources.list.d/gramine.list

RUN curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo "${INTEL_SGX_DEB_SHA256}  /usr/share/keyrings/intel-sgx-deb.key" | sha256sum -c - && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] https://download.01.org/intel-sgx/sgx_repo/ubuntu '${UBUNTU_CODENAME}' main' > /etc/apt/sources.list.d/intel-sgx.list

RUN curl -fsSLo /tmp/microsoft.asc https://packages.microsoft.com/keys/microsoft.asc && \
    echo "${MICROSOFT_ASC_SHA256}  /tmp/microsoft.asc" | sha256sum -c - && \
    gpg --dearmor /tmp/microsoft.asc && \
    mv /tmp/microsoft.asc.gpg /usr/share/keyrings/microsoft-prod.gpg && \
    rm -f /tmp/microsoft.asc && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/20.04/prod focal main' > /etc/apt/sources.list.d/microsoft-prod.list

# Pin Gramine + SGX package versions for reproducible MRENCLAVE.
# Bump these deliberately when upgrading.
# Query current versions: dpkg-query -W -f '${Package}=${Version}\n' gramine sgx-aesm-service
ARG GRAMINE_VERSION=1.8
ARG SGX_AESM_VERSION=2.25.100.3-focal1
ARG SGX_DCAP_QV_VERSION=1.22.100.3-focal1
ARG AZ_DCAP_VERSION=1.12.3
ARG PSMISC_VERSION=23.3-1

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gramine=${GRAMINE_VERSION} \
    gramine-ratls-dcap=${GRAMINE_VERSION} \
    sgx-aesm-service=${SGX_AESM_VERSION} \
    libsgx-aesm-launch-plugin=${SGX_AESM_VERSION} \
    libsgx-aesm-quote-ex-plugin=${SGX_AESM_VERSION} \
    libsgx-aesm-ecdsa-plugin=${SGX_AESM_VERSION} \
    libsgx-dcap-quote-verify=${SGX_DCAP_QV_VERSION} \
    az-dcap-client=${AZ_DCAP_VERSION} \
    psmisc=${PSMISC_VERSION} && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# az-dcap-client installs libdcap_quoteprov.so at /usr/lib, which the Gramine
# enclave cannot see (only /lib and /lib/x86_64-linux-gnu are mounted).
# The in-enclave QVL dlopens libdcap_quoteprov.so.1 then libdcap_quoteprov.so;
# place both in arch_libdir so it resolves via LD_LIBRARY_PATH and is measured
# into MRENCLAVE by the trusted_files sort below.
RUN cp /usr/lib/libdcap_quoteprov.so /lib/x86_64-linux-gnu/libdcap_quoteprov.so && \
    ln -s libdcap_quoteprov.so /lib/x86_64-linux-gnu/libdcap_quoteprov.so.1

WORKDIR /app

COPY --from=builder /build/target/release/relational-sdk /app/relational-sdk
COPY docker/relational-sdk.manifest.template /app/relational-sdk.manifest.template

# Static DNS config baked into the image as trusted_files. Public resolvers
# because Docker's internal 127.0.0.11 DNS is a userspace proxy that is NOT
# reachable from inside the Gramine SGX enclave.
RUN mkdir -p /app/dns && \
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions ndots:0\n' > /app/dns/resolv.conf && \
    printf '127.0.0.1 localhost\n' > /app/dns/hosts && \
    printf 'hosts: files dns\n' > /app/dns/nsswitch.conf

# Pin the system CA bundle into /app so libcurl inside the enclave (used by
# libdcap_quoteprov.so to fetch PCK collateral from Azure PCS over HTTPS) can
# verify server certificates. Without this, DCAP quote verification returns
# SGX_QL_NETWORK_ERROR (0xE019) because the TLS handshake fails.
RUN cp /etc/ssl/certs/ca-certificates.crt /app/ca-certificates.crt

# AVS RA-TLS trust anchor for libsecret_prov_attest.so. Must be present in the
# build context as avs-ca.crt (the Makefile docker-build target copies it from
# ../attestation-verification-service/secrets/avs-tls.crt). Measured into
# MRENCLAVE via sgx.trusted_files; rotating the AVS cert requires a rebuild.
COPY avs-ca.crt /app/avs-ca.crt

# Generate the Gramine manifest and rewrite sgx.trusted_files as an explicit
# sorted list to avoid nondeterminism from recursive directory traversal order.
RUN ENTRYPOINT=$(command -v gramine-ratls) && \
    gramine-manifest \
    -Dentrypoint="${ENTRYPOINT}" \
    -Dlog_level=error \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    -Dapp_dir=/app \
    -Dself_exe=/app/relational-sdk \
    -Dra_type=dcap \
    -Ddata_dir=/data \
    -Disvprodid=0 \
    -Disvsvn=0 \
    /app/relational-sdk.manifest.template /app/relational-sdk.manifest && \
    GRAMINE_RUNTIME_DIR=$(gramine-runtimedir 2>/dev/null || echo /usr/lib/x86_64-linux-gnu/gramine/runtime/glibc) && \
    { \
      echo 'sgx.trusted_files = ['; \
      echo '    "file:/app/relational-sdk",'; \
      echo "    \"file:${ENTRYPOINT}\","; \
      echo '    "file:/app/dns/resolv.conf",'; \
      echo '    "file:/app/dns/hosts",'; \
      echo '    "file:/app/dns/nsswitch.conf",'; \
      echo '    "file:/app/ca-certificates.crt",'; \
      echo '    "file:/app/avs-ca.crt",'; \
      find "${GRAMINE_RUNTIME_DIR}" /lib/x86_64-linux-gnu \
        -mindepth 1 \( -type f -o -type l \) -printf '%p\n' \
        | LC_ALL=C sort -u \
        | sed 's#^#    "file:#; s#$#",#'; \
      echo ']'; \
    } > /tmp/trusted_files.toml && \
    awk ' \
      BEGIN { in_block=0; replaced=0 } \
      /^sgx\.trusted_files[[:space:]]*=[[:space:]]*\[/ { \
        if (!replaced) { \
          while ((getline line < "/tmp/trusted_files.toml") > 0) print line; \
          close("/tmp/trusted_files.toml"); \
          replaced=1; \
        } \
        in_block=1; \
        next; \
      } \
      in_block && /^\]/ { in_block=0; next } \
      !in_block { print } \
    ' /app/relational-sdk.manifest > /app/relational-sdk.manifest.det && \
    mv /app/relational-sdk.manifest.det /app/relational-sdk.manifest && \
    rm -f /tmp/trusted_files.toml

# ---------- SIGN THE ENCLAVE AT BUILD TIME ----------
# The signing key is injected via Docker build secret so it never ends up in a
# layer. This produces relational-sdk.manifest.sgx and relational-sdk.sig which
# lock MRENCLAVE and MRSIGNER into the image.
#
# Usage:  docker build --secret id=sgx-key,src=/path/to/enclave-key.pem ...
RUN --mount=type=secret,id=sgx-key,required=true \
    gramine-sgx-sign \
        --manifest /app/relational-sdk.manifest \
        --output /app/relational-sdk.manifest.sgx \
        --key /run/secrets/sgx-key \
        --date 0000-00-00

# ---------------------------------------------------------------------------
# Stage 3 — Runtime image
# ---------------------------------------------------------------------------
# Start from a fresh Ubuntu base and install only the packages needed to run
# the signed enclave. Keyrings and repo definitions are copied from the signer
# stage so curl/gnupg2/binutils are not present in the shipped image.
# ---------------------------------------------------------------------------
# hadolint ignore=DL3006
FROM ${UBUNTU_IMAGE}
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG UBUNTU_CODENAME=focal
ARG UBUNTU_SNAPSHOT
ARG CA_CERTS_VERSION
ARG TARGETPLATFORM
ARG GRAMINE_VERSION=1.8
ARG SGX_AESM_VERSION=2.25.100.3-focal1
ARG SGX_DCAP_QV_VERSION=1.22.100.3-focal1
ARG AZ_DCAP_VERSION=1.12.3
ARG PSMISC_VERSION=23.3-1
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV TZ=UTC
ENV PYTHONHASHSEED=0

RUN test "${TARGETPLATFORM}" = "linux/amd64" || \
    (echo "error: SGX image must be built for linux/amd64 (got ${TARGETPLATFORM})" >&2; exit 1)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates=${CA_CERTS_VERSION} && \
    rm -rf /var/lib/apt/lists/*

RUN printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99ubuntu-snapshot && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" > /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal-updates main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" >> /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s focal-security main restricted universe multiverse\n' "${UBUNTU_SNAPSHOT}" >> /etc/apt/sources.list && \
    if ! apt-get update 2>/dev/null; then \
      echo "WARNING: snapshot.ubuntu.com unavailable — using archive.ubuntu.com" >&2; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse\n'        > /etc/apt/sources.list; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse\n' >> /etc/apt/sources.list; \
      printf 'deb http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse\n' >> /etc/apt/sources.list; \
    fi && \
    rm -rf /var/lib/apt/lists/*

COPY --from=signer /usr/share/keyrings/gramine-keyring.gpg /usr/share/keyrings/gramine-keyring.gpg
COPY --from=signer /usr/share/keyrings/intel-sgx-deb.key /usr/share/keyrings/intel-sgx-deb.key
COPY --from=signer /usr/share/keyrings/microsoft-prod.gpg /usr/share/keyrings/microsoft-prod.gpg
COPY --from=signer /etc/apt/sources.list.d/gramine.list /etc/apt/sources.list.d/gramine.list
COPY --from=signer /etc/apt/sources.list.d/intel-sgx.list /etc/apt/sources.list.d/intel-sgx.list
COPY --from=signer /etc/apt/sources.list.d/microsoft-prod.list /etc/apt/sources.list.d/microsoft-prod.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gramine=${GRAMINE_VERSION} \
    gramine-ratls-dcap=${GRAMINE_VERSION} \
    sgx-aesm-service=${SGX_AESM_VERSION} \
    libsgx-aesm-launch-plugin=${SGX_AESM_VERSION} \
    libsgx-aesm-quote-ex-plugin=${SGX_AESM_VERSION} \
    libsgx-aesm-ecdsa-plugin=${SGX_AESM_VERSION} \
    libsgx-dcap-quote-verify=${SGX_DCAP_QV_VERSION} \
    az-dcap-client=${AZ_DCAP_VERSION} \
    psmisc=${PSMISC_VERSION} && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Mirror the signer stage: the enclave measured libdcap_quoteprov.so at
# /lib/x86_64-linux-gnu/libdcap_quoteprov.so, so the runtime image must
# have the byte-identical file at the same path or integrity checks fail.
RUN cp /usr/lib/libdcap_quoteprov.so /lib/x86_64-linux-gnu/libdcap_quoteprov.so && \
    ln -s libdcap_quoteprov.so /lib/x86_64-linux-gnu/libdcap_quoteprov.so.1

WORKDIR /app

COPY --from=signer /app/relational-sdk /app/relational-sdk
COPY --from=signer /app/relational-sdk.manifest /app/relational-sdk.manifest
COPY --from=signer /app/relational-sdk.manifest.sgx /app/relational-sdk.manifest.sgx
COPY --from=signer /app/relational-sdk.sig /app/relational-sdk.sig
COPY --from=signer /app/dns /app/dns
COPY --from=signer /app/ca-certificates.crt /app/ca-certificates.crt
COPY --from=signer /app/avs-ca.crt /app/avs-ca.crt

# Fixed service identity: deterministic UID/GID across every build.
ARG APP_USER=relational
ARG APP_UID=10001
ARG APP_GID=10001

# Keep the container bootstrap as root so we can start AESM, then drop
# privileges in /start.sh before launching gramine-sgx.
RUN groupadd --gid ${APP_GID} ${APP_USER} && \
    useradd --uid ${APP_UID} --gid ${APP_GID} \
        --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin ${APP_USER} && \
    mkdir -p /var/run/aesmd/ /data && \
    chown root:root /var/run/aesmd && \
    chmod 0755 /var/run/aesmd && \
    chown ${APP_UID}:${APP_GID} /data && \
    chmod 0750 /data && \
    command -v getent >/dev/null && \
    command -v groupadd >/dev/null && \
    command -v usermod >/dev/null && \
    (command -v setpriv >/dev/null || command -v runuser >/dev/null || command -v su >/dev/null)

COPY docker/restart_aesm.sh /restart_aesm.sh
COPY docker/start.sh /start.sh
RUN chmod 0755 /restart_aesm.sh /start.sh

EXPOSE 8080

ENTRYPOINT ["/start.sh"]
