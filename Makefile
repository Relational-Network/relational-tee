# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Makefile for relational-sdk.
#
# Three workflows live here:
#
#   1. Host development (no SGX, debug only)
#      make dev-check | dev-build | dev-test
#      Uses the `cargo dev-*` aliases from .cargo/config.toml. These are the
#      ONLY non-Docker, non-SGX paths and are intended for fast iteration only.
#
#   2. Native SGX dev (iob-dev VM with Gramine + DCAP)
#      make                      # builds .manifest / .manifest.sgx / .sig
#      make start-relational-sdk # runs inside SGX enclave, loads .env if present
#      Uses the root-level relational-sdk.manifest.template (allowed_files for
#      host DNS/CA, SGX_DEBUG toggleable).
#
#   3. Production (Docker, signed and deterministic)
#      make docker-build         # builds & signs image, baking MRENCLAVE into the layer
#      make docker-run           # runs locally with SGX device pass-through
#      make docker-sigstruct     # prints [enclave] block in measurements.toml shape
#      make verify-mrenclave     # rebuilds --no-cache and diffs against measurements.toml
#      Uses docker/relational-sdk.manifest.template (sgx.debug=false hardcoded,
#      DNS + CA bundle baked in as trusted_files).

# Use fixed x86_64-linux-gnu path (clang may report x86_64-pc-linux-gnu which
# doesn't exist on Ubuntu/Gramine systems).
ARCH_LIBDIR ?= /lib/x86_64-linux-gnu

# Find gramine-ratls binary (required for RA-TLS)
ENTRYPOINT ?= $(firstword $(wildcard /usr/bin/gramine-ratls /usr/local/bin/gramine-ratls /bin/gramine-ratls))

# Native SGX dev paths. Docker uses its own paths set inside the Dockerfile.
APP_DIR ?= $(shell pwd)
SELF_EXE ?= target/release/relational-sdk
SRCS = $(shell find src -type f)

# Directory for encrypted persistent storage (on host). Override per command if desired:
#   make DATA_DIR=/opt/local-docker/data/ docker-run
DATA_DIR ?= $(abspath data)

# Path to AVS secrets directory (for TLS cert used as CA in secret provisioning).
# Used by setup-dev-certs and docker-run targets.
SECRETS_DIR ?= ../attestation-verification-service/secrets

# RA type is always DCAP — no EPID support.
RA_TYPE = dcap

# SGX enclave identity values
ISVPRODID ?= 0
ISVSVN ?= 0

# SGX_DEBUG controls whether sgx.debug is true in the *native* manifest.
# Docker builds hardcode sgx.debug = false in docker/relational-sdk.manifest.template
# and ignore this variable.
#   0 (default): Production mode — secure, no debugging
#   1: Debug mode — allows debugging but exposes enclave memory
SGX_DEBUG ?= 0

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: $(SELF_EXE) relational-sdk.manifest relational-sdk.manifest.sgx relational-sdk.sig

.PHONY: help
help:
	@echo "Host development (no SGX, debug only):"
	@echo "  make dev-check                fast host compile check"
	@echo "  make dev-build                host dev build (target/debug)"
	@echo "  make dev-test                 cargo test --features dev"
	@echo ""
	@echo "Native SGX dev (iob-dev VM):"
	@echo "  make                          build SGX artefacts (.manifest/.sgx/.sig)"
	@echo "  make start-relational-sdk     run inside SGX enclave (loads .env if present)"
	@echo "  make show-measurements        inspect local SIGSTRUCT measurements"
	@echo ""
	@echo "Production (Docker, signed and deterministic):"
	@echo "  make docker-build             build signed SGX Docker image"
	@echo "  make docker-run               run SGX Docker image (override with DATA_DIR=/path)"
	@echo "  make docker-stop              stop running SGX Docker container"
	@echo "  make docker-sigstruct         inspect SIGSTRUCT from Docker image"
	@echo "  make verify-mrenclave         rebuild --no-cache and compare against measurements.toml"
	@echo ""
	@echo "Attestation client (C-based DCAP verifier):"
	@echo "  make attest                   build attestation client"
	@echo "  make test-attest              test attestation against running enclave"
	@echo "  make test-attest-all          run all attestation tests"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean                    remove generated manifest/signing artifacts"
	@echo "  make distclean                clean + remove target/ and Cargo.lock"

# ─────────────────────────────────────────────────────────────────────────────
# Host development (no SGX, debug only)
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: dev-check
dev-check:
	cargo dev-check

.PHONY: dev-build
dev-build:
	cargo dev-build

.PHONY: dev-test
dev-test:
	cargo dev-test

# ─────────────────────────────────────────────────────────────────────────────
# Native SGX dev (iob-dev VM)
# ─────────────────────────────────────────────────────────────────────────────

# Create data directory for encrypted storage
$(DATA_DIR):
	mkdir -p $(DATA_DIR)

# Dev builds use release profile (debug is an order of magnitude slower in SGX).
# The DEBUG knob controls Gramine's loglevel only.
-include $(SELF_EXE).d # See also: .cargo/config.toml
$(SELF_EXE): Cargo.toml Cargo.lock $(SRCS)
	cargo build --release

relational-sdk.manifest: relational-sdk.manifest.template $(SELF_EXE) | $(DATA_DIR)
	@if [ -z "$(ENTRYPOINT)" ]; then \
		echo "error: gramine-ratls not found; install gramine-ratls-dcap or set ENTRYPOINT=/path/to/gramine-ratls"; \
		exit 1; \
	fi
	SGX_DEBUG=$(SGX_DEBUG) gramine-manifest \
		-Dentrypoint=$(ENTRYPOINT) \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dapp_dir=$(APP_DIR) \
		-Dself_exe=$(SELF_EXE) \
		-Ddata_dir=$(DATA_DIR) \
		-Dra_type=$(RA_TYPE) \
		-Disvprodid=$(ISVPRODID) \
		-Disvsvn=$(ISVSVN) \
		$< $@

relational-sdk.manifest.sgx relational-sdk.sig &: relational-sdk.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx \
		--date 0000-00-00

.PHONY: start-relational-sdk
start-relational-sdk: all
	@if [ -f .env ]; then \
		echo "Loading environment from .env"; \
		if grep -nE '^[[:space:]]*[^#[:space:]][^=]*=.*<[^>]+>' .env >/dev/null 2>&1; then \
			echo "error: .env contains placeholder syntax like <...> which breaks shell parsing."; \
			echo "replace placeholder values with literal URLs/values."; \
			grep -nE '^[[:space:]]*[^#[:space:]][^=]*=.*<[^>]+>' .env; \
			exit 1; \
		fi; \
		set -a; . ./.env; set +a; \
	fi; \
	gramine-sgx relational-sdk

# Back-compat alias for the previous Makefile target name.
.PHONY: start-gramine-server
start-gramine-server: start-relational-sdk

.PHONY: show-measurements
show-measurements: relational-sdk.sig
	@gramine-sgx-sigstruct-view relational-sdk.sig | grep -E "mr_enclave|mr_signer|isv_prod_id|isv_svn|debug_enclave"

# ─────────────────────────────────────────────────────────────────────────────
# Production (Docker, signed and deterministic)
# ─────────────────────────────────────────────────────────────────────────────

# Signing key path (resolved by docker/build.sh; default $HOME/.config/gramine/enclave-key.pem).
# SIGNING_KEY is kept as a back-compat alias for one release.
SGX_SIGNING_KEY ?= $(if $(SIGNING_KEY),$(SIGNING_KEY),$(HOME)/.config/gramine/enclave-key.pem)

.PHONY: docker-build
# The AVS RA-TLS trust anchor is baked into the image as /app/avs-ca.crt and
# measured into MRENCLAVE. Stage it into the build context first, run the
# build, then remove it whether the build succeeded or failed.
docker-build:
	@if [ ! -f "$(SECRETS_DIR)/avs-tls.crt" ]; then \
		echo "ERROR: $(SECRETS_DIR)/avs-tls.crt not found."; \
		echo "Run: cd ../attestation-verification-service && ./secrets/generate-keys.sh"; \
		exit 1; \
	fi
	@cp "$(SECRETS_DIR)/avs-tls.crt" avs-ca.crt && \
		( cd docker && sudo SGX_SIGNING_KEY="$(SGX_SIGNING_KEY)" ./build.sh ubuntu20 ); \
		status=$$?; rm -f avs-ca.crt; exit $$status

.PHONY: docker-run
# Auth & CORS env vars are loaded from .env via --env-file.
# This avoids the problem of `sudo` stripping the user's environment.
# Create .env from .env.example if you haven't already.
#
# Exit 137 (SIGKILL) is expected because Gramine SGX does not propagate
# SIGTERM to the enclave, so Docker force-stops the container after the
# configured stop-timeout. This is harmless: Gramine's encrypted filesystem
# flushes writes synchronously.
docker-run:
	@mkdir -p $(DATA_DIR)
	@status=0; \
	sudo docker run --rm -it \
		--name relational-sdk-sgx \
		--network host \
		--device /dev/sgx/enclave \
		--device /dev/sgx/provision \
		--stop-timeout 30 \
		-v "$(DATA_DIR):/data" \
		-e SECRET_PROVISION_SERVERS=127.0.0.1:4433 \
		$$( [ -f .env ] && echo "--env-file .env" ) \
		relationalnetwork/relational-sdk:focal || status=$$?; \
	case "$$status" in \
		0|130|137) exit 0 ;; \
		*) exit "$$status" ;; \
	esac

.PHONY: docker-stop
docker-stop:
	sudo docker stop -t 30 relational-sdk-sgx

.PHONY: docker-sigstruct
docker-sigstruct:
	@echo "Extracting enclave measurements from Docker image..."
	@sudo docker create --name relational-sdk-sigstruct relationalnetwork/relational-sdk:focal >/dev/null 2>&1
	@sudo docker cp relational-sdk-sigstruct:/app/relational-sdk.sig /tmp/relational-sdk-docker.sig >/dev/null 2>&1
	@sudo docker rm relational-sdk-sigstruct >/dev/null 2>&1
	@echo "[enclave]"
	@gramine-sgx-sigstruct-view --verbose --output-format=toml /tmp/relational-sdk-docker.sig \
		| awk ' \
			/^mr_enclave = / { mr_enclave = $$0 } \
			/^mr_signer = / { mr_signer = $$0 } \
			/^isv_prod_id = / { isv_prod_id = $$0 } \
			/^isv_svn = / { isv_svn = $$0 } \
			/^debug_enclave = / { debug_enclave = $$0 } \
			END { \
				print mr_enclave; \
				print mr_signer; \
				print isv_prod_id; \
				print isv_svn; \
				print debug_enclave; \
			} \
		'
	@sudo rm -f /tmp/relational-sdk-docker.sig

.PHONY: verify-mrenclave
verify-mrenclave:
	@EXPECTED_MR=$$(sed -n 's/^mr_enclave = "\(.*\)"$$/\1/p' measurements.toml | head -1); \
	if ! printf '%s\n' "$$EXPECTED_MR" | grep -Eq '^[0-9a-f]{64}$$'; then \
		echo "ERROR: measurements.toml does not contain a pinned mr_enclave yet."; \
		echo "Run 'make docker-build' and 'make docker-sigstruct', then record the value in measurements.toml."; \
		exit 1; \
	fi
	@if [ ! -f "$(SGX_SIGNING_KEY)" ]; then \
		echo "ERROR: Signing key not found at $(SGX_SIGNING_KEY)"; \
		echo "Set SGX_SIGNING_KEY=/path/to/enclave-key.pem"; \
		exit 1; \
	fi
	@if [ ! -f "$(SECRETS_DIR)/avs-tls.crt" ]; then \
		echo "ERROR: $(SECRETS_DIR)/avs-tls.crt not found."; \
		echo "Run: cd ../attestation-verification-service && ./secrets/generate-keys.sh"; \
		exit 1; \
	fi
	@cp "$(SECRETS_DIR)/avs-tls.crt" avs-ca.crt
	@echo "=== Building locally (no cache) ==="
	@cd docker && sudo DOCKER_BUILDKIT=1 SGX_SIGNING_KEY="$(SGX_SIGNING_KEY)" docker build \
		--platform linux/amd64 \
		--no-cache \
		--build-arg UBUNTU_CODENAME=focal \
		--secret id=sgx-key,src="$(SGX_SIGNING_KEY)" \
		-t relationalnetwork/relational-sdk:verify-local \
		-f Dockerfile \
		.. >/dev/null; \
		build_status=$$?; rm -f ../avs-ca.crt; \
		if [ "$$build_status" -ne 0 ]; then exit "$$build_status"; fi
	@BUILT_MR=$$(sudo docker run --rm \
		--entrypoint gramine-sgx-sigstruct-view \
		relationalnetwork/relational-sdk:verify-local \
		/app/relational-sdk.sig 2>/dev/null | grep 'mr_enclave:' | awk '{print $$2}' | head -1); \
	EXPECTED_MR=$$(sed -n 's/^mr_enclave = "\(.*\)"$$/\1/p' measurements.toml | head -1); \
	echo "Built:    $$BUILT_MR"; \
	echo "Expected: $$EXPECTED_MR  (measurements.toml)"; \
	if [ "$$BUILT_MR" = "$$EXPECTED_MR" ]; then \
		echo "MATCH - MRENCLAVE matches measurements.toml"; \
	else \
		echo "MISMATCH - MRENCLAVE differs from measurements.toml!"; \
		echo "If intentional, update measurements.toml in the same PR."; \
		exit 1; \
	fi

# ─────────────────────────────────────────────────────────────────────────────
# Attestation client (C-based DCAP verifier)
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: attest
attest:
	$(MAKE) -C attestation-client

.PHONY: test-attest
test-attest:
	$(MAKE) -C attestation-client test

.PHONY: test-attest-all
test-attest-all:
	$(MAKE) -C attestation-client test-all

# ─────────────────────────────────────────────────────────────────────────────
# AVS dev certs
# ─────────────────────────────────────────────────────────────────────────────

# Copy the AVS TLS cert to the system CA store so the enclave can verify the
# secret provisioning TLS connection on port 4433. Run once after first-time
# setup or when avs-tls.crt is regenerated.
.PHONY: setup-dev-certs
setup-dev-certs:
	@if [ ! -f "$(SECRETS_DIR)/avs-tls.crt" ]; then \
		echo "ERROR: $(SECRETS_DIR)/avs-tls.crt not found."; \
		echo "Run: cd ../attestation-verification-service && ./secrets/generate-keys.sh"; \
		exit 1; \
	fi
	sudo cp "$(SECRETS_DIR)/avs-tls.crt" /etc/ssl/certs/avs-ca.crt
	sudo update-ca-certificates --fresh
	@echo "Installed AVS CA cert at /etc/ssl/certs/avs-ca.crt"

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	$(RM) -rf *.sig *.manifest.sgx *.manifest
	$(MAKE) -C attestation-client clean

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock
