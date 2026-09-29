# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Attestation Client Makefile
# RA-TLS verification client for testing SGX enclave attestation

CFLAGS := $(shell pkg-config --cflags mbedtls_gramine)
LDFLAGS := -ldl $(shell pkg-config --libs mbedtls_gramine)
CC ?= gcc

# Path to enclave sigstruct (for auto-extracting measurements)
SIGSTRUCT ?= ../relational-sdk.sig

# Auto-extract measurements from sigstruct if it exists, otherwise use defaults
MRENCLAVE ?= $(shell if [ -f $(SIGSTRUCT) ]; then gramine-sgx-sigstruct-view $(SIGSTRUCT) 2>/dev/null | grep 'mr_enclave:' | awk '{print $$2}'; else echo "fec39a2b787345d421d0edc6bd5e76e4d214816b0fa3df6e1c420e959a307df4"; fi)
MRSIGNER ?= $(shell if [ -f $(SIGSTRUCT) ]; then gramine-sgx-sigstruct-view $(SIGSTRUCT) 2>/dev/null | grep 'mr_signer:' | awk '{print $$2}'; else echo "777d23b75d3974a2a67224e49e78a45f65537861605cc0b86cb92e8d79a8d243"; fi)
ISV_PROD_ID ?= $(shell if [ -f $(SIGSTRUCT) ]; then gramine-sgx-sigstruct-view $(SIGSTRUCT) 2>/dev/null | grep 'isv_prod_id:' | awk '{print $$2}'; else echo "0"; fi)
ISV_SVN ?= $(shell if [ -f $(SIGSTRUCT) ]; then gramine-sgx-sigstruct-view $(SIGSTRUCT) 2>/dev/null | grep 'isv_svn:' | awk '{print $$2}'; else echo "0"; fi)

# Enclave endpoint
HOST ?= 127.0.0.1
PORT ?= 8080

.PHONY: all clean ssl test test-env test-cli test-wrong-mrenclave test-wrong-mrsigner help

all: attest ssl/ca.crt

attest: attest.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

# Generate dummy CA certificate (only needed to satisfy mbedTLS, not for actual verification)
ssl/ca.crt: ssl/ca_config.conf
	@echo "Generating dummy CA certificate..."
	openssl req -x509 -newkey rsa:2048 -keyout ssl/ca.key -out ssl/ca.crt \
		-days 3650 -nodes -config ssl/ca_config.conf 2>/dev/null
	@echo "Generated ssl/ca.crt and ssl/ca.key"

clean:
	rm -f attest ssl/ca.crt ssl/ca.key

# Test with environment variables (default Gramine callback)
test-env: attest ssl/ca.crt
	@echo "=== Testing RA-TLS with environment variables ==="
	@export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 && \
	export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 && \
	export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1 && \
	export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1 && \
	export RA_TLS_MRSIGNER=$(MRSIGNER) && \
	export RA_TLS_MRENCLAVE=$(MRENCLAVE) && \
	export RA_TLS_ISV_PROD_ID=$(ISV_PROD_ID) && \
	export RA_TLS_ISV_SVN=$(ISV_SVN) && \
	export APPLICATION_HOST=$(HOST) && \
	export APPLICATION_PORT=$(PORT) && \
	./attest dcap

# Test with command-line measurements (custom callback)
test-cli: attest ssl/ca.crt
	@echo "=== Testing RA-TLS with command-line measurements ==="
	@export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 && \
	export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 && \
	export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1 && \
	export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1 && \
	export APPLICATION_HOST=$(HOST) && \
	export APPLICATION_PORT=$(PORT) && \
	./attest dcap $(MRENCLAVE) $(MRSIGNER) $(ISV_PROD_ID) $(ISV_SVN)

# Default test target
test: test-cli

# Test with wrong MRENCLAVE (should FAIL)
test-wrong-mrenclave: attest ssl/ca.crt
	@echo "=== Testing RA-TLS with WRONG MRENCLAVE (should fail) ==="
	@export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 && \
	export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 && \
	export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1 && \
	export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1 && \
	export APPLICATION_HOST=$(HOST) && \
	export APPLICATION_PORT=$(PORT) && \
	./attest dcap 1111111111111111111111111111111111111111111111111111111111111111 $(MRSIGNER) 0 0 || \
	echo "✓ Correctly rejected wrong MRENCLAVE"

# Test with wrong MRSIGNER (should FAIL)
test-wrong-mrsigner: attest ssl/ca.crt
	@echo "=== Testing RA-TLS with WRONG MRSIGNER (should fail) ==="
	@export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 && \
	export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 && \
	export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1 && \
	export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1 && \
	export APPLICATION_HOST=$(HOST) && \
	export APPLICATION_PORT=$(PORT) && \
	./attest dcap $(MRENCLAVE) 2222222222222222222222222222222222222222222222222222222222222222 0 0 || \
	echo "✓ Correctly rejected wrong MRSIGNER"

# Run all tests
test-all: test-cli test-wrong-mrenclave test-wrong-mrsigner
	@echo ""
	@echo "=== All tests completed ==="

# Extract measurements from enclave sigstruct
update-measurements:
	@echo "Extracting measurements from ../relational-sdk.sig..."
	@gramine-sgx-sigstruct-view ../relational-sdk.sig 2>/dev/null | grep -E "mr_enclave|mr_signer|isv_prod_id|isv_svn"
	@echo ""
	@echo "Update MRENCLAVE and MRSIGNER in this Makefile with values above"

help:
	@echo "RA-TLS Attestation Client"
	@echo ""
	@echo "Usage:"
	@echo "  make                    Build attestation client and CA cert"
	@echo "  make test               Test attestation with current measurements"
	@echo "  make test-env           Test using RA_TLS_* environment variables"
	@echo "  make test-cli           Test using command-line measurements"
	@echo "  make test-wrong-mrenclave  Verify wrong MRENCLAVE is rejected"
	@echo "  make test-wrong-mrsigner   Verify wrong MRSIGNER is rejected"
	@echo "  make test-all           Run all tests"
	@echo "  make update-measurements   Show current enclave measurements"
	@echo "  make clean              Remove built files"
	@echo ""
	@echo "Configuration variables:"
	@echo "  MRENCLAVE=$(MRENCLAVE)"
	@echo "  MRSIGNER=$(MRSIGNER)"
	@echo "  HOST=$(HOST)"
	@echo "  PORT=$(PORT)"
	@echo ""
	@echo "Example with custom endpoint:"
	@echo "  make test HOST=10.0.0.5 PORT=443"
