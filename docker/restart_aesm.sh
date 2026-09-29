#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Restart AESM service for SGX attestation

set -e

killall -q aesm_service || true

AESM_PATH=/opt/intel/sgx-aesm-service/aesm \
LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm \
/opt/intel/sgx-aesm-service/aesm/aesm_service --no-syslog &

echo $! > /var/run/aesmd/aesm.pid
