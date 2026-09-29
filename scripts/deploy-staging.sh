#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network
#
# Manual deployment script for relational-sdk enclave
# Run this on the staging SGX VM (iob-staging)
#
# Usage: ./scripts/deploy-staging.sh [--skip-build]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="/opt/iob-micres/.env"

echo "=============================================="
echo "  relational-sdk Staging Deployment"
echo "=============================================="
echo ""

# Check if running on SGX hardware
if [ ! -e /dev/sgx/enclave ]; then
    echo "ERROR: SGX device not found at /dev/sgx/enclave"
    echo "This script must be run on an SGX-enabled machine."
    exit 1
fi

# Check for enclave signing key
SIGNING_KEY="${GRAMINE_SGX_SIGNING_KEY:-/opt/iob-micres/secrets/enclave-key.pem}"
if [ ! -f "$SIGNING_KEY" ]; then
    echo "ERROR: Enclave signing key not found at $SIGNING_KEY"
    echo "Set GRAMINE_SGX_SIGNING_KEY or copy key to /opt/iob-micres/secrets/"
    exit 1
fi
export GRAMINE_SGX_SIGNING_KEY="$SIGNING_KEY"

cd "$PROJECT_DIR"

# Parse arguments
SKIP_BUILD=false
if [ "$1" == "--skip-build" ]; then
    SKIP_BUILD=true
fi

# Step 1: Pull latest code
echo "=== Step 1: Pulling latest code ==="
git pull origin staging || git pull origin main || echo "Git pull failed, continuing with local code"

# Step 2: Build enclave (unless skipped)
if [ "$SKIP_BUILD" = false ]; then
    echo ""
    echo "=== Step 2: Building enclave with SGX ==="
    make clean || true
    make SGX=1 RA_TYPE=dcap
    
    echo ""
    echo "=== Step 3: Extracting measurements ==="
    MEASUREMENTS=$(gramine-sgx-sigstruct-view relational-sdk.sig)
    echo "$MEASUREMENTS"
    
    MRENCLAVE=$(echo "$MEASUREMENTS" | grep "mr_enclave:" | awk '{print $2}')
    MRSIGNER=$(echo "$MEASUREMENTS" | grep "mr_signer:" | awk '{print $2}')
    
    echo ""
    echo "Extracted measurements:"
    echo "  MRENCLAVE: $MRENCLAVE"
    echo "  MRSIGNER:  $MRSIGNER"
    
    # Update .env file with new MRENCLAVE
    if [ -f "$ENV_FILE" ]; then
        echo ""
        echo "=== Step 4: Updating $ENV_FILE ==="
        
        # Update MRENCLAVE
        if grep -q "^AVS_EXPECTED_MRENCLAVE=" "$ENV_FILE"; then
            sudo sed -i "s/^AVS_EXPECTED_MRENCLAVE=.*/AVS_EXPECTED_MRENCLAVE=$MRENCLAVE/" "$ENV_FILE"
            echo "Updated AVS_EXPECTED_MRENCLAVE"
        else
            echo "AVS_EXPECTED_MRENCLAVE=$MRENCLAVE" | sudo tee -a "$ENV_FILE"
            echo "Added AVS_EXPECTED_MRENCLAVE"
        fi
        
        # Verify MRSIGNER matches
        EXISTING_MRSIGNER=$(grep "^AVS_EXPECTED_MRSIGNER=" "$ENV_FILE" | cut -d= -f2)
        if [ -n "$EXISTING_MRSIGNER" ] && [ "$EXISTING_MRSIGNER" != "$MRSIGNER" ]; then
            echo ""
            echo "WARNING: MRSIGNER mismatch!"
            echo "  Existing: $EXISTING_MRSIGNER"
            echo "  Current:  $MRSIGNER"
            echo "This means the signing key has changed. Update AVS_EXPECTED_MRSIGNER manually if intentional."
        fi
    fi
else
    echo ""
    echo "=== Skipping build (--skip-build flag) ==="
fi

# Step 5: Build Docker image
echo ""
echo "=== Step 5: Building Docker image ==="
docker build -t relational-sdk:local -f docker/Dockerfile .

# Step 6: Restart enclave service
echo ""
echo "=== Step 6: Restarting enclave service ==="
sudo systemctl restart enclave

# Wait for enclave to start
echo "Waiting for enclave to start..."
sleep 15

# Step 7: Verify enclave health
echo ""
echo "=== Step 7: Verifying enclave health ==="
if curl -sf --max-time 10 -k https://127.0.0.1:8080/health; then
    echo ""
    echo "✅ Enclave is healthy!"
else
    echo ""
    echo "❌ Enclave health check failed!"
    echo "Check logs: sudo journalctl -u enclave -f"
    exit 1
fi

# Step 8: Restart AVS to pick up new measurements
echo ""
echo "=== Step 8: Restarting AVS ==="
sudo systemctl restart avs

sleep 5

if curl -sf --max-time 10 http://127.0.0.1:9100/health; then
    echo ""
    echo "✅ AVS is healthy!"
else
    echo ""
    echo "❌ AVS health check failed!"
    echo "Check logs: sudo journalctl -u avs -f"
    exit 1
fi

# Step 9: Test attestation
echo ""
echo "=== Step 9: Verifying public endpoints ==="
# /v1/attest now requires a Clerk Bearer token, so we cannot exercise the full
# attestation flow from a deploy script. Instead, verify the unauthenticated
# endpoints — a successful enclave start already implies that secret
# provisioning (RA-TLS to AVS:4433) succeeded.
if curl -sf --max-time 10 http://127.0.0.1:9100/.well-known/jwks.json >/dev/null \
    && curl -sfk --max-time 10 https://127.0.0.1:8080/health >/dev/null; then
    echo "✅ Public smoke tests passed!"
    echo ""
    echo "=============================================="
    echo "  Deployment Complete!"
    echo "=============================================="
    echo ""
    echo "Public URL: https://iob-staging.duckdns.org"
    echo ""
    echo "Measurements:"
    if [ -n "$MRENCLAVE" ]; then
        echo "  MRENCLAVE: $MRENCLAVE"
        echo "  MRSIGNER:  $MRSIGNER"
    else
        gramine-sgx-sigstruct-view relational-sdk.sig | grep -E "mr_(enclave|signer):"
    fi
else
    echo "❌ Public smoke tests failed!"
    echo ""
    echo "Check AVS logs:     sudo journalctl -u avs -f"
    echo "Check enclave logs: sudo journalctl -u enclave -f"
    exit 1
fi
