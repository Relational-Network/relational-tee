#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network
#
# Health monitoring script for iob-micres services
# Checks AVS, Enclave, and Caddy-Docker services
# Auto-restarts failed services and logs issues
#
# Installation:
#   sudo cp health-check.sh /opt/iob-micres/scripts/
#   sudo chmod +x /opt/iob-micres/scripts/health-check.sh
#
# Usage:
#   /opt/iob-micres/scripts/health-check.sh
#
# Exit codes:
#   0 - All services healthy
#   1 - One or more services unhealthy (auto-restart attempted)

set -euo pipefail

LOGFILE="/opt/iob-micres/logs/health-check.log"
DEPLOY_LOCK="/opt/iob-micres/.deploying"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Ensure log directory exists
mkdir -p /opt/iob-micres/logs

log() {
    echo "[$TIMESTAMP] $1" | tee -a "$LOGFILE"
}

# Skip health check if a CD deployment is in progress.
# The lock file is created by the CD pipeline and removed on completion.
# Stale locks older than 15 minutes are ignored (deployment likely failed).
if [ -f "$DEPLOY_LOCK" ]; then
    lock_age=$(( $(date +%s) - $(stat -c %Y "$DEPLOY_LOCK" 2>/dev/null || echo 0) ))
    if [ "$lock_age" -lt 900 ]; then
        log "=== Skipping health check: deployment in progress (lock age: ${lock_age}s) ==="
        exit 0
    else
        log "WARNING: Stale deploy lock found (age: ${lock_age}s), removing and continuing"
        rm -f "$DEPLOY_LOCK"
    fi
fi

check_service() {
    local service_name=$1
    local health_url=$2
    local curl_opts=$3

    log "Checking $service_name..."

    # Check systemd service is active
    if ! systemctl is-active --quiet "$service_name"; then
        log "ERROR: $service_name systemd service is not active!"
        log "Attempting to restart $service_name..."
        sudo systemctl restart "$service_name"
        sleep 5

        if systemctl is-active --quiet "$service_name"; then
            log "✓ $service_name restarted successfully"
        else
            log "✗ $service_name restart failed!"
            sudo journalctl -u "$service_name" -n 20 --no-pager >> "$LOGFILE"
            return 1
        fi
    fi

    # Check HTTP health endpoint if provided
    if [ -n "$health_url" ]; then
        if ! curl $curl_opts -sf "$health_url" > /dev/null 2>&1; then
            log "ERROR: $service_name health check failed at $health_url"
            log "Attempting to restart $service_name..."
            sudo systemctl restart "$service_name"
            sleep 10

            if curl $curl_opts -sf "$health_url" > /dev/null 2>&1; then
                log "✓ $service_name restarted and health check passed"
            else
                log "✗ $service_name health check still failing after restart!"
                sudo journalctl -u "$service_name" -n 20 --no-pager >> "$LOGFILE"
                return 1
            fi
        else
            log "✓ $service_name healthy"
        fi
    else
        log "✓ $service_name active"
    fi

    return 0
}

check_ports() {
    local service_name=$1
    shift
    local ports=("$@")

    log "Checking $service_name ports: ${ports[*]}..."

    for port in "${ports[@]}"; do
        if ! ss -tln | grep -q ":$port "; then
            log "ERROR: $service_name port $port not listening!"
            return 1
        fi
    done

    log "✓ $service_name ports listening"
    return 0
}

main() {
    log "=== Starting health check ==="

    local all_healthy=true

    # Check Caddy-Docker (must be running for public access)
    if ! check_service "caddy-docker" "" ""; then
        all_healthy=false
    fi

    # Check Caddy ports
    if ! check_ports "caddy-docker" 80 443; then
        log "Attempting to restart caddy-docker due to missing ports..."
        sudo systemctl restart caddy-docker
        sleep 5
        if ! check_ports "caddy-docker" 80 443; then
            log "✗ caddy-docker ports still not listening!"
            all_healthy=false
        fi
    fi

    # Check AVS (required for attestation)
    if ! check_service "avs" "http://127.0.0.1:9100/health" ""; then
        all_healthy=false
    fi

    # Check AVS JWKS endpoint (critical for enclave auth)
    if ! curl -sf http://127.0.0.1:9100/.well-known/jwks.json > /dev/null 2>&1; then
        log "ERROR: AVS JWKS endpoint not responding!"
        all_healthy=false
    else
        log "✓ AVS JWKS endpoint responding"
    fi

    # Check Enclave (core service)
    if ! check_service "enclave" "https://127.0.0.1:8080/health" "-k"; then
        all_healthy=false
    fi

    # Check AESM service (required for SGX)
    if ! systemctl is-active --quiet aesmd; then
        log "WARNING: AESM service not active, attempting restart..."
        sudo systemctl restart aesmd
        sleep 2
        if ! systemctl is-active --quiet aesmd; then
            log "ERROR: AESM service restart failed!"
            all_healthy=false
        else
            log "✓ AESM service restarted"
        fi
    else
        log "✓ AESM service active"
    fi

    # Summary
    if [ "$all_healthy" = true ]; then
        log "=== All services healthy ==="
        exit 0
    else
        log "=== One or more services unhealthy (see log above) ==="
        exit 1
    fi
}

main
