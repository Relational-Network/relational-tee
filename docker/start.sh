#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Start script for the SGX container with DCAP RA-TLS attestation.
# This script:
# 1. Starts AESM as root for SGX attestation support
# 2. Prepares SGX device groups and the persistent /data mount
# 3. Drops privileges to the fixed service user before launching gramine-sgx
#
# NOTE: The enclave is signed at docker build time. No signing key is needed
# at runtime. This guarantees MRENCLAVE and MRSIGNER are fixed for every
# container started from the same image.

set -eu

APP_USER=relational
DATA_DIR=/data
STARTUP_UMASK=${RELATIONAL_STARTUP_UMASK:-027}

log() {
    printf '%s\n' "$*"
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

fatal() {
    printf 'FATAL: %s\n' "$*" >&2
    exit 1
}

app_uid() {
    id -u "${APP_USER}"
}

app_gid() {
    id -g "${APP_USER}"
}

user_in_group() {
    _user=$1
    _group=$2
    id -nG "${_user}" | tr ' ' '\n' | grep -Fx "${_group}" >/dev/null 2>&1
}

device_accessible_as_app() {
    _device=$1
    run_as_app test -r "${_device}" && run_as_app test -w "${_device}"
}

ensure_runtime_group() {
    _gid=$1
    _device=$2

    if [ "${_gid}" = "0" ]; then
        if ! device_accessible_as_app "${_device}"; then
            warn "${_device} is owned by GID 0 and is not accessible to ${APP_USER}. Non-root SGX access may require host-side device permission changes."
        fi
        return 0
    fi

    _group_name=$(getent group "${_gid}" | cut -d: -f1 || true)
    if [ -z "${_group_name}" ]; then
        _group_name="relational-sgx-${_gid}"
        groupadd --gid "${_gid}" "${_group_name}"
    fi

    if user_in_group "${APP_USER}" "${_group_name}"; then
        return 0
    fi

    usermod -a -G "${_group_name}" "${APP_USER}"
}

configure_sgx_access() {
    _seen_gids=" "

    for _device in /dev/sgx/enclave /dev/sgx/provision; do
        if [ ! -e "${_device}" ]; then
            continue
        fi

        _gid=$(stat -c '%g' "${_device}")
        case " ${_seen_gids} " in
            *" ${_gid} "*) continue ;;
        esac
        _seen_gids="${_seen_gids}${_gid} "

        ensure_runtime_group "${_gid}" "${_device}"
    done
}

validate_sgx_access() {
    for _device in /dev/sgx/enclave /dev/sgx/provision; do
        if [ ! -e "${_device}" ]; then
            continue
        fi

        if ! device_accessible_as_app "${_device}"; then
            fatal "${_device} is not accessible to ${APP_USER}. Fix the host device permissions or container group mapping before starting the server."
        fi
    done
}

run_as_app() {
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "${APP_USER}" -- "$@"
        return
    fi

    if command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid "$(app_uid)" --regid "$(app_gid)" --init-groups "$@"
        return
    fi

    if command -v su >/dev/null 2>&1; then
        su -s /bin/sh "${APP_USER}" -c 'exec "$@"' sh "$@"
        return
    fi

    fatal "No supported privilege drop helper found (expected one of: runuser, setpriv, su)."
}

exec_as_app() {
    if command -v setpriv >/dev/null 2>&1; then
        exec setpriv --reuid "$(app_uid)" --regid "$(app_gid)" --init-groups "$@"
    fi

    if command -v runuser >/dev/null 2>&1; then
        exec runuser -u "${APP_USER}" -- "$@"
    fi

    if command -v su >/dev/null 2>&1; then
        exec su -s /bin/sh "${APP_USER}" -c 'exec "$@"' sh "$@"
    fi

    fatal "No supported privilege drop helper found (expected one of: setpriv, runuser, su)."
}

prepare_data_dir() {
    if [ -e "${DATA_DIR}" ] && [ ! -d "${DATA_DIR}" ]; then
        fatal "${DATA_DIR} exists but is not a directory."
    fi

    mkdir -p "${DATA_DIR}"

    # Auto-fix ownership so the non-root service user can write.
    # This runs as root before privilege drop, so it works whether the
    # host bind-mount was pre-created or auto-created by Docker (root:root).
    # Recursive: legacy bind mounts may contain files written by earlier
    # image revisions that ran as root; chown -R rebases them onto the
    # service user so the app can reopen its existing database.
    chown -R "$(app_uid):$(app_gid)" "${DATA_DIR}"
    chmod 0750 "${DATA_DIR}"

    if ! run_as_app test -w "${DATA_DIR}"; then
        fatal "${DATA_DIR} is not writable by ${APP_USER} after chown. Check that the bind mount allows ownership changes."
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    fatal "This container must start as root so it can bootstrap AESM and then drop to ${APP_USER}."
fi

if ! id "${APP_USER}" >/dev/null 2>&1; then
    fatal "Required runtime user ${APP_USER} is missing from the image."
fi

umask "${STARTUP_UMASK}"

/restart_aesm.sh

if [ ! -f /app/relational-sdk.manifest.sgx ]; then
    fatal "/app/relational-sdk.manifest.sgx not found. Rebuild the image with: --secret id=sgx-key,src=/path/to/enclave-key.pem"
fi

configure_sgx_access
validate_sgx_access
prepare_data_dir

log "Enclave measurements:"
gramine-sgx-sigstruct-view /app/relational-sdk.sig \
    | grep -E "mr_enclave|mr_signer|isv_prod_id|isv_svn|debug_enclave"

log "Starting relational-sdk with DCAP RA-TLS attestation as ${APP_USER}..."
log "Server will be available at https://0.0.0.0:8080"

# gramine-sgx will execute the manifest which uses gramine-ratls as entrypoint.
# gramine-ratls generates TLS cert/key with DCAP attestation evidence, then
# executes the actual Rust server binary inside the enclave.
exec_as_app gramine-sgx relational-sdk
