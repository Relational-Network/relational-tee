# RA-TLS Attestation Client

A test client for verifying SGX enclave attestation via RA-TLS (Remote Attestation TLS) using Intel DCAP.

## Overview

This client connects to the relational-sdk enclave over TLS and verifies:
1. The SGX quote embedded in the RA-TLS certificate
2. Enclave measurements (MRENCLAVE, MRSIGNER, ISV_PROD_ID, ISV_SVN)
3. Quote verification status (TCB level, debug mode, etc.)

## Prerequisites

- Gramine with mbedTLS (`mbedtls_gramine` pkg-config)
- Intel DCAP libraries (`libsgx_urts.so`, `libdcap_quoteprov.so`)
- OpenSSL (for generating dummy CA cert)

## Quick Start

```bash
# Build the client
make

# Test against running enclave
make test

# See all options
make help
```

## Usage

### Basic Test
```bash
# Ensure enclave is running first:
# cd .. && gramine-sgx relational-sdk

# Run attestation test
make test
```

### Custom Measurements
After rebuilding the enclave, update measurements:
```bash
# Show current enclave measurements
make update-measurements

# Then edit Makefile with new values, or pass directly:
make test MRENCLAVE=<new_value> MRSIGNER=<new_value>
```

### Custom Endpoint
```bash
# Test against remote enclave
make test HOST=enclave.example.com PORT=443
```

### Negative Tests
Verify that wrong measurements are correctly rejected:
```bash
make test-wrong-mrenclave  # Should fail
make test-wrong-mrsigner   # Should fail
```

## Environment Variables

The client respects these RA-TLS environment variables:

| Variable | Description |
|----------|-------------|
| `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE` | Allow debug enclaves (set to 1 for testing) |
| `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE` | Allow outdated TCB |
| `RA_TLS_ALLOW_HW_CONFIG_NEEDED` | Allow HW config needed status |
| `RA_TLS_ALLOW_SW_HARDENING_NEEDED` | Allow SW hardening needed status |
| `RA_TLS_MRENCLAVE` | Expected MRENCLAVE (hex) |
| `RA_TLS_MRSIGNER` | Expected MRSIGNER (hex) |
| `RA_TLS_ISV_PROD_ID` | Expected ISV Product ID |
| `RA_TLS_ISV_SVN` | Expected ISV SVN |

## Quote Verification Results

| Code | Status | Meaning |
|------|--------|---------|
| 0x0 | OK | Quote verified successfully |
| 0xa001 | SIGNATURE_INVALID | Quote signature verification failed |
| 0xa002 | GROUP_REVOKED | Attestation key has been revoked |
| 0xa003 | SIGNATURE_REVOKED | Signature has been revoked |
| 0xa004 | KEY_REVOKED | Key has been revoked |
| 0xa005 | SIGRL_VERSION_MISMATCH | Signature revocation list version mismatch |
| 0xa006 | GROUP_OUT_OF_DATE | TCB is out of date |
| 0xa007 | SW_HARDENING_NEEDED | Platform requires software hardening |
| 0xa008 | CONFIGURATION_NEEDED | Platform configuration needs update |

## Error Locations (err_loc)

| Code | Location | Description |
|------|----------|-------------|
| 0 | AT_INIT | Initialization (success if no error) |
| 1 | AT_EXTRACT_QUOTE | Failed to extract quote from certificate |
| 2 | AT_VERIFY_EXTERNAL | External verification failed |
| 3 | AT_VERIFY_ENCLAVE_ATTRS | Enclave attributes verification failed |
| 4 | AT_VERIFY_ENCLAVE_ATTRS_DEBUG | Debug enclave not allowed |
| 5 | AT_VERIFY_ENCLAVE_MEASUREMENTS | Measurement mismatch |
| 6 | AT_VERIFY_IAS_RESPONSE | IAS response verification failed |

## Files

- `attest.c` - Main attestation client source
- `ssl/ca_config.conf` - OpenSSL config for dummy CA cert
- `ssl/ca.crt` - Generated dummy CA (not used for actual verification)
- `ssl/ca.key` - Generated dummy CA key

## How It Works

1. Client loads `libra_tls_verify_dcap.so` for DCAP quote verification
2. Connects to enclave over TLS
3. During TLS handshake, receives RA-TLS certificate containing SGX quote
4. RA-TLS callback extracts and verifies the quote via DCAP
5. Compares enclave measurements against expected values
6. If all checks pass, TLS handshake completes successfully
