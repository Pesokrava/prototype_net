# certs/ -- TLS Certificate Generation for strongSwan

This directory contains a shell script for generating X.509 certificates used by strongSwan IKEv2 mutual authentication. Generated certificates are output to `certs/output/` which is gitignored.

## What `gen-certs.sh` Generates

Takes `SERVER_IP` as an argument and produces:

1. **CA** -- 4096-bit RSA self-signed certificate (CN=prototype-net-ca, 10-year validity). Root of trust for both server and client certs.
2. **Server certificate** -- 4096-bit RSA, signed by CA (CN=SERVER_IP, SAN=IP:SERVER_IP, 1-year). Key usage: digitalSignature + keyEncipherment, extendedKeyUsage: serverAuth.
3. **Client certificate** -- 4096-bit RSA, signed by CA (CN=test-client, 1-year). Key usage: digitalSignature, extendedKeyUsage: clientAuth.

Intermediate CSR, CNF, and SRL files are cleaned up after generation.

## Conventions

- Uses `set -euo pipefail` for strict error handling.
- Generated certs in `output/` are never committed (gitignored as secrets).
- Server cert includes SAN with IP address (strongSwan requires this for IP-based identity).
- Separate key usage profiles for server (encryption + signing) and client (signing only).
