# certs/ -- TLS Certificate Generation for strongSwan

This directory contains shell scripts for generating X.509 certificates used by strongSwan IKEv2 mutual authentication. Generated certificates are output to `certs/output/` which is gitignored.

## Scripts

### `gen-ca-server.sh <SERVER_IP>`

Generates the CA and server certificate. Must be run first.

1. **CA** -- 4096-bit RSA self-signed certificate (CN=prototype-net-ca, 10-year validity). Root of trust for both server and client certs.
2. **Server certificate** -- 4096-bit RSA, signed by CA (CN=SERVER_IP, SAN=IP:SERVER_IP, 1-year). Key usage: digitalSignature + keyEncipherment, extendedKeyUsage: serverAuth.

### `gen-client.sh <CLIENT_ID>`

Generates a per-client certificate, PKCS#12 identity, and JSON bundle.

**Output files:**
- `output/client-<CLIENT_ID>.key` -- 4096-bit RSA private key
- `output/client-<CLIENT_ID>.crt` -- Signed client certificate (1-year, SAN=DNS:<CLIENT_ID>)
- `output/client-<CLIENT_ID>.p12` -- PKCS#12 identity blob (cert + key + CA chain)
- `output/client-bundle-<CLIENT_ID>.json` -- JSON bundle containing all PEM certs, base64 P12, and P12 password

**Bundle JSON fields:**
| Field | Description |
|-------|-------------|
| `ca_cert_pem` | CA certificate PEM (newlines escaped as `\n`) |
| `client_cert_pem` | Client certificate PEM |
| `client_key_pem` | Client private key PEM |
| `client_id` | Client identifier string |
| `pkcs12_b64` | Base64-encoded PKCS#12 blob (single line) |
| `pkcs12_password` | Random hex password for the P12 |

**PKCS#12 generation (critical):**

The script locates OpenSSL 3.x (Homebrew `/opt/homebrew/bin/openssl` preferred, then PATH) and generates the P12 with the `-legacy` flag. This is required because:

- **LibreSSL** (macOS default `openssl`) produces PKCS#12 files where macOS Keychain imports the certificate and private key as **separate items** rather than a linked identity.
- This causes strongSwan's IKE_AUTH to fail with `signature validation failed, looking for another key` because macOS cannot find the private key associated with the certificate.
- **OpenSSL 3.x + `-legacy`** produces PKCS#12 files that macOS imports as a proper linked identity, fixing IKE_AUTH.

The script will error out if OpenSSL 3.x is not found. Install via `brew install openssl@3`.

**`subjectAltName=DNS:<CLIENT_ID>`:**

The client certificate includes a DNS SAN matching the client ID. This is required because macOS IKEv2 sends the `LocalIdentifier` as `ID_FQDN` type (bare string like `macbook-test`), and strongSwan matches this against the certificate's SAN, not the CN.

## Server-Side Deployment

After generating a client certificate, deploy it to the server:

```bash
scp certs/output/client-<CLIENT_ID>.crt ubuntu@<SERVER_IP>:/etc/swanctl/x509/
ssh ubuntu@<SERVER_IP> sudo swanctl --load-creds
```

The client cert must be pre-loaded in `/etc/swanctl/x509/` for strongSwan to find a trusted public key matching the FQDN identity. Without it, strongSwan logs `no trusted RSA public key found for '<CLIENT_ID>'`.

## Conventions

- Uses `set -euo pipefail` for strict error handling.
- Generated certs in `output/` are never committed (gitignored as secrets).
- Server cert includes SAN with IP address (strongSwan requires this for IP-based identity).
- Client cert includes SAN with DNS name (strongSwan matches FQDN identity against this).
- Separate key usage profiles for server (encryption + signing) and client (signing only).
- PKCS#12 pre-generated at build time so the macOS agent doesn't need OpenSSL at runtime.
- Uses `awk` for PEM-to-JSON newline escaping (macOS BSD `sed` doesn't support GNU multi-line patterns).
