#!/usr/bin/env bash
#
# Generate a per-client certificate signed by the existing CA.
#
# Usage: ./gen-client.sh <CLIENT_ID>
#
# Requires: certs/output/ca.crt and ca.key must already exist.
#           Run ./gen-ca-server.sh <SERVER_IP> first if they don't.
#
# Output: certs/output/client-<CLIENT_ID>.{key,crt,p12}
#         certs/output/client-bundle-<CLIENT_ID>.json
#
# The bundle JSON includes a pre-generated PKCS#12 blob (base64) so the
# macOS agent doesn't need OpenSSL at runtime. The P12 MUST be generated
# with OpenSSL 3.x + -legacy for macOS Keychain compatibility — LibreSSL
# produces P12 files where macOS imports cert and key as separate items,
# breaking IKE_AUTH signature validation.
#
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <CLIENT_ID>"
    echo "  CLIENT_ID: unique identifier for this client (e.g. test-client, macbook-alice)"
    exit 1
fi

CLIENT_ID="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
SERIAL_FILE="${OUTPUT_DIR}/ca.srl"

if [ ! -f "${OUTPUT_DIR}/ca.crt" ] || [ ! -f "${OUTPUT_DIR}/ca.key" ]; then
    echo "ERROR: CA not found at ${OUTPUT_DIR}/ca.{crt,key}"
    echo "  Run: ./gen-ca-server.sh <SERVER_IP>"
    exit 1
fi

# --- Locate OpenSSL 3.x (required for PKCS#12 -legacy) ---
# Homebrew OpenSSL is preferred; fall back to PATH openssl if it's 3.x+.
find_openssl3() {
    # Check Homebrew location first (macOS).
    local brew_openssl="/opt/homebrew/bin/openssl"
    if [ -x "${brew_openssl}" ]; then
        local ver
        ver=$("${brew_openssl}" version 2>/dev/null || true)
        if echo "${ver}" | grep -qE '^OpenSSL [34]\.'; then
            echo "${brew_openssl}"
            return
        fi
    fi

    # Check system PATH.
    local sys_openssl
    sys_openssl=$(command -v openssl 2>/dev/null || true)
    if [ -n "${sys_openssl}" ]; then
        local ver
        ver=$("${sys_openssl}" version 2>/dev/null || true)
        if echo "${ver}" | grep -qE '^OpenSSL [34]\.'; then
            echo "${sys_openssl}"
            return
        fi
    fi

    return 1
}

OPENSSL3=$(find_openssl3) || {
    echo "ERROR: OpenSSL 3.x+ not found."
    echo "  macOS ships LibreSSL which produces incompatible PKCS#12 files."
    echo "  Install OpenSSL 3.x via: brew install openssl@3"
    exit 1
}
echo "=== Using OpenSSL: ${OPENSSL3} ($(${OPENSSL3} version)) ==="

echo "=== Generating client key and certificate for '${CLIENT_ID}' ==="
openssl genrsa -out "${OUTPUT_DIR}/client-${CLIENT_ID}.key" 4096
openssl req -new \
    -key "${OUTPUT_DIR}/client-${CLIENT_ID}.key" \
    -out "${OUTPUT_DIR}/client-${CLIENT_ID}.csr" \
    -subj "/CN=${CLIENT_ID}"

cat > "${OUTPUT_DIR}/client_ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:${CLIENT_ID}
EOF

openssl x509 -req \
    -in "${OUTPUT_DIR}/client-${CLIENT_ID}.csr" \
    -CA "${OUTPUT_DIR}/ca.crt" \
    -CAkey "${OUTPUT_DIR}/ca.key" \
    -CAserial "${SERIAL_FILE}" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/client-${CLIENT_ID}.crt" \
    -days 365 \
    -sha256 \
    -extfile "${OUTPUT_DIR}/client_ext.cnf"

rm -f "${OUTPUT_DIR}/client-${CLIENT_ID}.csr" "${OUTPUT_DIR}/client_ext.cnf"

# --- Generate PKCS#12 with OpenSSL 3.x -legacy ---
echo "=== Generating PKCS#12 identity (OpenSSL 3.x -legacy) ==="
P12_PASSWORD=$(openssl rand -hex 16)
P12_PATH="${OUTPUT_DIR}/client-${CLIENT_ID}.p12"

"${OPENSSL3}" pkcs12 -export -legacy \
    -inkey "${OUTPUT_DIR}/client-${CLIENT_ID}.key" \
    -in "${OUTPUT_DIR}/client-${CLIENT_ID}.crt" \
    -certfile "${OUTPUT_DIR}/ca.crt" \
    -out "${P12_PATH}" \
    -passout "pass:${P12_PASSWORD}"

P12_B64=$(base64 < "${P12_PATH}")

echo "=== Generating JSON bundle for '${CLIENT_ID}' ==="
# Use awk to join lines with literal \n — works on both macOS (BSD) and Linux (GNU).
pem_to_json_string() { awk '{printf "%s%s", sep, $0; sep="\\n"} END{print ""}' "$1"; }
CA_PEM=$(pem_to_json_string "${OUTPUT_DIR}/ca.crt")
CLIENT_CRT_PEM=$(pem_to_json_string "${OUTPUT_DIR}/client-${CLIENT_ID}.crt")
CLIENT_KEY_PEM=$(pem_to_json_string "${OUTPUT_DIR}/client-${CLIENT_ID}.key")

# Inline the base64 P12 without newlines (JSON-safe).
P12_B64_ONELINE=$(echo "${P12_B64}" | tr -d '\n')

cat > "${OUTPUT_DIR}/client-bundle-${CLIENT_ID}.json" <<EOF
{
  "ca_cert_pem": "${CA_PEM}",
  "client_cert_pem": "${CLIENT_CRT_PEM}",
  "client_key_pem": "${CLIENT_KEY_PEM}",
  "client_id": "${CLIENT_ID}",
  "pkcs12_b64": "${P12_B64_ONELINE}",
  "pkcs12_password": "${P12_PASSWORD}"
}
EOF

echo ""
echo "=== Client certificate + bundle ready ==="
echo "  Cert:   ${OUTPUT_DIR}/client-${CLIENT_ID}.crt"
echo "  Key:    ${OUTPUT_DIR}/client-${CLIENT_ID}.key"
echo "  P12:    ${P12_PATH}"
echo "  Bundle: ${OUTPUT_DIR}/client-bundle-${CLIENT_ID}.json"
