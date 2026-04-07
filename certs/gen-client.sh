#!/usr/bin/env bash
#
# Generate a per-client certificate signed by the existing CA.
#
# Usage: ./gen-client.sh <CLIENT_ID>
#
# Requires: certs/output/ca.crt and ca.key must already exist.
#           Run ./gen-ca-server.sh <SERVER_IP> first if they don't.
#
# Output: certs/output/client-<CLIENT_ID>.{key,crt}
#         certs/output/client-bundle-<CLIENT_ID>.json
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

echo "=== Generating JSON bundle for '${CLIENT_ID}' ==="
CA_PEM=$(sed ':a;N;$!ba;s/\n/\\n/g' "${OUTPUT_DIR}/ca.crt")
CLIENT_CRT_PEM=$(sed ':a;N;$!ba;s/\n/\\n/g' "${OUTPUT_DIR}/client-${CLIENT_ID}.crt")
CLIENT_KEY_PEM=$(sed ':a;N;$!ba;s/\n/\\n/g' "${OUTPUT_DIR}/client-${CLIENT_ID}.key")

cat > "${OUTPUT_DIR}/client-bundle-${CLIENT_ID}.json" <<EOF
{
  "ca_cert_pem": "${CA_PEM}",
  "client_cert_pem": "${CLIENT_CRT_PEM}",
  "client_key_pem": "${CLIENT_KEY_PEM}",
  "client_id": "${CLIENT_ID}"
}
EOF

echo ""
echo "=== Client certificate + bundle ready ==="
echo "  Cert:   ${OUTPUT_DIR}/client-${CLIENT_ID}.crt"
echo "  Key:    ${OUTPUT_DIR}/client-${CLIENT_ID}.key"
echo "  Bundle: ${OUTPUT_DIR}/client-bundle-${CLIENT_ID}.json"
