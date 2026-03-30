#!/usr/bin/env bash
#
# Generate CA, server, and client certificates for strongSwan IKEv2.
#
# Usage: ./gen-certs.sh <SERVER_IP>
#
# Output: certs/output/{ca,server,client}.{key,crt}
#
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <SERVER_IP>"
    echo "  SERVER_IP: IP address or hostname of the server VM (used as CN for server cert)"
    exit 1
fi

SERVER_IP="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"

mkdir -p "${OUTPUT_DIR}"

echo "=== Generating CA key and certificate ==="
openssl genrsa -out "${OUTPUT_DIR}/ca.key" 4096
openssl req -x509 -new -nodes \
    -key "${OUTPUT_DIR}/ca.key" \
    -sha256 \
    -days 3650 \
    -out "${OUTPUT_DIR}/ca.crt" \
    -subj "/CN=prototype-net-ca"

echo "=== Generating server key and certificate ==="
openssl genrsa -out "${OUTPUT_DIR}/server.key" 4096
openssl req -new \
    -key "${OUTPUT_DIR}/server.key" \
    -out "${OUTPUT_DIR}/server.csr" \
    -subj "/CN=${SERVER_IP}"

# Create extensions file for server cert (SAN + key usage for strongSwan)
cat > "${OUTPUT_DIR}/server_ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${SERVER_IP}
EOF

openssl x509 -req \
    -in "${OUTPUT_DIR}/server.csr" \
    -CA "${OUTPUT_DIR}/ca.crt" \
    -CAkey "${OUTPUT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/server.crt" \
    -days 365 \
    -sha256 \
    -extfile "${OUTPUT_DIR}/server_ext.cnf"

echo "=== Generating client key and certificate ==="
openssl genrsa -out "${OUTPUT_DIR}/client.key" 4096
openssl req -new \
    -key "${OUTPUT_DIR}/client.key" \
    -out "${OUTPUT_DIR}/client.csr" \
    -subj "/CN=test-client"

# Create extensions file for client cert
cat > "${OUTPUT_DIR}/client_ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl x509 -req \
    -in "${OUTPUT_DIR}/client.csr" \
    -CA "${OUTPUT_DIR}/ca.crt" \
    -CAkey "${OUTPUT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/client.crt" \
    -days 365 \
    -sha256 \
    -extfile "${OUTPUT_DIR}/client_ext.cnf"

# Clean up CSR and extension files
rm -f "${OUTPUT_DIR}"/*.csr "${OUTPUT_DIR}"/*.cnf "${OUTPUT_DIR}"/*.srl

echo ""
echo "=== Certificates generated successfully ==="
echo "  CA:     ${OUTPUT_DIR}/ca.key, ${OUTPUT_DIR}/ca.crt"
echo "  Server: ${OUTPUT_DIR}/server.key, ${OUTPUT_DIR}/server.crt"
echo "  Client: ${OUTPUT_DIR}/client.key, ${OUTPUT_DIR}/client.crt"
