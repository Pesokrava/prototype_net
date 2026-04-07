#!/usr/bin/env bash
#
# Generate CA and server certificates for strongSwan IKEv2.
# Idempotent: skips CA generation if ca.crt already exists.
#
# Usage: ./gen-ca-server.sh <SERVER_IP>
#
# Output: certs/output/{ca,server}.{key,crt}
#
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <SERVER_IP>"
    echo "  SERVER_IP: IP address or hostname of the server VM (used as CN/SAN for server cert)"
    exit 1
fi

SERVER_IP="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
SERIAL_FILE="${OUTPUT_DIR}/ca.srl"

mkdir -p "${OUTPUT_DIR}"

# --- CA ---
if [ -f "${OUTPUT_DIR}/ca.crt" ] && [ -f "${OUTPUT_DIR}/ca.key" ]; then
    echo "=== CA already exists — skipping CA generation ==="
else
    echo "=== Generating CA key and certificate ==="
    rm -f "${SERIAL_FILE}"

    openssl genrsa -out "${OUTPUT_DIR}/ca.key" 4096

    cat > "${OUTPUT_DIR}/ca_ext.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = prototype-net-ca

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

    openssl req -x509 -new -nodes \
        -key "${OUTPUT_DIR}/ca.key" \
        -sha256 \
        -days 3650 \
        -out "${OUTPUT_DIR}/ca.crt" \
        -config "${OUTPUT_DIR}/ca_ext.cnf" \
        -extensions v3_ca

    rm -f "${OUTPUT_DIR}/ca_ext.cnf"
fi

# --- Server ---
echo "=== Generating server key and certificate ==="
openssl genrsa -out "${OUTPUT_DIR}/server.key" 4096
openssl req -new \
    -key "${OUTPUT_DIR}/server.key" \
    -out "${OUTPUT_DIR}/server.csr" \
    -subj "/CN=${SERVER_IP}"

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
    -CAserial "${SERIAL_FILE}" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/server.crt" \
    -days 365 \
    -sha256 \
    -extfile "${OUTPUT_DIR}/server_ext.cnf"

rm -f "${OUTPUT_DIR}/server.csr" "${OUTPUT_DIR}/server_ext.cnf"

echo ""
echo "=== CA + server certificates ready ==="
echo "  CA:     ${OUTPUT_DIR}/ca.crt"
echo "  Server: ${OUTPUT_DIR}/server.crt"
