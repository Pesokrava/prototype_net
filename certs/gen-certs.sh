#!/usr/bin/env bash
#
# Generate CA + server + test-client certificates for strongSwan IKEv2.
#
# Usage: ./gen-certs.sh <SERVER_IP>
#
# For additional clients use gen-client.sh directly:
#   ./gen-client.sh <CLIENT_ID>
#
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <SERVER_IP>"
    echo "  SERVER_IP: IP address or hostname of the server VM"
    exit 1
fi

SERVER_IP="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"${SCRIPT_DIR}/gen-ca-server.sh" "${SERVER_IP}"
"${SCRIPT_DIR}/gen-client.sh" "test-client"

echo ""
echo "=== All certificates generated ==="
echo "  To generate additional client certs:"
echo "    ./certs/gen-client.sh <CLIENT_ID>"

