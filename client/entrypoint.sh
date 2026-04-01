#!/usr/bin/env bash
#
# Test client entrypoint:
#  1. Install certificates from bind-mounted volume
#  2. Substitute SERVER_IP in swanctl config
#  3. Start strongSwan
#  4. Initiate IKEv2 tunnel
#  5. Configure DNS and routing
#  6. Keep container alive
#
set -euo pipefail

echo "=== prototype_net test client ==="

# --- Certificates ---
# Expect certs to be bind-mounted at /certs/
CERT_SRC="/certs"
if [ -d "$CERT_SRC" ]; then
    echo "Installing certificates from ${CERT_SRC}..."
    mkdir -p /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private
    cp "${CERT_SRC}/client.crt" /etc/swanctl/x509/client.crt
    cp "${CERT_SRC}/client.key" /etc/swanctl/private/client.key
    cp "${CERT_SRC}/ca.crt" /etc/swanctl/x509ca/ca.crt
    chmod 600 /etc/swanctl/private/client.key
else
    echo "WARNING: /certs/ not mounted — strongSwan may fail to authenticate"
fi

# --- Substitute SERVER_IP in swanctl config ---
SERVER_IP="${SERVER_IP:-}"
if [ -n "$SERVER_IP" ]; then
    echo "Configuring server address: ${SERVER_IP}"
    sed -i "s/%SERVER_IP%/${SERVER_IP}/g" /etc/swanctl/conf.d/prototype.conf
else
    echo "ERROR: SERVER_IP environment variable not set"
    exit 1
fi

# --- Start strongSwan ---
echo "Starting strongSwan..."
ipsec start
sleep 2

# Load all credentials and connections
swanctl --load-all
echo "strongSwan loaded."

# --- Initiate tunnel ---
echo "Initiating IKEv2 tunnel..."
swanctl --initiate --child prototype || {
    echo "WARNING: Tunnel initiation failed — retrying in 5s..."
    sleep 5
    swanctl --initiate --child prototype || echo "WARNING: Tunnel still failed"
}

# --- Wait for tunnel ---
echo "Waiting for tunnel to establish..."
for i in $(seq 1 30); do
    if swanctl --list-sas 2>/dev/null | grep -q "ESTABLISHED"; then
        echo "Tunnel established!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "WARNING: Tunnel did not establish within 30 seconds"
    fi
    sleep 1
done

# --- Configure DNS ---
DNS_SERVER="${DNS_SERVER:-}"
if [ -n "$DNS_SERVER" ]; then
    echo "Setting DNS server to ${DNS_SERVER}"
    echo "nameserver ${DNS_SERVER}" > /etc/resolv.conf
fi

# --- Add route for synthetic prefix ---
# In TUNNEL-in-UDP (NAT-T) mode strongSwan installs xfrm policies directly on
# the outbound interface rather than creating a named virtual interface.
# Find the interface that holds the default IPv4 route (used to reach the server)
# and add the fd00:abcd::/32 route on it so the kernel applies the xfrm policy.
OUTBOUND_IF=""
# Try xfrm/ipsec/vti named interfaces first (non-NAT-T kernels)
for iface in $(ip -6 route show 2>/dev/null | grep -o 'dev [^ ]*' | awk '{print $2}' | sort -u); do
    case "$iface" in
        xfrm*|ipsec*|vti*)
            OUTBOUND_IF="$iface"
            break
            ;;
    esac
done
# Fall back to the interface used for the default IPv4 route (NAT-T / TUNNEL-in-UDP)
if [ -z "$OUTBOUND_IF" ]; then
    OUTBOUND_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
fi

if [ -n "$OUTBOUND_IF" ]; then
    echo "Adding route for fd00:abcd::/32 via ${OUTBOUND_IF}"
    ip -6 route add fd00:abcd::/32 dev "$OUTBOUND_IF" 2>/dev/null || true
else
    echo "WARNING: Could not determine outbound interface — route not added"
    echo "  Available interfaces: $(ip link show | awk -F': ' '/^[0-9]+:/{print $2}')"
fi

echo ""
echo "=== Test client ready ==="
echo "  Try: curl -v https://google.com"
echo "  Try: curl -v https://youtube.com"
echo ""

# Keep the container alive
exec tail -f /dev/null
