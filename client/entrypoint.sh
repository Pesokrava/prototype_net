#!/usr/bin/env bash
#
# Test client entrypoint:
#  1. Install certificates from bind-mounted volume
#  2. Substitute SERVER_IP in swanctl config
#  3. Start strongSwan
#  4. Initiate IKEv2 tunnel
#  5. Discover assigned VIP from server pool
#  6. Configure DNS and routing
#  7. Keep container alive
#
set -euo pipefail

echo "=== prototype_net test client ==="

# --- Certificates ---
# Expect certs to be bind-mounted at /certs/
CERT_SRC="/certs"
if [ -d "$CERT_SRC" ]; then
    echo "Installing certificates from ${CERT_SRC}..."
    mkdir -p /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private
    cp "${CERT_SRC}/client-test-client.crt" /etc/swanctl/x509/client.crt
    cp "${CERT_SRC}/client-test-client.key" /etc/swanctl/private/client.key
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

# --- Discover VIP assigned by server pool ---
# The server assigns a per-client IPv6 address from fd00:abcd:0:1::1:0-::ffff:ffff
# via IKEv2 Configuration Payload. Parse it from the established IKE_SA.
echo "Discovering assigned VIP from IKEv2 SA..."
ASSIGNED_VIP=""
for i in $(seq 1 10); do
    VIP_LINE=$(swanctl --list-sas 2>/dev/null | grep -m1 -E "local .*\[fd[0-9a-f:]+\]" || true)
    if [ -n "$VIP_LINE" ]; then
        ASSIGNED_VIP=$(echo "$VIP_LINE" | grep -oE 'fd[0-9a-f:]+' | head -1 || true)
    fi
    if [ -n "$ASSIGNED_VIP" ]; then
        echo "Assigned VIP: ${ASSIGNED_VIP}"
        break
    fi
    sleep 1
done

if [ -z "$ASSIGNED_VIP" ]; then
    echo "ERROR: Could not determine VIP assigned by server pool — cannot configure routing"
    exit 1
fi

# --- Configure DNS ---
DNS_SERVER="${DNS_SERVER:-}"
if [ -n "$DNS_SERVER" ]; then
    echo "Setting DNS server to ${DNS_SERVER}"
    echo "nameserver ${DNS_SERVER}" > /etc/resolv.conf
fi

# --- Restrict plain IPv4 egress ---
# Keep only a host route to the IPSec gateway so application traffic cannot
# escape over IPv4 when DNS returns A records.
if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IPV4_GW=$(ip route show default | awk '/default/ {print $3; exit}')
    if [ -z "$IPV4_GW" ]; then
        echo "ERROR: Could not determine IPv4 default gateway to pin SERVER_IP route"
        exit 1
    fi

    echo "Restricting plain IPv4 egress: allow only ${SERVER_IP}/32 via ${IPV4_GW}"
    ip route replace "${SERVER_IP}/32" via "$IPV4_GW" dev eth0
    ip route del default 2>/dev/null || true
fi

# --- Add route for synthetic prefix ---
# The tunnel uses NAT-T (ESP-in-UDP over IPv4). strongSwan installs XFRM
# policies that match fd00:abcd::/32 outbound traffic and encapsulate it.
# We need an IPv6 route so the kernel selects eth0 (which has the client's
# IPv6 address) as the outbound interface for the XFRM policy to fire.
echo "Ensuring client IPv6 address ${ASSIGNED_VIP} is on eth0..."
# Use /128 (host route only) so the kernel does NOT create an on-link
# fd00:abcd::/64 subnet route that would shadow the fd00:abcd::/32
# XFRM policy route and send synthetic traffic directly on-link.
ip -6 addr add "${ASSIGNED_VIP}/128" dev eth0 2>/dev/null || true

# --- Create XFRM interface for if_id=1 ---
# The swanctl config sets if_id_in/out = 1 on the CHILD_SA, which means the
# kernel uses XFRM interface if_id=1 for tunnel traffic. We must create a
# matching xfrm netdev so the kernel can route packets through the tunnel.
echo "Creating xfrm0 interface (if_id=1) on eth0..."
ip link del xfrm0 2>/dev/null || true
ip link add xfrm0 type xfrm if_id 1 dev eth0
ip link set xfrm0 up
ip -6 addr add "${ASSIGNED_VIP}/128" dev xfrm0 2>/dev/null || true

echo "Adding route for fd00:abcd::/32 via xfrm0"
ip -6 route replace fd00:abcd::/32 dev xfrm0 2>/dev/null || \
    ip -6 route add    fd00:abcd::/32 dev xfrm0 2>/dev/null || true

echo ""
echo "==> IPv6 addresses on eth0:"
ip -6 addr show dev eth0
echo "==> IPv6 routes:"
ip -6 route show

echo ""
echo "=== Test client ready ==="
echo "  Try: curl -v https://google.com"
echo "  Try: curl -v https://youtube.com"
echo ""

# Keep the container alive
exec tail -f /dev/null
