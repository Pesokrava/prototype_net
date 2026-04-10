#!/usr/bin/env bash
set -euo pipefail

# dev-nat-up.sh — Enable dev-mode for the prototype_net daemon
#
# Usage: sudo ./dev/dev-nat-up.sh
#
# This script is a NO-OP placeholder. Dev-mode is now a build-time feature.
#
# To use dev-mode:
#   1. Build eBPF with dev-mode: cargo xtask build-ebpf --dev-mode
#   2. Build daemon with dev-mode: cargo build -p daemon --features dev-mode
#   3. Deploy and run the daemon - it will auto-detect WAN IPv6 and enable double-NAT
#
# In dev-mode:
#   - tc_ingress uses server's WAN IPv6 as source (instead of proxy-source)
#   - xdp_wan rewrites reply packets back to proxy-source for normal processing
#   - No veth pairs, ip6tables, or policy routing needed

echo "==> dev-nat-up.sh is a NO-OP"
echo ""
echo "Dev-mode is now a BUILD-TIME feature."
echo ""
echo "To use dev-mode:"
echo "  1. Build eBPF: cargo xtask build-ebpf --dev-mode"
echo "  2. Build daemon: cargo build -p daemon --features dev-mode --release"
echo "  3. Deploy the dev-mode binaries to your server"
echo ""
echo "The daemon will auto-detect the WAN IPv6 address."
