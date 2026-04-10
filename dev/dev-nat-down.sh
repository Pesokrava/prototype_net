#!/usr/bin/env bash
set -euo pipefail

# dev-nat-down.sh — Disable dev-mode for the prototype_net daemon
#
# Usage: sudo ./dev/dev-nat-down.sh
#
# This script is a NO-OP placeholder. Dev-mode is now a build-time feature.
#
# To disable dev-mode:
#   1. Build eBPF without dev-mode: cargo xtask build-ebpf
#   2. Build daemon without dev-mode: cargo build -p daemon --release
#   3. Deploy the production binaries to your server

echo "==> dev-nat-down.sh is a NO-OP"
echo ""
echo "Dev-mode is now a BUILD-TIME feature."
echo ""
echo "To disable dev-mode, deploy production binaries:"
echo "  1. Build eBPF: cargo xtask build-ebpf"
echo "  2. Build daemon: cargo build -p daemon --release"
echo ""
echo "Then restart the daemon with production binaries."
