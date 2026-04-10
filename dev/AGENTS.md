# dev/ -- Dev Tooling Scripts

This directory contains scripts and configuration for the local development environment.

## Contents

```
dev/
└── build-vm.yaml      # Lima VM config for building Linux binaries on macOS
```

## `build-vm.yaml` — Lima Build VM

A Lima VM configuration for building Linux x86_64 binaries on macOS. Lima provides a
lightweight QEMU-based VM with automatic directory mounts and SSH access.

The VM is used exclusively for compilation — the source directory is bind-mounted read-write
so edits on macOS are immediately visible inside the VM. All `make dev-*` targets delegate to
this VM via `limactl shell`.

Lifecycle:

```sh
make dev-up        # create + start (first run: ~3-5 min to download base image)
make dev-shell     # open interactive shell inside the VM
make dev-build     # build eBPF + userspace binaries inside the VM
make dev-down      # stop the VM (disk preserved)
make dev-destroy   # permanently delete the VM
```

## Dev-Mode — Build-Time Double-NAT for Testing

### The Problem

The proxy-source prefix (`2001:db8::/32`, configured in `contract.toml`) is a documentation
prefix (RFC 3849) — not globally routable. When `tc_ingress` rewrites the source address of
outbound packets to a `2001:db8::X` address, origin servers on the internet cannot route
replies back because no ISP forwards `2001:db8::/32` traffic.

### The Solution: Build-Time Dev-Mode

Dev-mode is now a **build-time Cargo feature** that enables double-NAT entirely in BPF:

1. **tc_ingress** rewrites src to the server's WAN IPv6 (instead of proxy-source)
2. **xdp_wan** detects reply packets, rewrites dst back to proxy-source, and redirects for
   normal processing by tc_ingress_wan

No veth pairs, ip6tables, policy routing, or environment variables needed.

### Building with Dev-Mode

```sh
# Build eBPF with dev-mode
make dev-build-ebpf-dev-mode
# OR: cargo xtask build-ebpf --dev-mode

# Build all binaries with dev-mode
make dev-build-dev-mode
# OR: cargo build -p daemon --features dev-mode --release
```

### How It Works

**OUTBOUND** (tc_ingress on xfrm0):
```
Production mode:
  src = client_vip → src = proxy_source (encoded)
  dst = synthetic  → dst = origin

Dev-mode:
  src = client_vip → src = WAN_IPV6 (auto-detected)
  dst = synthetic  → dst = origin
  REPLY_TRACK[(origin, ports)] = proxy_source  # track for reply handling
```

**REPLY** (xdp_wan on enp0s3):
```
Reply arrives: dst = WAN_IPV6, src = origin:443

  If REPLY_TRACK[(origin, ports)] found:
    Rewrite dst: WAN_IPV6 → proxy_source (no checksum update)
    Return XDP_PASS → kernel stack

  tc_ingress_wan picks up rewritten packet:
    dst = proxy_source → normal processing
    Compensating checksum update for the XDP rewrite
    Redirects to xfrm0
```

### Deployment

1. Build dev-mode binaries on the Lima VM
2. Copy to server VM: `make deploy-bins`
3. Restart daemon: `ssh ubuntu@$SERVER_VM_IP sudo systemctl restart prototype-daemon`

The daemon logs will show:
```
Dev-mode: set DEV_WAN_IPV6[0] = 2a01:xxxx:xxxx::xxxx (auto-detected from enp0s3)
```

### Switching Back to Production

```sh
# Build production binaries
make dev-build

# Deploy and restart
make deploy-bins
ssh ubuntu@$SERVER_VM_IP sudo systemctl restart prototype-daemon
```

Production builds have zero dev-mode overhead — the dev-mode code is not compiled in.

### BPF Maps (Dev-Mode Only)

| Map | Type | Purpose |
|:----|:-----|:--------|
| `DEV_WAN_IPV6` | Array[1] | Server's WAN IPv6 address (auto-detected) |
| `REPLY_TRACK` | HashMap | Tracks outbound connections for reply handling |
| `DBG_COUNTERS` | Array[8] | Debug counters for tracing xdp_wan decision paths |

Key: `(origin_ipv6, origin_port, translated_port, proto)`
Value: `proxy_source` address to restore in replies

In production, these maps don't exist — zero overhead.
