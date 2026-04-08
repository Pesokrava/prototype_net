# prototype_net

eBPF-based IPv6 NAT66 transparent proxy using synthetic DNS AAAA records, strongSwan IKEv2, and Postgres-backed domain mappings.

## What this project does

`prototype_net` transparently proxies IPv6 traffic through an IPSec tunnel in two phases:

1. DNS phase
   - Client asks for `AAAA`.
   - `dns-server` resolves upstream IPv6, allocates a synthetic address in `fd00:abcd::/32`, stores mapping in Postgres.
   - Postgres trigger emits `NOTIFY domain_changes`.

2. Data-plane phase
   - Client sends traffic to synthetic destination via IPSec.
   - eBPF on `xfrm0` and WAN ingress rewrites IPv6 addresses in-kernel.
   - Reply traffic is decoded and routed back to the correct client without per-flow userspace state.

## Current architecture (important updates)

- Multi-client is supported via strongSwan VIP pool assignment (no static `CLIENT_IPV6` wiring).
- The data plane uses stateless proxy-source address encoding.
- `daemon` manages `NAT_MAP` (domain_id -> origin IPv6) plus `XFRM_IFINDEX`; legacy reverse/flow map wiring is gone.
- Server strongSwan config is rendered from Ansible template (`ansible/roles/prototype_net/templates/swanctl.conf.j2`).

Packet path:

```text
Client DNS query -> dns-server -> Postgres domains table
                                 -> NOTIFY domain_changes -> daemon updates NAT_MAP

Client packet (to fd00:abcd::/32) -> IPSec -> xfrm0 ingress tc_ingress
  tc_ingress: dst synthetic -> origin, src -> proxy_src(client_id, domain_id)

Origin reply -> WAN ingress xdp_wan (prefix filter) -> tc_ingress_wan
  tc_ingress_wan: decode client_id/domain_id from dst, verify src via NAT_MAP,
                  rewrite src -> synthetic, dst -> client VIP, redirect to xfrm0
```

## Single source of truth

Address-space constants live in `contract.toml`:

- synthetic prefix (`fd00:abcd::/32`)
- VIP pool discriminator and range
- XFRM `if_id`

Validation command:

```bash
cargo xtask verify-contract
```

In normal workflows this is already enforced by `make dev-build`.

## Repository layout

- `common/` shared `no_std` map/value types and address helpers
- `ebpf/` XDP + TC programs (`xdp_wan`, `tc_ingress`, `tc_ingress_wan`)
- `daemon/` eBPF loader + Postgres LISTEN/NOTIFY sync + periodic re-resolve
- `dns-server/` synthetic AAAA DNS server
- `xtask/` `build-ebpf` and `verify-contract`
- `ansible/` server provisioning and systemd templates
- `terraform/` libvirt VM provisioning
- `client/` Docker strongSwan test client
- `certs/` CA/server/client certificate generation

## Prerequisites

For development and testing, you need both tooling and a VM-capable Linux environment.

- Control machine (where you run `make`):
  - `make`, `git`, `ssh`, `scp`
  - Rust stable + nightly
  - `bpf-linker` (`cargo install bpf-linker`)
  - OpenSSL
  - Terraform CLI
  - Ansible (`ansible-playbook`)
- Linux virtualization host for server VM testing:
  - Linux machine with `libvirtd` + KVM/QEMU
  - a usable libvirt URI (`qemu:///system` locally, or remote `qemu+sshcmd://...`)
  - bridge interface configured (or libvirt NAT network `default`)
- Container runtime host (for Postgres + test client):
  - Docker Engine + Docker Compose plugin
  - IPv6 enabled for Docker networking
- macOS-specific note:
  - if building Linux binaries from macOS, use Lima (`limactl`) because Makefile build targets run inside a Linux x86_64 VM (it's just easier than getting shit on by the cross compilation)

## Full setup guide (including test client)

This flow uses the built-in Docker test client in `client/`.

### 1) Create `.env`

```bash
cp .env.example .env
```

Fill at least these values:

- `POSTGRES_PASSWORD`
- `TF_VAR_vm_bridge_name` (or leave empty to use `TF_VAR_vm_network_name=default`)
- `TF_VAR_libvirt_uri`
- `TF_VAR_ssh_public_key` (from `ssh-add -L`)
- `TF_VAR_host_bridge_ip`
- `TF_VAR_postgres_password` (must exactly match `POSTGRES_PASSWORD`)
- `TF_VAR_dns_listen_addr` (usually `0.0.0.0`)

Set these after VM creation:

- `SERVER_VM_IP`
- `TF_VAR_server_ipv6`

### 2) Start Postgres
This depends on where you want to run the postgres( I run it on the linux host)

```bash
make postgres-up
```

### 3) Bring up server VM

```bash
make vm-up
```

Find VM IP (example with local libvirt):

```bash
virsh -c qemu:///system domifaddr --source agent prototype-net-server
```

Set `SERVER_VM_IP` in `.env`.

### 4) Get server global IPv6 and finish env

Use the Makefile SSH helper:

```bash
make vm-ssh
```

Then inside the VM shell run:

```bash
ip -6 addr show scope global
```

Set `TF_VAR_server_ipv6` in `.env`.

### 5) Provision VM (packages, strongSwan config, systemd units)

```bash
make vm-provision
```

### 6) Generate certs

```bash
make certs
```

This creates CA + server certs and default test client certs under `certs/output/`.

### 7) Build binaries

```bash
make dev-up
make dev-build
```

`make dev-build` runs in the Lima VM and builds eBPF + userspace binaries.

### 8) Deploy binaries, certs, and units

```bash
make deploy
```

### 9) Start test client container

Linux host:

```bash
make client-up
```

macOS convenience alias:

```bash
make client-up-mac
```

The client will:

- establish IKEv2 tunnel
- request VIP dynamically (`vips = 0::0`)
- discover assigned VIP from strongSwan
- create `xfrm0` with matching `if_id`
- route synthetic prefix traffic via `xfrm0`

### 10) Run end-to-end tests

```bash
make test
```

This performs DNS + HTTPS tests from inside the test client and dumps `NAT_MAP` from VM.

## Useful operational commands

```bash
make status
make logs-daemon
make logs-dns
make client-down
make postgres-down
```

## Verification (Makefile-first)

Primary end-to-end validation:

```bash
make test
```

Extra checks:

```bash
make status
make logs-daemon
make logs-dns
```

If you need interactive low-level checks from the client container, use:

```bash
docker compose exec client swanctl --list-sas
docker compose exec client dig AAAA google.com +short
docker compose exec client curl -6 -sv --max-time 15 https://google.com
```

## Multi-client certificates

Generate additional client certificate + bundle:

```bash
make client-cert CLIENT_ID=macbook-alice
```

Outputs:

- `certs/output/client-macbook-alice.crt`
- `certs/output/client-macbook-alice.key`
- `certs/output/client-bundle-macbook-alice.json`

The bundle contains private key material; treat it as a secret.

## Troubleshooting notes

- If VM WAN interface is not `enp0s3`, update relevant Ansible systemd templates before provisioning/deploy.
- After editing any `contract.toml`-derived config, run `cargo xtask verify-contract`.
- If strongSwan config or other non-unit provisioning changed, rerun `make vm-provision` (not just `make deploy-units`).
