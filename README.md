# prototype_net

eBPF-based IPv6 NAT66 transparent proxy using synthetic DNS addresses, strongSwan IKEv2 tunnels, and Postgres-backed domain mapping.

## Architecture

```
Physical Linux Host
├── docker-compose.yml        — Postgres 18 + test client container
│     ├── postgres:18         — port 5432, accessible at 192.168.122.1:5432 from VM
│     └── test-client         — Ubuntu 24.04, strongSwan, curl
│
└── libvirt/KVM (virbr0 bridge, host IP 192.168.122.1)
      └── Server VM (Ubuntu 24.04)
            ├── strongSwan (IKEv2 IPSec endpoint)
            ├── daemon binary      — loads eBPF TC programs, syncs BPF maps from Postgres
            └── dns-server binary  — synthetic AAAA responder, writes domain mappings to Postgres
```

### Data Flow

1. Test client queries DNS for `google.com` (AAAA)
2. DNS server resolves upstream AAAA, mints a synthetic `fd00:abcd:XXXX:YYYY::1` address, stores mapping in Postgres
3. Postgres NOTIFY triggers daemon to populate BPF maps
4. Client sends traffic to synthetic address through IPSec tunnel
5. eBPF `tc_ingress` on `xfrm0` rewrites dst to real origin IPv6, src to server's public IPv6
6. Origin responds; eBPF `tc_ingress_wan` on `enp0s3` rewrites src back to synthetic, dst to client, redirects to `xfrm0` for IPSec re-encapsulation
7. Client receives response transparently

### IPv6 Address Layout

```
fd00:abcd:XXXX:YYYY::1
          └─────────┘
          domain_id (u32) encoded in bytes [4..8]
```

## Prerequisites

- **Rust**: stable 1.87.0+ and nightly (for eBPF cross-compilation)
- **bpf-linker**: `cargo install bpf-linker`
- **Docker + Docker Compose**: for Postgres and test client
- **Terraform**: for VM provisioning
- **libvirt/KVM**: with `virbr0` bridge network
- **openssl**: for certificate generation

## Setup

### 1. Configure environment

```bash
cp .env.example .env
vim .env  # set POSTGRES_PASSWORD, SERVER_VM_IP, TF_VAR_*, INTERFACE_NAME, SERVER_IPV6, CLIENT_IPV6
```

### 2. Start Postgres

```bash
docker compose up -d postgres
```

### 3. Generate certificates

```bash
./certs/gen-certs.sh <SERVER_VM_IP>
```

### 4. Provision VM with Terraform

```bash
cd terraform
terraform init
terraform apply
cd ..
```

### 5. Build binaries (inside Lima build VM)

```bash
make dev-up        # create Lima x86_64 build VM (first time only)
make dev-build     # build eBPF + daemon + dns-server
```

### 6. Deploy to VM

```bash
make deploy        # SCP binaries + certs + push systemd units, restart services
```

> `make deploy` pushes binaries, certificates, and systemd unit files.
> Changes to sysctl, packages, or strongSwan config require a full re-provision:
> `make vm-provision`

### 7. Start test client

```bash
make client-up
```

### 8. Test

```bash
make test
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `POSTGRES_PASSWORD` | Postgres password | (required) |
| `SERVER_VM_IP` | Server VM IP address | (required) |
| `TF_VAR_host_bridge_ip` | Host bridge IP (virbr0) | `192.168.122.1` |
| `TF_VAR_postgres_password` | Postgres password for Terraform/Ansible | (required) |
| `TF_VAR_server_ipv6` | Static IPv6 for server VM | (required) |
| `TF_VAR_dns_listen_addr` | DNS server bind address | `0.0.0.0` |
| `INTERFACE_NAME` | Tunnel interface for `tc_ingress` (e.g. `xfrm0`) | (required) |
| `WAN_INTERFACE` | WAN interface for `tc_ingress_wan` (e.g. `enp0s3`) | (required) |
| `SERVER_IPV6` | Server's public IPv6 (NAT src) | (required) |
| `CLIENT_IPV6` | VPN client's IPv6 (IKEv2 traffic selector) | (required) |
| `DATABASE_URL` | Postgres connection string | (derived) |

## Project Structure

```
prototype_net/
├── Cargo.toml                 # workspace: common, daemon, dns-server, xtask
├── rust-toolchain.toml        # stable toolchain
├── docker-compose.yml         # Postgres + test client
├── migrations/                # Postgres schema
├── common/                    # shared #[repr(C)] BPF map types (no_std)
├── ebpf/                      # TC ingress/egress NAT66 programs (nightly, bpfel-unknown-none)
├── daemon/                    # eBPF loader, BPF map sync, Postgres LISTEN
├── dns-server/                # synthetic AAAA DNS responder
├── xtask/                     # build-ebpf cross-compilation helper
├── certs/                     # CA + cert generation script
├── strongswan/                # server-side IKEv2 config
├── client/                    # Docker test client (strongSwan + curl)
└── terraform/                 # libvirt VM provisioning + cloud-init
```

## Limitations (v1)

- No device signature in IPv6 bits
- No whitelist enforcement (all AAAA-capable domains accepted)
- No ICMP error translation
- No fragmentation handling
- No per-client policy enforcement
- No client agent automation (macOS/Windows)
- Single VM only (no HA)
- No admin API for domain management
