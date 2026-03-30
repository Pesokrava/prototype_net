# prototype_net

eBPF-based IPv6 NAT66 transparent proxy using synthetic DNS addresses, strongSwan IKEv2 tunnels, and Postgres-backed domain mapping.

## Architecture

```
Physical Linux Host
├── docker-compose.yml        — Postgres 16 + test client container
│     ├── postgres:16         — port 5432, accessible at 192.168.122.1:5432 from VM
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
5. eBPF TC ingress rewrites dst to real origin IPv6, src to server's public IPv6
6. Origin responds; eBPF TC egress rewrites src back to synthetic, dst to client
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
vim .env  # set POSTGRES_PASSWORD, SERVER_VM_IP, TF_VAR_*, INTERFACE_NAME, SERVER_IPV6
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

### 5. Build eBPF program

```bash
cargo xtask build-ebpf
```

### 6. Build userspace binaries

```bash
cargo build --release -p daemon -p dns-server
```

### 7. Deploy to VM

```bash
VM_IP=$(cd terraform && terraform output -raw vm_ip)

# Copy binaries
scp target/release/daemon target/release/dns-server ubuntu@${VM_IP}:/opt/prototype_net/

# Copy certificates
scp certs/output/ca.crt ubuntu@${VM_IP}:/etc/swanctl/x509ca/
scp certs/output/server.crt ubuntu@${VM_IP}:/etc/swanctl/x509/
scp certs/output/server.key ubuntu@${VM_IP}:/etc/swanctl/private/

# Start services
ssh ubuntu@${VM_IP} 'sudo systemctl restart strongswan-starter prototype-daemon prototype-dns-server'
```

### 8. Start test client

```bash
docker compose up -d client
```

### 9. Test

```bash
docker exec -it prototype-client curl -v https://google.com
docker exec -it prototype-client curl -v https://youtube.com
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `POSTGRES_PASSWORD` | Postgres password | (required) |
| `SERVER_VM_IP` | Server VM IP address | (required) |
| `TF_VAR_host_bridge_ip` | Host bridge IP (virbr0) | `192.168.122.1` |
| `TF_VAR_postgres_password` | Postgres password for Terraform | (required) |
| `TF_VAR_server_ipv6` | Static IPv6 for server VM | (required) |
| `TF_VAR_dns_listen_addr` | DNS server bind address | `0.0.0.0` |
| `INTERFACE_NAME` | Tunnel interface for eBPF TC | (required) |
| `SERVER_IPV6` | Server's public IPv6 (NAT src) | (required) |
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
