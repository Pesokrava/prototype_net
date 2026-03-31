# terraform/ -- Infrastructure Provisioning

This directory contains Terraform configuration for provisioning the server VM on a local libvirt/KVM hypervisor. It uses cloud-init for automated VM setup.

## Resources Defined (`main.tf`)

- **`libvirt_volume.ubuntu_base`** -- Downloads the Ubuntu 24.04 cloud image.
- **`libvirt_volume.server_disk`** -- 20GB disk based on the Ubuntu image.
- **`libvirt_cloudinit_disk.server`** -- Cloud-init ISO generated from `cloud-init/server.yaml`.
- **`libvirt_domain.server`** -- VM definition: 2 vCPU, 2048MB RAM, virbr0 network, serial console, SPICE graphics.

## Cloud-Init (`cloud-init/server.yaml`)

The cloud-init template:
- Installs packages: strongSwan, bpftool, curl, iproute2, net-tools.
- Configures sysctl for IPv6 forwarding.
- Writes strongSwan IKEv2 server config.
- Creates two systemd services: `prototype-daemon.service` and `prototype-dns-server.service`.
- Passes configuration via env vars: `DATABASE_URL`, `INTERFACE_NAME`, `SERVER_IPV6`, `LISTEN_ADDR`.
- Note: Binaries and certs must be SCP'd to the VM after creation.

## Variables (`variables.tf`)

- `vm_name` -- VM name (default: "prototype-net-server").
- `host_bridge_ip` -- Host bridge IP for Postgres access (default: "192.168.122.1").
- `postgres_password` -- Postgres password (sensitive).
- `server_ipv6` -- Server's public IPv6 address.
- `dns_listen_addr` -- DNS server bind address (default: "0.0.0.0").

## Outputs (`outputs.tf`)

- `vm_ip` -- DHCP-assigned IPv4 address.
- `ssh_command` -- Ready-to-use SSH command.

## Conventions

- Uses `dmacvicar/libvirt` Terraform provider (v0.7+).
- `templatefile()` for injecting variables into cloud-init YAML.
- Sensitive variables are marked appropriately.
- All variables can be set via `TF_VAR_*` environment variables.
- The VM accesses host Postgres over the virbr0 bridge (192.168.122.1:5432).
