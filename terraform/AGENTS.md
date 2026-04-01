# terraform/ -- Infrastructure Provisioning

This directory contains Terraform configuration for provisioning the server VM on a local libvirt/KVM hypervisor. Cloud-init is minimal — only user creation and SSH key injection. All software provisioning is done by Ansible (`ansible/`).

## Resources Defined (`main.tf`)

- **`libvirt_volume.ubuntu_base`** -- Downloads the Ubuntu 24.04 cloud image.
- **`libvirt_volume.server_disk`** -- 20GB qcow2 overlay disk backed by the base image.
- **`libvirt_cloudinit_disk.server`** -- Cloud-init ISO with user+SSH key only.
- **`libvirt_domain.server`** -- VM definition: 2 vCPU, 2048MB RAM, br0 bridge network, serial console, SPICE graphics.

## Cloud-Init (`cloud-init/server.yaml`)

Intentionally minimal — only creates the `ubuntu` user with sudo and injects the SSH public key. The base image's built-in netplan config handles DHCP. All packages, sysctl, and services are managed by Ansible.

## Variables (`variables.tf`)

- `vm_name` -- VM name (default: "prototype-net-server").
- `vm_bridge_name` -- Host bridge interface (e.g. `br0`). Leave empty to use libvirt NAT.
- `vm_network_name` -- Libvirt network name when not using a bridge (default: "default").
- `ssh_public_key` -- SSH public key injected into the ubuntu user.

## Workflow

```
make vm-up          # Terraform: create VM
# find IP: virsh -c qemu:///system domifaddr prototype-net-server
# set SERVER_VM_IP in .env
make vm-provision   # Ansible: install packages, services, sysctl
make certs          # generate TLS certs
make dev-build      # build binaries
make deploy         # scp binaries + certs, restart services
```

## Conventions

- Uses `dmacvicar/libvirt` Terraform provider (~> 0.9).
- Only `ssh_public_key` is passed as a templatefile variable — everything else goes to Ansible.
- All variables can be set via `TF_VAR_*` environment variables.
