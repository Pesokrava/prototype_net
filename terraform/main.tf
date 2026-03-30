terraform {
  required_version = ">= 1.5.0"
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.7"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}

# ---------------------------------------------------------------------------
# Ubuntu 24.04 cloud image
# ---------------------------------------------------------------------------

resource "libvirt_volume" "ubuntu_base" {
  name   = "${var.vm_name}-ubuntu-base.qcow2"
  pool   = "default"
  source = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
  format = "qcow2"
}

resource "libvirt_volume" "server_disk" {
  name           = "${var.vm_name}-disk.qcow2"
  pool           = "default"
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = 21474836480 # 20GB
}

# ---------------------------------------------------------------------------
# Cloud-init
# ---------------------------------------------------------------------------

resource "libvirt_cloudinit_disk" "server" {
  name = "${var.vm_name}-cloudinit.iso"
  pool = "default"

  user_data = templatefile("${path.module}/cloud-init/server.yaml", {
    host_bridge_ip    = var.host_bridge_ip
    postgres_password = var.postgres_password
    server_ipv6       = var.server_ipv6
    dns_listen_addr   = var.dns_listen_addr
  })
}

# ---------------------------------------------------------------------------
# VM definition
# ---------------------------------------------------------------------------

resource "libvirt_domain" "server" {
  name   = var.vm_name
  memory = 2048
  vcpu   = 2

  cloudinit = libvirt_cloudinit_disk.server.id

  disk {
    volume_id = libvirt_volume.server_disk.id
  }

  network_interface {
    network_name   = "default" # virbr0
    wait_for_lease = true
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  graphics {
    type        = "spice"
    listen_type = "address"
    autoport    = true
  }
}
