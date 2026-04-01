terraform {
  required_version = ">= 1.5.0"
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.9"
    }
  }
}

provider "libvirt" {
  uri = var.libvirt_uri
}

locals {
  cloudinit_network_config = <<-EOT
    version: 2
    ethernets:
      enp0s3:
        dhcp4: true
  EOT

  cloudinit_user_data = templatefile("${path.module}/cloud-init/server.yaml", {
    ssh_public_key = var.ssh_public_key
  })

  cloudinit_hash        = substr(sha1("${local.cloudinit_network_config}\n---\n${local.cloudinit_user_data}"), 0, 12)
  cloudinit_volume_name = "${var.vm_name}-cloudinit-${local.cloudinit_hash}.iso"
}

# ---------------------------------------------------------------------------
# Ubuntu 24.04 cloud image
# ---------------------------------------------------------------------------

resource "libvirt_volume" "ubuntu_base" {
  name = "${var.vm_name}-ubuntu-base.qcow2"
  pool = "default"

  create = {
    content = {
      url = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
    }
  }

  target = {
    format = {
      type = "qcow2"
    }
  }
}

resource "libvirt_volume" "server_disk" {
  name     = "${var.vm_name}-disk.qcow2"
  pool     = "default"
  capacity = 21474836480 # 20GB

  target = {
    format = {
      type = "qcow2"
    }
  }

  backing_store = {
    path = libvirt_volume.ubuntu_base.path
    format = {
      type = "qcow2"
    }
  }
}

# ---------------------------------------------------------------------------
# Cloud-init
# ---------------------------------------------------------------------------

resource "libvirt_cloudinit_disk" "server" {
  name      = local.cloudinit_volume_name
  meta_data = ""

  network_config = local.cloudinit_network_config

  user_data = local.cloudinit_user_data
}

resource "libvirt_volume" "server_cloudinit_iso" {
  name = local.cloudinit_volume_name
  pool = "default"

  target = {
    format = {
      type = "iso"
    }
  }

  create = {
    content = {
      url = libvirt_cloudinit_disk.server.path
    }
  }
}

# ---------------------------------------------------------------------------
# VM definition
# ---------------------------------------------------------------------------

resource "libvirt_domain" "server" {
  name        = var.vm_name
  type        = "kvm"
  memory      = 2048
  memory_unit = "MiB"
  vcpu        = 2

  os = {
    type = "hvm"
  }

  devices = {
    disks = [
      {
        device = "disk"
        driver = {
          name = "qemu"
          type = "qcow2"
        }
        source = {
          volume = {
            pool   = "default"
            volume = libvirt_volume.server_disk.name
          }
        }
        target = {
          bus = "virtio"
          dev = "vda"
        }
      },
      {
        device = "cdrom"
        source = {
          volume = {
            pool   = "default"
            volume = local.cloudinit_volume_name
          }
        }
        target = {
          bus = "sata"
          dev = "sda"
        }
      }
    ]

    interfaces = [
      {
        model = {
          type = "virtio"
        }
        source = {
          network = var.vm_bridge_name == "" ? {
            network = var.vm_network_name
          } : null
          bridge = var.vm_bridge_name != "" ? {
            bridge = var.vm_bridge_name
          } : null
        }
      }
    ]

    channels = [
      {
        source = {
          unix = {}
        }
        target = {
          virt_io = {
            name = "org.qemu.guest_agent.0"
          }
        }
      }
    ]

    consoles = [
      {
        target = {
          type = "serial"
          port = 0
        }
      }
    ]

    graphics = [
      {
        spice = {
          auto_port = true
          listen    = "127.0.0.1"
        }
      }
    ]
  }
}
