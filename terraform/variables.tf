variable "vm_name" {
  description = "Name of the libvirt VM"
  type        = string
  default     = "prototype-net-server"
}

variable "libvirt_uri" {
  description = "Libvirt connection URI (for example: qemu:///system, qemu+sshcmd://host/system, or qemu+ssh://user@host/system)"
  type        = string
  default     = "qemu:///system"
}

variable "vm_bridge_name" {
  description = "Host bridge interface the VM NIC attaches to (e.g. br0). Required for bridged networking. Leave empty to use vm_network_name instead."
  type        = string
  default     = ""
}

variable "vm_network_name" {
  description = "Libvirt network name when not using a bridge (default libvirt NAT network). Ignored when vm_bridge_name is set."
  type        = string
  default     = "default"
}

variable "ssh_public_key" {
  description = "SSH public key injected into the ubuntu user. Must be the full public key string (from ssh-add -L), not a file path."
  type        = string
}
