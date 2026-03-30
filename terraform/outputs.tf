output "vm_ip" {
  description = "IPv4 address of the server VM (assigned by libvirt DHCP)"
  value       = libvirt_domain.server.network_interface[0].addresses[0]
}

output "ssh_command" {
  description = "SSH command to connect to the server VM"
  value       = "ssh ubuntu@${libvirt_domain.server.network_interface[0].addresses[0]}"
}
