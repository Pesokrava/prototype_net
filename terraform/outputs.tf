output "vm_ip" {
  description = "IPv4 address of the server VM — run: virsh domifaddr --source agent $(terraform output -raw vm_name)"
  value       = "run: virsh domifaddr --source agent ${libvirt_domain.server.name}"
}

output "vm_name" {
  description = "Libvirt domain name"
  value       = libvirt_domain.server.name
}

output "ssh_command" {
  description = "SSH command template — replace <IP> with the address from 'virsh domifaddr --source agent'"
  value       = "ssh ubuntu@$(virsh domifaddr --source agent ${libvirt_domain.server.name} | awk '/ipv4/{print $4}' | cut -d/ -f1)"
}
