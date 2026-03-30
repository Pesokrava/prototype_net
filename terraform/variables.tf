variable "vm_name" {
  description = "Name of the libvirt VM"
  type        = string
  default     = "prototype-net-server"
}

variable "host_bridge_ip" {
  description = "IP address of the host on the virbr0 bridge (verify with: ip addr show virbr0)"
  type        = string
  default     = "192.168.122.1"
}

variable "postgres_password" {
  description = "Postgres password (must match POSTGRES_PASSWORD in .env / docker-compose)"
  type        = string
  sensitive   = true
}

variable "server_ipv6" {
  description = "Static IPv6 address to assign to the server VM"
  type        = string
}

variable "dns_listen_addr" {
  description = "IP address the DNS server binds to inside the VM"
  type        = string
  default     = "0.0.0.0"
}
