# prototype_net Makefile
#
# Binaries are built inside a Lima x86_64 VM (dev/build-vm.yaml).
# Source is mounted from macOS — edit here, build in the VM.
# Runtime infrastructure (server VM, Postgres, test client) lives on the Linux host.
#
# Usage:
#   make help          — list all targets
#   make dev-up        — create + start the Lima build VM (first run: ~3-5 min)
#   make dev-shell     — open a shell inside the build VM
#   make dev-build     — build eBPF + daemon + dns-server inside the VM
#   make dev-build-ebpf — build only eBPF inside the VM
#   make dev-down      — stop the build VM (disk preserved)
#   make dev-destroy   — permanently delete the build VM
#   make certs         — generate TLS certificates
#   make vm-up         — provision server VM with Terraform
#   make vm-ip         — print the VM IP
#   make postgres-up   — start Postgres on the Linux host via docker compose
#   make deploy        — copy binaries + certs to VM, restart services
#   make client-up     — start the test client container
#   make test          — run end-to-end curl tests
#   make status        — show service status on the VM
#   make logs-daemon   — tail daemon logs on the VM
#   make logs-dns      — tail dns-server logs on the VM
#   make vm-down       — destroy the server VM
#   make clean         — remove cargo build artifacts (target/)
#   make clean-certs   — remove generated certificates (certs/output/)
#   make clean-all     — clean + destroy VMs + wipe Docker volumes

# ---------------------------------------------------------------------------
# Load .env if it exists
# ---------------------------------------------------------------------------

-include .env
export

# ---------------------------------------------------------------------------
# Derived values
# ---------------------------------------------------------------------------

VM_IP          ?= $(SERVER_VM_IP)
LINUX_TARGET    = x86_64-unknown-linux-gnu
RELEASE_DIR     = target/$(LINUX_TARGET)/release
CERT_DIR        = certs/output
TERRAFORM_DIR   = terraform
SSH             = ssh -o StrictHostKeyChecking=no ubuntu@$(VM_IP)
SCP             = scp -o StrictHostKeyChecking=no

# Lima build VM
DEV_VM_NAME     = prototype-net-build
DEV_VM_YAML     = dev/build-vm.yaml
# Run a command inside the Lima VM as the current user
LIMA            = limactl shell $(DEV_VM_NAME)

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------

.PHONY: help dev-up dev-shell dev-build dev-build-ebpf dev-down dev-destroy \
        certs \
        vm-up vm-provision vm-ip vm-down vm-ssh \
        postgres-up postgres-down \
        deploy deploy-bins deploy-certs \
        client-up client-up-mac client-down \
        test status logs-daemon logs-dns \
        clean clean-certs clean-all

# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------

help:
	@echo ""
	@echo "prototype_net — available targets"
	@echo ""
	@echo "  Lima build VM  (x86_64 Ubuntu, builds Linux binaries natively)"
	@echo "    dev-up         Create + start the Lima build VM"
	@echo "    dev-shell      Open an interactive shell inside the build VM"
	@echo "    dev-build      Build eBPF + daemon + dns-server inside the VM"
	@echo "    dev-build-ebpf Build only eBPF inside the VM"
	@echo "    dev-down       Stop the build VM (disk preserved)"
	@echo "    dev-destroy    Permanently delete the build VM"
	@echo ""
	@echo "  Certificates  (runs on macOS)"
	@echo "    certs          Generate TLS certificates  (requires SERVER_VM_IP in .env)"
	@echo ""
	@echo "  Server VM  (Terraform from local machine)"
	@echo "    vm-up          Provision server VM with Terraform"
	@echo "    vm-provision   Run Ansible to install packages + services on VM"
	@echo "    vm-ip          Print the VM IP"
	@echo "    vm-ssh         Open SSH session to server VM"
	@echo "    vm-down        Destroy the server VM"
	@echo ""
	@echo "  Postgres  (docker compose on Linux host)"
	@echo "    postgres-up    Start Postgres"
	@echo "    postgres-down  Stop Postgres"
	@echo ""
	@echo "  Deploy"
	@echo "    deploy         deploy-bins + deploy-certs + restart services"
	@echo "    deploy-bins    SCP daemon + dns-server to server VM"
	@echo "    deploy-certs   SCP TLS certs to server VM"
	@echo ""
	@echo "  Test"
	@echo "    client-up      Start the test client container"
	@echo "    client-up-mac  Start the test client container (macOS, no local Postgres)"
	@echo "    client-down    Stop the test client container"
	@echo "    test           Run end-to-end curl tests"
	@echo ""
	@echo "  Observe"
	@echo "    status         Show systemd service status on server VM"
	@echo "    logs-daemon    Tail prototype-daemon logs on server VM"
	@echo "    logs-dns       Tail prototype-dns-server logs on server VM"
	@echo ""
	@echo "  Clean"
	@echo "    clean          Remove cargo build artifacts (target/)"
	@echo "    clean-certs    Remove generated certificates (certs/output/)"
	@echo "    clean-all      Everything above + destroy VMs + wipe Docker volumes"
	@echo ""

# ---------------------------------------------------------------------------
# Lima build VM
# ---------------------------------------------------------------------------

# REPO_PATH is the absolute path of this repo as seen inside the Lima VM.
# Lima mounts ~ at the same absolute path, so this just works.
REPO_PATH = $(CURDIR)

dev-up:
	@echo "==> Starting Lima build VM '$(DEV_VM_NAME)'..."
	limactl start --name=$(DEV_VM_NAME) $(DEV_VM_YAML)
	@echo ""
	@echo "==> Build VM ready. Run: make dev-build"

dev-shell:
	$(LIMA)

dev-build:
	@echo "==> Building inside Lima VM '$(DEV_VM_NAME)'..."
	$(LIMA) bash -c 'cd $(REPO_PATH) && \
		source $$HOME/.cargo/env && \
		echo "--- eBPF ---" && \
		cargo xtask build-ebpf && \
		echo "--- userspace binaries (x86_64-unknown-linux-gnu) ---" && \
		cargo build --release -p daemon -p dns-server --target $(LINUX_TARGET) && \
		echo "" && \
		echo "==> Build complete:" && \
		ls -lh $(REPO_PATH)/$(RELEASE_DIR)/daemon $(REPO_PATH)/$(RELEASE_DIR)/dns-server'

dev-build-ebpf:
	@echo "==> Building eBPF inside Lima VM '$(DEV_VM_NAME)'..."
	$(LIMA) bash -c 'cd $(REPO_PATH) && \
		source $$HOME/.cargo/env && \
		cargo xtask build-ebpf'
	@echo "==> eBPF build complete."

dev-down:
	@echo "==> Stopping Lima build VM '$(DEV_VM_NAME)'..."
	limactl stop $(DEV_VM_NAME)

dev-destroy:
	@echo "==> Deleting Lima build VM '$(DEV_VM_NAME)'..."
	limactl delete --force $(DEV_VM_NAME)

# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

certs:
	$(call require,SERVER_VM_IP)
	@echo "==> Generating TLS certificates for $(SERVER_VM_IP)..."
	./certs/gen-certs.sh $(SERVER_VM_IP)

# ---------------------------------------------------------------------------
# VM
# ---------------------------------------------------------------------------

vm-up:
	@KEY='$(TF_VAR_ssh_public_key)'; \
	if [ -z "$$KEY" ]; then \
		echo "ERROR: TF_VAR_ssh_public_key is empty."; \
		echo "Set it from your agent: ssh-add -L"; \
		exit 1; \
	fi; \
	if ! ssh-add -L 2>/dev/null | grep -Fqx -- "$$KEY"; then \
		echo "ERROR: TF_VAR_ssh_public_key is not currently loaded in ssh-agent."; \
		echo "This will cause SSH auth failures after boot."; \
		echo "Fix: update TF_VAR_ssh_public_key from: ssh-add -L"; \
		exit 1; \
	fi
	@echo "==> Applying Terraform from this machine..."
	@echo "==> Using libvirt URI: $${TF_VAR_libvirt_uri:-qemu:///system}"
	@cd $(TERRAFORM_DIR) && terraform init -upgrade -input=false >/dev/null && terraform apply -auto-approve -input=false
	@URI=$${TF_VAR_libvirt_uri:-qemu:///system}; \
	case "$$URI" in \
		qemu:///system) \
			echo "==> Ensuring VM is running via local libvirt..."; \
			virsh -c qemu:///system start prototype-net-server >/dev/null 2>&1 || true; \
			;; \
		qemu+sshcmd://*) \
			REMOTE=$${URI#qemu+sshcmd://}; REMOTE=$${REMOTE%%/*}; \
			echo "==> Ensuring VM is running via SSH host '$$REMOTE'..."; \
			ssh $$REMOTE "virsh -c qemu:///system start prototype-net-server >/dev/null 2>&1 || true"; \
			;; \
		qemu+ssh://*) \
			REMOTE=$${URI#qemu+ssh://}; REMOTE=$${REMOTE%%/*}; \
			echo "==> Ensuring VM is running via SSH target '$$REMOTE'..."; \
			ssh $$REMOTE "virsh -c qemu:///system start prototype-net-server >/dev/null 2>&1 || true"; \
			;; \
		*) \
			echo "==> Note: URI transport does not support automatic VM start from this target."; \
			echo "==> If needed, start VM manually: virsh -c qemu:///system start prototype-net-server"; \
			;; \
	esac
	@echo "==> VM created/updated. Fetch VM IP manually from your hypervisor or LAN tools."
	@echo "==> Tip (on libvirt host): virsh -c qemu:///system domifaddr --source agent prototype-net-server"
	@echo "Next: set SERVER_VM_IP in .env, then run: make vm-provision"

vm-provision:
	$(call require,SERVER_VM_IP)
	@echo "==> Waiting for SSH on $(SERVER_VM_IP)..."
	@until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes ubuntu@$(SERVER_VM_IP) true 2>/dev/null; do \
		echo "  SSH not ready yet, retrying in 5s..."; sleep 5; \
	done
	@echo "==> Running Ansible provisioning..."
	ansible-playbook \
		-i "$(SERVER_VM_IP)," \
		-u ubuntu \
		-e @ansible/vars.yml \
		-e postgres_password=$(TF_VAR_postgres_password) \
		-e host_bridge_ip=$(TF_VAR_host_bridge_ip) \
		-e server_ipv6=$(TF_VAR_server_ipv6) \
		-e client_ipv6=$(CLIENT_IPV6) \
		-e dns_listen_addr=$(TF_VAR_dns_listen_addr) \
		ansible/site.yml
	@echo ""
	@echo "==> VM provisioned. Next: make certs && make dev-build && make deploy"

vm-ssh:
	$(call require,SERVER_VM_IP)
	$(SSH)

vm-down:
	@echo "==> Destroying VM from this machine..."
	@echo "==> Using libvirt URI: $${TF_VAR_libvirt_uri:-qemu:///system}"
	@cd $(TERRAFORM_DIR) && terraform init -upgrade -input=false >/dev/null && terraform destroy -auto-approve -input=false
	@echo "==> VM destroyed. Next run of 'make vm-up' will create a fresh VM."

# ---------------------------------------------------------------------------
# Postgres
# ---------------------------------------------------------------------------

postgres-up:
	$(call require,POSTGRES_PASSWORD)
	@echo "==> Starting Postgres..."
	docker compose up -d postgres
	@echo "==> Waiting for Postgres to be ready..."
	@for i in $$(seq 1 20); do \
		docker compose exec postgres pg_isready -U prototype -d prototype_net -q && break; \
		echo "  waiting... ($$i/20)"; \
		sleep 2; \
	done
	@echo "==> Postgres ready."

postgres-down:
	@echo "==> Stopping Postgres..."
	docker compose stop postgres

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

deploy: deploy-bins deploy-certs
	@echo "==> Restarting services on VM..."
	$(SSH) 'sudo systemctl restart strongswan-starter && LOADED=0; for i in $$(seq 1 20); do if sudo swanctl --load-all >/dev/null 2>&1; then LOADED=1; break; fi; sleep 1; done; if [ $$LOADED -ne 1 ]; then echo "ERROR: strongSwan VICI socket not ready"; sudo systemctl status strongswan-starter --no-pager -l; exit 1; fi; sudo systemctl restart prototype-daemon prototype-dns-server'
	@echo "==> Waiting for services..."
	@sleep 3
	$(SSH) 'sudo systemctl is-active prototype-daemon prototype-dns-server strongswan-starter'

deploy-bins:
	$(call require,SERVER_VM_IP)
	@test -f $(RELEASE_DIR)/daemon || (echo "ERROR: $(RELEASE_DIR)/daemon not found — run: make dev-build" && exit 1)
	@test -f $(RELEASE_DIR)/dns-server || (echo "ERROR: $(RELEASE_DIR)/dns-server not found — run: make dev-build" && exit 1)
	@echo "==> Creating /opt/prototype_net on VM..."
	$(SSH) 'sudo mkdir -p /opt/prototype_net'
	@echo "==> Copying binaries to VM..."
	$(SCP) $(RELEASE_DIR)/daemon $(RELEASE_DIR)/dns-server ubuntu@$(VM_IP):/tmp/
	$(SSH) 'sudo mv /tmp/daemon /tmp/dns-server /opt/prototype_net/ && sudo chmod +x /opt/prototype_net/*'

deploy-certs:
	$(call require,SERVER_VM_IP)
	@test -f $(CERT_DIR)/ca.crt     || (echo "ERROR: certs not found — run: make certs" && exit 1)
	@test -f $(CERT_DIR)/server.crt || (echo "ERROR: certs not found — run: make certs" && exit 1)
	@test -f $(CERT_DIR)/server.key || (echo "ERROR: certs not found — run: make certs" && exit 1)
	@echo "==> Copying certificates to VM..."
	$(SCP) $(CERT_DIR)/ca.crt     ubuntu@$(VM_IP):/tmp/ca.crt
	$(SCP) $(CERT_DIR)/server.crt ubuntu@$(VM_IP):/tmp/server.crt
	$(SCP) $(CERT_DIR)/server.key ubuntu@$(VM_IP):/tmp/server.key
	$(SSH) ' \
		sudo mkdir -p /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private && \
		sudo mv /tmp/ca.crt     /etc/swanctl/x509ca/ca.crt     && \
		sudo mv /tmp/server.crt /etc/swanctl/x509/server.crt   && \
		sudo mv /tmp/server.key /etc/swanctl/private/server.key && \
		sudo chmod 600 /etc/swanctl/private/server.key \
	'

# ---------------------------------------------------------------------------
# Test client
# ---------------------------------------------------------------------------

client-up:
	$(call require,SERVER_VM_IP)
	@test -f $(CERT_DIR)/client.crt || (echo "ERROR: client certs not found — run: make certs" && exit 1)
	@echo "==> Starting test client..."
	docker compose up -d --no-deps client
	@echo "==> Waiting for tunnel to establish..."
	@for i in $$(seq 1 30); do \
		docker compose exec client swanctl --list-sas 2>/dev/null | grep -q ESTABLISHED && \
			echo "  Tunnel established!" && break; \
		echo "  waiting for tunnel... ($$i/30)"; \
		sleep 2; \
	done

client-up-mac:
	$(call require,SERVER_VM_IP)
	@test -f $(CERT_DIR)/client.crt || (echo "ERROR: client certs not found — run: make certs" && exit 1)
	@echo "==> Starting test client (macOS)..."
	docker compose up -d --no-deps client
	@echo "==> Waiting for tunnel to establish..."
	@for i in $$(seq 1 30); do \
		docker compose exec client swanctl --list-sas 2>/dev/null | grep -q ESTABLISHED && \
			echo "  Tunnel established!" && break; \
		echo "  waiting for tunnel... ($$i/30)"; \
		sleep 2; \
	done

client-down:
	@echo "==> Stopping test client..."
	docker compose stop client

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test:
	$(call require,SERVER_VM_IP)
	@echo ""
	@echo "==> Test 1: AAAA DNS query (should return synthetic fd00:abcd::* address)"
	docker compose exec client dig AAAA google.com +short
	@echo ""
	@echo "==> Test 2: HTTPS through NAT66 tunnel — google.com"
	docker compose exec client curl -sv --max-time 15 https://google.com 2>&1 | grep -E "^[<>*]" | head -20
	@echo ""
	@echo "==> Test 3: HTTPS through NAT66 tunnel — youtube.com"
	docker compose exec client curl -sv --max-time 15 https://youtube.com 2>&1 | grep -E "^[<>*]" | head -20
	@echo ""
	@echo "==> Test 4: Domain mappings in Postgres"
	docker compose exec postgres psql -U prototype -d prototype_net -c "SELECT domain, synthetic_ipv6, real_ipv6 FROM domains ORDER BY created_at DESC LIMIT 10;"
	@echo ""
	@echo "==> Test 5: eBPF NAT map on VM"
	$(SSH) 'sudo bpftool map dump name NAT_MAP 2>/dev/null || echo "(map empty or not loaded)"'

# ---------------------------------------------------------------------------
# Observe
# ---------------------------------------------------------------------------

status:
	$(call require,SERVER_VM_IP)
	@echo "==> Service status on VM:"
	$(SSH) 'sudo systemctl status prototype-daemon prototype-dns-server strongswan-starter --no-pager -l'

logs-daemon:
	$(call require,SERVER_VM_IP)
	$(SSH) 'sudo journalctl -fu prototype-daemon'

logs-dns:
	$(call require,SERVER_VM_IP)
	$(SSH) 'sudo journalctl -fu prototype-dns-server'

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	@echo "==> Removing cargo build artifacts..."
	cargo clean

clean-certs:
	@echo "==> Removing generated certificates..."
	rm -rf $(CERT_DIR)

clean-all: clean clean-certs
	@echo "==> Stopping and removing all Docker containers and volumes..."
	docker compose down -v --remove-orphans
	@echo "==> Destroying server VM..."
	cd $(TERRAFORM_DIR) && terraform destroy -auto-approve || true
	@echo "==> Removing Terraform state..."
	rm -rf $(TERRAFORM_DIR)/.terraform $(TERRAFORM_DIR)/terraform.tfstate $(TERRAFORM_DIR)/terraform.tfstate.backup
	@echo "==> Deleting Lima build VM..."
	limactl delete --force $(DEV_VM_NAME) || true
	@echo ""
	@echo "==> clean-all complete. Start fresh with:"
	@echo "    1. Edit .env"
	@echo "    2. make dev-up"
	@echo "    3. make postgres-up"
	@echo "    4. make vm-up"
	@echo "    5. make certs"
	@echo "    6. make dev-build"
	@echo "    7. make deploy"
	@echo "    8. make client-up"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# $(call require,VAR_NAME) — abort with a helpful message if VAR_NAME is unset or empty
define require
	@if [ -z "$($(1))" ]; then \
		echo "ERROR: $(1) is not set. Add it to .env or export it."; \
		exit 1; \
	fi
endef
