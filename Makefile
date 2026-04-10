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

# Read address-space constants from contract.toml (the single source of truth).
# awk extracts each value from its section.  Fails loudly if the file is missing
# or a key is absent.
XFRM_IF_ID           := $(shell awk '/^\[xfrm\]/{f=1} f && /^if_id/{gsub(/[^0-9]/,"",$$3); print $$3; exit}' contract.toml)
SYNTHETIC_PREFIX_CIDR := $(shell awk '/^\[address\]/{f=1} f && /^synthetic_prefix_cidr/{gsub(/[" ]/,"",$$3); print $$3; exit}' contract.toml)
VIP_POOL_START        := $(shell awk '/^\[vip_pool\]/{f=1} f && /^pool_start/{gsub(/[" ]/,"",$$3); print $$3; exit}' contract.toml)
VIP_POOL_END          := $(shell awk '/^\[vip_pool\]/{f=1} f && /^pool_end/{gsub(/[" ]/,"",$$3); print $$3; exit}' contract.toml)

VM_IP          ?= $(SERVER_VM_IP)
LINUX_TARGET    = x86_64-unknown-linux-gnu
RELEASE_DIR     = target/$(LINUX_TARGET)/release
CERT_DIR        = certs/output
TERRAFORM_DIR   = terraform
SSH_OPTS        = -o StrictHostKeyChecking=no
SSH             = ssh $(SSH_OPTS) ubuntu@$(VM_IP)
SCP             = scp $(SSH_OPTS)
TERRAFORM       = terraform -chdir=$(TERRAFORM_DIR)
DOCKER_COMPOSE  = docker compose
BINARIES        = daemon dns-server
CERT_FILES      = ca.crt server.crt server.key

# Lima build VM
DEV_VM_NAME     = prototype-net-build
DEV_VM_YAML     = dev/build-vm.yaml
# Run a command inside the Lima VM as the current user
LIMA            = limactl shell $(DEV_VM_NAME)

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------

.PHONY: help dev-up dev-shell dev-build dev-build-ebpf dev-build-ebpf-dev-mode dev-build-dev-mode dev-down dev-destroy \
        certs client-cert \
        vm-up vm-provision vm-ip vm-down vm-ssh terraform-init \
        postgres-up postgres-down \
        deploy deploy-bins deploy-certs deploy-units \
        client-up client-up-mac _client-up client-down \
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
	@echo "    dev-up                Create + start the Lima build VM"
	@echo "    dev-shell             Open an interactive shell inside the build VM"
	@echo "    dev-build             Build eBPF + daemon + dns-server inside the VM"
	@echo "    dev-build-ebpf        Build only eBPF inside the VM (production)"
	@echo "    dev-build-ebpf-dev-mode Build eBPF with dev-mode (double-NAT for testing)"
	@echo "    dev-build-dev-mode    Build all binaries with dev-mode enabled"
	@echo "    dev-down              Stop the build VM (disk preserved)"
	@echo "    dev-destroy           Permanently delete the build VM"
	@echo ""
	@echo "  Certificates  (runs on macOS)"
	@echo "    certs          Generate CA + server + test-client cert  (requires SERVER_VM_IP)"
	@echo "    client-cert    Generate a per-client cert + bundle  (requires CLIENT_ID)"
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
	@echo "    deploy         deploy-bins + deploy-certs + deploy-units + restart services"
	@echo "    deploy-bins    SCP daemon + dns-server to server VM"
	@echo "    deploy-certs   SCP TLS certs to server VM"
	@echo "    deploy-units   Push systemd unit files to server VM + daemon-reload"
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
		cargo --config "build.target=\"aarch64-unknown-linux-gnu\"" xtask build-ebpf && \
		echo "--- userspace binaries (x86_64-unknown-linux-gnu) ---" && \
		cargo build --release -p daemon -p dns-server --target $(LINUX_TARGET) && \
		echo "" && \
		echo "==> Build complete:" && \
		ls -lh $(REPO_PATH)/$(RELEASE_DIR)/daemon $(REPO_PATH)/$(RELEASE_DIR)/dns-server'

dev-build-ebpf:
	@echo "==> Building eBPF inside Lima VM '$(DEV_VM_NAME)'..."
	$(LIMA) bash -c 'cd $(REPO_PATH) && \
		source $$HOME/.cargo/env && \
		cargo --config "build.target=\"aarch64-unknown-linux-gnu\"" xtask build-ebpf'
	@echo "==> eBPF build complete."

dev-build-ebpf-dev-mode:
	@echo "==> Building eBPF with dev-mode inside Lima VM '$(DEV_VM_NAME)'..."
	$(LIMA) bash -c 'cd $(REPO_PATH) && \
		source $$HOME/.cargo/env && \
		cargo --config "build.target=\"aarch64-unknown-linux-gnu\"" xtask build-ebpf --dev-mode'
	@echo "==> eBPF dev-mode build complete."

dev-build-dev-mode:
	@echo "==> Building dev-mode binaries inside Lima VM '$(DEV_VM_NAME)'..."
	$(LIMA) bash -c 'cd $(REPO_PATH) && \
		source $$HOME/.cargo/env && \
		echo "--- eBPF (dev-mode) ---" && \
		cargo --config "build.target=\"aarch64-unknown-linux-gnu\"" xtask build-ebpf --dev-mode && \
		echo "--- userspace binaries (dev-mode) ---" && \
		cargo build --release -p daemon --features dev-mode -p dns-server --target $(LINUX_TARGET) && \
		echo "" && \
		echo "==> Build complete:" && \
		ls -lh $(REPO_PATH)/$(RELEASE_DIR)/daemon $(REPO_PATH)/$(RELEASE_DIR)/dns-server'

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

# Generate a per-client certificate + JSON bundle.
# Usage: make client-cert CLIENT_ID=macbook-alice
# Requires: make certs must have been run first (CA must exist).
client-cert:
	$(call require,CLIENT_ID)
	@echo "==> Generating client certificate + bundle for '$(CLIENT_ID)'..."
	./certs/gen-client.sh $(CLIENT_ID)

# ---------------------------------------------------------------------------
# VM
# ---------------------------------------------------------------------------

terraform-init:
	@$(TERRAFORM) init -upgrade -input=false >/dev/null

vm-up: terraform-init
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
	@$(TERRAFORM) apply -auto-approve -input=false
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
		-e dns_listen_addr=$(TF_VAR_dns_listen_addr) \
		-e xfrm_if_id=$(XFRM_IF_ID) \
		-e synthetic_prefix_cidr=$(SYNTHETIC_PREFIX_CIDR) \
		-e vip_pool_start=$(VIP_POOL_START) \
		-e vip_pool_end=$(VIP_POOL_END) \
		ansible/site.yml
	@echo ""
	@echo "==> VM provisioned. Next: make certs && make dev-build && make deploy"

vm-ssh:
	$(call require,SERVER_VM_IP)
	$(SSH)

vm-down: terraform-init
	@echo "==> Destroying VM from this machine..."
	@echo "==> Using libvirt URI: $${TF_VAR_libvirt_uri:-qemu:///system}"
	@$(TERRAFORM) destroy -auto-approve -input=false
	@echo "==> VM destroyed. Next run of 'make vm-up' will create a fresh VM."

# ---------------------------------------------------------------------------
# Postgres
# ---------------------------------------------------------------------------

postgres-up:
	$(call require,POSTGRES_PASSWORD)
	@echo "==> Starting Postgres..."
	$(DOCKER_COMPOSE) up -d postgres
	@echo "==> Waiting for Postgres to be ready..."
	@for i in $$(seq 1 20); do \
		$(DOCKER_COMPOSE) exec postgres pg_isready -U prototype -d prototype_net -q && break; \
		echo "  waiting... ($$i/20)"; \
		sleep 2; \
	done
	@echo "==> Postgres ready."

postgres-down:
	@echo "==> Stopping Postgres..."
	$(DOCKER_COMPOSE) stop postgres

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
#
# IMPORTANT — what "make deploy" does and does NOT do:
#
#   deploy-bins    SCPs compiled binaries (daemon, dns-server) to the VM.
#   deploy-certs   SCPs TLS certificates to the VM swanctl directories.
#   deploy-units   Renders unit files from ansible/roles/…/templates/*.j2 and
#                  pushes them to the VM via SSH then runs daemon-reload.
#                  Required after any change to a template or contract.toml.
#   deploy         Runs all three sub-targets then restarts services.
#
# Changes to ansible/roles/prototype_net/tasks/main.yml that are NOT unit
# files (e.g. sysctl, strongSwan config, package list) still require running
# the full Ansible playbook:
#   make vm-provision
#   — or —
#   ansible-playbook -i "$(SERVER_VM_IP)," -u ubuntu -e @ansible/vars.yml ... ansible/site.yml
# ---------------------------------------------------------------------------

deploy: deploy-bins deploy-certs deploy-units
	@echo "==> Restarting services on VM..."
	$(SSH) 'sudo systemctl restart strongswan-starter && sudo systemctl restart prototype-swanctl-load && sudo systemctl restart prototype-daemon prototype-dns-server'
	@echo "==> Waiting for services..."
	@sleep 3
	$(SSH) 'sudo systemctl is-active prototype-daemon prototype-dns-server strongswan-starter prototype-swanctl-load'

deploy-bins:
	$(call require,SERVER_VM_IP)
	@for bin in $(BINARIES); do \
		test -f "$(RELEASE_DIR)/$$bin" || { echo "ERROR: $(RELEASE_DIR)/$$bin not found — run: make dev-build"; exit 1; }; \
	done
	@echo "==> Creating /opt/prototype_net on VM..."
	$(SSH) 'sudo mkdir -p /opt/prototype_net'
	@echo "==> Copying binaries to VM..."
	$(SCP) $(addprefix $(RELEASE_DIR)/,$(BINARIES)) ubuntu@$(VM_IP):/tmp/
	$(SSH) 'sudo mv $(addprefix /tmp/,$(BINARIES)) /opt/prototype_net/ && sudo chmod +x /opt/prototype_net/*'

# deploy-units — push systemd unit files to the VM and reload systemd.
#
# Renders each unit from ansible/roles/prototype_net/templates/*.j2 by
# substituting Jinja2 {{ variable }} placeholders with their runtime values
# using sed.  The same .j2 files are used by `make vm-provision` (via Ansible),
# so there is exactly ONE source for each unit — no inline printf duplication.
#
# Run this after any change to a template or to address-space constants.
# Full provisioning changes (sysctl, packages, strongSwan config) still
# require: make vm-provision
deploy-units:
	$(call require,SERVER_VM_IP)
	$(call require,TF_VAR_postgres_password)
	$(call require,TF_VAR_host_bridge_ip)
	$(call require,TF_VAR_server_ipv6)
	$(call require,TF_VAR_dns_listen_addr)
	@test -n "$(XFRM_IF_ID)"           || (echo "ERROR: could not parse xfrm.if_id from contract.toml" && exit 1)
	@test -n "$(SYNTHETIC_PREFIX_CIDR)" || (echo "ERROR: could not parse address.synthetic_prefix_cidr from contract.toml" && exit 1)
	@test -n "$(VIP_POOL_START)"        || (echo "ERROR: could not parse vip_pool.pool_start from contract.toml" && exit 1)
	@test -n "$(VIP_POOL_END)"          || (echo "ERROR: could not parse vip_pool.pool_end from contract.toml" && exit 1)
	@echo "==> Deploying systemd units to VM (XFRM_IF_ID=$(XFRM_IF_ID))..."
	@TMPL=ansible/roles/prototype_net/templates; \
	render() { \
		sed \
			-e 's/{{ xfrm_if_id }}/$(XFRM_IF_ID)/g' \
			-e 's|{{ synthetic_prefix_cidr }}|$(SYNTHETIC_PREFIX_CIDR)|g' \
			-e 's|{{ vip_pool_start }}|$(VIP_POOL_START)|g' \
			-e 's|{{ vip_pool_end }}|$(VIP_POOL_END)|g' \
			-e 's/{{ postgres_password }}/$(TF_VAR_postgres_password)/g' \
			-e 's/{{ host_bridge_ip }}/$(TF_VAR_host_bridge_ip)/g' \
			-e 's/{{ dns_listen_addr }}/$(TF_VAR_dns_listen_addr)/g' \
			-e 's/{{ proxy_addr_key_hex }}/$(PROXY_ADDR_KEY_HEX)/g' \
			"$$TMPL/$$1" | \
		if [ -n "$(PROXY_ADDR_PREV_KEY_HEX)" ]; then \
			sed \
				-e '/{% if proxy_addr_prev_key_hex is defined and proxy_addr_prev_key_hex %}/d' \
				-e 's/{{ proxy_addr_prev_key_hex }}/$(PROXY_ADDR_PREV_KEY_HEX)/g' \
				-e '/{% endif %}/d'; \
		else \
			sed \
				-e '/{% if proxy_addr_prev_key_hex is defined and proxy_addr_prev_key_hex %}/,/{% endif %}/d'; \
		fi | \
		sed \
			-e '/{% if dev_wan_ipv6 is defined and dev_wan_ipv6 %}/,/{% endif %}/d'; \
	}; \
	render prototype-xfrm0.service.j2       | $(SSH) 'sudo tee /etc/systemd/system/prototype-xfrm0.service > /dev/null'; \
	render prototype-swanctl-load.service.j2 | $(SSH) 'sudo tee /etc/systemd/system/prototype-swanctl-load.service > /dev/null'; \
	render prototype-daemon.service.j2       | $(SSH) 'sudo tee /etc/systemd/system/prototype-daemon.service > /dev/null'; \
	render prototype-dns-server.service.j2   | $(SSH) 'sudo tee /etc/systemd/system/prototype-dns-server.service > /dev/null'
	$(SSH) 'sudo systemctl daemon-reload && sudo systemctl enable prototype-swanctl-load.service'
	@echo "==> Unit files deployed and systemd reloaded."

deploy-certs:
	$(call require,SERVER_VM_IP)
	@for cert in $(CERT_FILES); do \
		test -f "$(CERT_DIR)/$$cert" || { echo "ERROR: certs not found — run: make certs"; exit 1; }; \
	done
	@echo "==> Copying certificates to VM..."
	@for cert in $(CERT_FILES); do \
		$(SCP) "$(CERT_DIR)/$$cert" "ubuntu@$(VM_IP):/tmp/$$cert"; \
	done
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

client-up: CLIENT_UP_LABEL = test client
client-up: _client-up

client-up-mac: CLIENT_UP_LABEL = test client (macOS)
client-up-mac: _client-up

_client-up:
	$(call require,SERVER_VM_IP)
	@test -f $(CERT_DIR)/client-test-client.crt || (echo "ERROR: client certs not found — run: make certs" && exit 1)
	@echo "==> Starting $(CLIENT_UP_LABEL)..."
	$(DOCKER_COMPOSE) up -d --build --force-recreate --no-deps client
	@echo "==> Waiting for tunnel to establish..."
	@for i in $$(seq 1 30); do \
		$(DOCKER_COMPOSE) exec client swanctl --list-sas 2>/dev/null | grep -q ESTABLISHED && \
			echo "  Tunnel established!" && break; \
		echo "  waiting for tunnel... ($$i/30)"; \
		sleep 2; \
	done

client-down:
	@echo "==> Stopping test client..."
	$(DOCKER_COMPOSE) stop client

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test:
	$(call require,SERVER_VM_IP)
	@echo ""
	@echo "==> Test 1: AAAA DNS query (should return synthetic fd00:abcd::* address)"
	$(DOCKER_COMPOSE) exec client dig AAAA google.com +short
	@echo ""
	@echo "==> Test 2: HTTPS through NAT66 tunnel — google.com"
	$(DOCKER_COMPOSE) exec client curl -sv --max-time 15 https://google.com 2>&1 | grep -E "^[<>*]" | head -20
	@echo ""
	@echo "==> Test 3: HTTPS through NAT66 tunnel — youtube.com"
	$(DOCKER_COMPOSE) exec client curl -sv --max-time 15 https://youtube.com 2>&1 | grep -E "^[<>*]" | head -20
	@echo ""
	# @echo "==> Test 4: Domain mappings in Postgres"
	# docker compose exec postgres psql -U prototype -d prototype_net -c "SELECT domain, synthetic_ipv6, real_ipv6 FROM domains ORDER BY created_at DESC LIMIT 10;"
	# @echo ""
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
	$(DOCKER_COMPOSE) down -v --remove-orphans
	@echo "==> Destroying server VM..."
	@$(TERRAFORM) destroy -auto-approve || true
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
