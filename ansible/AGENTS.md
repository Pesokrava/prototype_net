# ansible/ -- Server Provisioning

This directory contains the Ansible playbook and role that provision the prototype_net server
VM after it has been brought up by Terraform (`make vm-up`). It installs packages, configures
sysctl, deploys the strongSwan config, renders systemd unit files from Jinja2 templates, and
enables the required services.

## Directory Structure

```
ansible/
├── inventory.ini                         # Static inventory (VM_IP substituted by Makefile)
├── site.yml                              # Top-level playbook — applies role `prototype_net`
├── vars.yml                              # Runtime variables (bridge IP, Postgres password, etc.)
└── roles/
    └── prototype_net/
        ├── tasks/
        │   └── main.yml                  # All provisioning tasks
        ├── templates/
        │   ├── prototype-xfrm0.service.j2        # Creates xfrm0 XFRM interface
        │   ├── prototype-daemon.service.j2        # Runs the eBPF daemon
        │   ├── prototype-dns-server.service.j2    # Runs the custom DNS server
        │   └── prototype-swanctl-load.service.j2  # Loads strongSwan credentials on boot
        └── handlers/
            └── main.yml                  # Handlers: Apply sysctl, Reload systemd, etc.
```

## Usage

Normally invoked via the Makefile after `make vm-up`:

```sh
make vm-provision
```

Which expands to (approximately):

```sh
ansible-playbook -i "$(VM_IP)," -u ubuntu ansible/site.yml \
  -e @ansible/vars.yml \
  -e host_bridge_ip=$(HOST_BRIDGE_IP) \
  -e postgres_password=$(POSTGRES_PASSWORD) \
  -e server_ipv6=$(SERVER_IPV6) \
  -e xfrm_if_id=$(XFRM_IF_ID)
```

The `xfrm_if_id` extra-var is read from `contract.toml` by the Makefile at eval time and
passed in here, so the Jinja2 templates receive the correct value without duplicating it.

## Key Tasks (`tasks/main.yml`)

1. **Packages** -- installs strongSwan, iproute2, bpftool, curl, net-tools.
2. **sysctl** -- writes `/etc/sysctl.d/99-prototype-net.conf`:
   - `net.ipv6.conf.all.forwarding=1`
   - `net.ipv6.conf.xfrm0.disable_policy=1` (prevents XFRM re-check on rewritten packets)
3. **systemd-resolved** -- disables the stub listener so `dns-server` can own port 53.
4. **strongSwan config** -- renders `swanctl.conf.j2` to `/etc/swanctl/conf.d/prototype.conf`
   via Ansible `template:` task; all address-space values are substituted from extra-vars.
5. **Systemd units** -- renders the four systemd `.j2` templates to `/etc/systemd/system/`
   via Ansible `template:` tasks.
6. **Enable services** -- enables all five units plus `strongswan-starter`.

## Jinja2 Templates

All templates live under `roles/prototype_net/templates/` as `.j2` files. Address-space
variables (`xfrm_if_id`, `synthetic_prefix_cidr`, `vip_pool_start`, `vip_pool_end`) are
read from `contract.toml` by the Makefile and passed as `-e` extra-vars to Ansible
(`vm-provision`) and as `sed` substitutions (`deploy-units`). Never hardcode these values
inside a template — add a new variable and wire it through the Makefile.

| Template | Installed at | Variables substituted |
|:---------|:-------------|:----------------------|
| `swanctl.conf.j2` | `/etc/swanctl/conf.d/prototype.conf` | `vip_pool_start`, `vip_pool_end`, `synthetic_prefix_cidr`, `xfrm_if_id` |
| `prototype-xfrm0.service.j2` | `/etc/systemd/system/prototype-xfrm0.service` | `xfrm_if_id` |
| `prototype-daemon.service.j2` | `/etc/systemd/system/prototype-daemon.service` | `postgres_password`, `host_bridge_ip`, `dns_listen_addr`, `proxy_addr_key_hex`, optionally `dev_wan_ipv6` |
| `prototype-dns-server.service.j2` | `/etc/systemd/system/prototype-dns-server.service` | `dns_listen_addr` |
| `prototype-swanctl-load.service.j2` | `/etc/systemd/system/prototype-swanctl-load.service` | _(none)_ |

`prototype-daemon.service.j2` uses a Jinja2 conditional to include `DEV_WAN_IPV6` only when
`dev_wan_ipv6` is defined and non-empty:

```jinja2
{% if dev_wan_ipv6 is defined and dev_wan_ipv6 %}
Environment=DEV_WAN_IPV6={{ dev_wan_ipv6 }}
{% endif %}
```

The `deploy-units` Makefile target replicates this conditional with `sed` range deletion so the
rendered unit file is correct whether `DEV_WAN_IPV6` is set in `.env` or not.

## `vars.yml`

Contains runtime/machine-specific variables that are **not** address-space constants:

| Variable | Required | Meaning |
|:---------|:---------|:--------|
| `host_bridge_ip` | yes | IPv4 address of the hypervisor bridge, reachable from inside the VM |
| `postgres_password` | yes | Postgres password (must match `.env` / docker-compose) |
| `server_ipv6` | yes | VM's public IPv6 address |
| `dns_listen_addr` | yes | Address the DNS server binds to (default `0.0.0.0`) |
| `proxy_addr_key_hex` | yes | 64-hex-char proxy-source obfuscation key |
| `proxy_addr_prev_key_hex` | no | Previous key for rotation grace window |
| `dev_wan_ipv6` | no | Server's WAN IPv6 for dev-NAT `DEV_PASSTHROUGH` (leave commented out in production) |

Do **not** put address-space constants (`synthetic_prefix`, `xfrm if_id`, pool range) in
`vars.yml` — those come from `contract.toml` and are passed in by the Makefile.

## Conventions

- The playbook runs with `become: true` (root) — all tasks install system files.
- Use `template:` (not `copy: content:`) for any file that contains `{{ xfrm_if_id }}` or
  any other value derived from `contract.toml`.
- Handlers in `handlers/main.yml` ensure sysctl and systemd are reloaded only when the
  corresponding tasks report a change.
- The inline strongSwan swanctl config block in `tasks/main.yml` still contains the pool
  range and `remote_ts` values as plain strings — they are checked by
  `cargo xtask verify-contract` and must match `contract.toml`.
- `dev_wan_ipv6` should only be set when running dev-NAT tests. Never set it in a production
  deployment — an accidental entry in `DEV_PASSTHROUGH` would allow non-proxy-source traffic
  destined for that address to bypass the `xdp_wan` prefix filter.
