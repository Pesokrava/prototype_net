# client/ -- Docker Test Client

This directory contains a Docker container that acts as a test client. It establishes an IKEv2 tunnel to the server VM and routes synthetic IPv6 traffic (`fd00:abcd::/32`) through it.

## Components

- **`Dockerfile`** -- Ubuntu 24.04 base. Installs strongSwan, curl, iproute2, iputils-ping, dnsutils. Copies the swanctl config and entrypoint script.
- **`entrypoint.sh`** -- Container startup script that:
  1. Installs certificates from bind-mounted `/certs/` volume.
  2. Substitutes the `%SERVER_IP%` placeholder in swanctl.conf with the `$SERVER_IP` env var.
  3. Starts strongSwan and loads credentials.
  4. Initiates the IKEv2 tunnel with retry logic (up to 30s timeout).
  5. Configures `/etc/resolv.conf` to point to the custom DNS server (`$DNS_SERVER`).
  6. Creates an `xfrm0` XFRM interface (`if_id=1`) on `eth0` — matching the `if_id_in/out=1`
     set in the child SA — assigns the client's IPv6 address to it (`$CLIENT_IPV6`), and
     routes `fd00:abcd::/32` via `xfrm0` so outbound synthetic traffic is captured by the
     kernel's XFRM policy and sent through the IPSec tunnel.
  7. Keeps the container alive with `tail -f /dev/null`.
- **`swanctl.conf`** -- Client-side IKEv2 config. Mirrors the server config but acts as the
  active initiator (`start_action = start`) with DPD restart enabled. Sets
  `if_id_in = 1` / `if_id_out = 1` to match the server-side child SA.

## Usage

Started via `docker-compose.yml` at the project root. Requires:
- `SERVER_IP`, `DNS_SERVER`, and `CLIENT_IPV6` environment variables.
- Certificates mounted from `certs/output/` to `/certs/`.
- `NET_ADMIN` capability (required for IPSec and XFRM interface creation).

## Conventions

- `set -euo pipefail` in entrypoint for strict error handling.
- Runtime placeholder substitution via `sed -i`.
- Retry logic for tunnel establishment to handle timing issues.
- `xfrm0` is created explicitly with `ip link add xfrm0 type xfrm if_id 1 dev eth0` — this
  is required when the child SA uses `if_id_in/out`, because the kernel routes XFRM-interface
  traffic through the named `xfrm` netdev rather than installing a policy on the default route
  interface. The old heuristic of auto-detecting `xfrm*/ipsec*/vti*` interface names is no
  longer used.
