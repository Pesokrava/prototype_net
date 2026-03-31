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
  6. Auto-detects the tunnel interface (xfrm*/ipsec*/vti*) and adds a route for `fd00:abcd::/32`.
  7. Keeps the container alive with `tail -f /dev/null`.
- **`swanctl.conf`** -- Client-side IKEv2 config. Mirrors the server config but acts as the active initiator (`start_action = start`) with DPD restart enabled.

## Usage

Started via `docker-compose.yml` at the project root. Requires:
- `SERVER_IP` and `DNS_SERVER` environment variables.
- Certificates mounted from `certs/output/` to `/certs/`.
- `NET_ADMIN` capability (required for IPSec).

## Conventions

- `set -euo pipefail` in entrypoint for strict error handling.
- Runtime placeholder substitution via `sed -i`.
- Retry logic for tunnel establishment to handle timing issues.
- Auto-detection of tunnel interface name (varies by kernel/strongSwan version).
