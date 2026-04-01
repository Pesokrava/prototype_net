# strongswan/ -- Server-Side IKEv2 Configuration

This directory contains the reference `swanctl.conf` for the server-side strongSwan IKEv2 VPN configuration. This file is deployed to the server VM (either via cloud-init or SCP) and defines the IPSec tunnel that carries NAT66-translated traffic.

## Configuration Summary

- **Connection**: `prototype` using IKEv2.
- **IKE proposal**: `aes256-sha256-ecp384`.
- **ESP proposal**: `aes256gcm128`.
- **Authentication**: Mutual certificate-based (pubkey). Server uses `server.crt`; remote clients validated against `ca.crt`.
- **Traffic selectors**: local_ts = `::/0`, remote_ts = `fd00:abcd::/32` -- only synthetic prefix traffic enters the tunnel.
- **Mode**: Tunnel mode, passive (`start_action = none`) -- the client initiates.
- **XFRM interface**: `if_id_in = 1` / `if_id_out = 1` -- associates the child SA with XFRM
  interface `if_id=1`. Both the server and client must create a matching `xfrm` netdev
  (`ip link add xfrm0 type xfrm if_id 1 dev <iface>`) to route tunnel traffic. The daemon
  attaches `tc_ingress` to the server-side `xfrm0` interface.

## Conventions

- This is the server-side config; the client-side mirror lives in `client/swanctl.conf`.
- Certificate paths follow strongSwan defaults under `/etc/swanctl/`.
- Comments in the file document expected file locations for certs and keys.
- No PSK -- cert-based auth only.
