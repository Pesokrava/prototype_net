# macos-agent

A Go CLI tool that automates the macOS client-side workflow for the prototype_net IPv6 NAT66 transparent proxy system. It handles one-time VPN profile installation and the session-level connect/disconnect lifecycle, including DNS redirection.

## Purpose

The agent bridges the gap between the server-side prototype_net infrastructure and a macOS end user. It:

1. Parses a server-issued **client bundle** (JSON containing TLS certs/keys) and the workspace `contract.toml`.
2. Generates a signed **Apple `.mobileconfig` profile** (IKEv2 VPN with certificate auth + CA cert trust + client identity PKCS#12).
3. Opens the profile in System Settings for one-time user installation.
4. On `start`: redirects macOS system DNS to the prototype-net DNS server and brings up the IKEv2 tunnel.
5. On `stop`: tears down the tunnel, restores original DNS, and flushes the resolver cache.

## Companion: vpnctl

`vpnctl` is a Swift CLI binary (`macos-agent/vpnctl/main.swift`) that uses the `NEVPNManager` (NetworkExtension framework) to control profile-installed IKEv2 VPNs on macOS Sequoia. Profile-installed VPNs do **not** appear in `scutil --nc list` and cannot be controlled via `networksetup` or AppleScript.

### Usage

```
vpnctl list                    # List all VPN configurations visible to NEVPNManager
vpnctl start <display-name>    # Connect VPN
vpnctl stop  <display-name>    # Disconnect VPN
vpnctl status <display-name>   # Show VPN status
```

### Limitations

- **Must NOT be run with `sudo`**: root has a different NEVPNManager context with no VPN configs.
- **Ad-hoc signed with entitlements**: requires `com.apple.networking.vpn.configuration` entitlement. The `list` and `status` actions work, but `start`/`stop` may be SIGKILL'd (exit 137) on Sequoia because `startVPNTunnel()` requires `com.apple.developer.networking.vpn.api` (a restricted entitlement needing an Apple provisioning profile).
- **Workaround**: connect/disconnect VPN via System Settings UI instead of `vpnctl start/stop`.

### Build

```bash
swiftc -o target/vpnctl -framework NetworkExtension -target arm64-apple-macosx15.0 macos-agent/vpnctl/main.swift
codesign --force --sign - --entitlements macos-agent/vpnctl/vpnctl.entitlements target/vpnctl
```

## Subcommands

| Command | Description |
|---------|-------------|
| `setup` | One-time provisioning. Requires `--server-ip`, `--dns-ip`, `--bundle-file`, and optionally `--contract-file` (default `./contract.toml`). Writes `~/.prototype-net/config.json` and `~/.prototype-net/prototype-net.mobileconfig`. |
| `start` | Backs up DNS, sets system DNS to `dns_ip`, starts the IKEv2 VPN via `vpnctl` (primary) or `scutil --nc` (fallback), polls until `Connected` (15 s timeout), and verifies the synthetic IPv6 route is present. |
| `stop` | Stops VPN via `vpnctl stop` or `scutil --nc stop`, restores DNS from backup, flushes resolver cache (`dscacheutil -flushcache` + `killall mDNSResponder`). |
| `status` | Displays local state files, VPN connection status, active network service, current DNS servers, and synthetic prefix route presence. |

## Package Layout

```
macos-agent/
├── main.go                          Entry point; calls cmd.Execute()
├── cmd/
│   ├── root.go                      Cobra root command; registers subcommands
│   ├── setup.go                     setup subcommand
│   ├── start.go                     start subcommand
│   ├── stop.go                      stop subcommand
│   └── status.go                    status subcommand
├── vpnctl/
│   ├── main.swift                   Swift NEVPNManager CLI for VPN control
│   └── vpnctl.entitlements          Entitlements plist for code signing
└── internal/
    ├── bundle/bundle.go             Parses the client bundle JSON (ClientID, PEM certs/keys, CA)
    ├── contract/contract.go         Reads contract.toml; exposes SyntheticPrefix()
    ├── dns/dns.go                   BackupAndSet / Restore / FlushCache via networksetup
    ├── mobileconfig/
    │   ├── mobileconfig.go          Generates .mobileconfig XML from template
    │   └── mobileconfig.xml.tmpl    Apple plist template (IKEv2 + certs)
    ├── network/network.go           ActiveService() and DNSServers() via networksetup
    ├── pkcs12/pkcs12.go             Generates PKCS#12 from PEM using openssl CLI (temp dir)
    ├── state/state.go               Reads/writes ~/.prototype-net/{config,dns-backup}.json
    └── vpn/vpn.go                   Start / Stop / Status / HasIPv6Route via vpnctl + scutil fallback
```

## State Files

All runtime state lives in `~/.prototype-net/` (mode `0700`):

| File | Written by | Removed by | Contents |
|------|-----------|-----------|----------|
| `config.json` | `setup` | never (manual) | Server IP, DNS IP, client ID, synthetic prefix, profile name, CA issuer CN |
| `prototype-net.mobileconfig` | `setup` | never (manual) | Full mobileconfig XML including embedded PKCS#12 private key (mode `0600`) |
| `dns-backup.json` | `start` | `stop` (on success) | Network service name + original DNS server list |

## DNS Management

DNS is managed exclusively via `networksetup`:

- **Detect active service**: `route -n get default` → interface name → `networksetup -listallhardwareports` → service name.
- **Read current DNS**: `networksetup -getdnsservers <service>` — detects DHCP-default DNS (returns nil slice).
- **Set DNS**: `networksetup -setdnsservers <service> <ip>`.
- **Restore DNS**: `networksetup -setdnsservers <service> <original-servers>` or `Empty` for DHCP.

The backup is written **before** DNS is modified, so a crash after backup creation but before `networksetup` still leaves DNS unchanged. A crash after DNS is set leaves the backup on disk; running `stop` recovers correctly.

## VPN Management

VPN is managed via `vpnctl` (NEVPNManager) as primary, with `scutil --nc` as fallback:

- `vpnctl start <profile>` — initiates the connection via NEVPNManager; monitors status via NotificationCenter.
- `vpnctl stop <profile>` — terminates the connection.
- `vpnctl status <profile>` — returns Connected, Disconnected, etc.
- `scutil --nc` fallback — used if `vpnctl` binary is not found; **does not work** for profile-installed VPNs on Sequoia.

**Note**: `vpnctl start/stop` may be killed by macOS Sequoia due to missing restricted entitlements. The current working approach is to connect/disconnect via the System Settings UI.

The split-tunnel route (`fd00:abcd::/32` → `ipsec0`) is installed by the macOS IKEv2 subsystem based on the negotiated traffic selectors (not from mobileconfig keys). The server's `local_ts = fd00:abcd::/32` tells macOS which subnet is reachable through the tunnel.

## PKCS#12 Generation

**Critical**: The PKCS#12 blob embedded in the mobileconfig **must** be generated with OpenSSL 3.x + `-legacy` flag for macOS Keychain compatibility. LibreSSL (macOS default `openssl`) produces PKCS#12 files where macOS imports the cert and key as separate Keychain items rather than a linked identity, causing IKE_AUTH signature validation failure on the server (`signature validation failed, looking for another key`).

The current working approach is to pre-generate the PKCS#12 on the build machine (which has Homebrew OpenSSL 3.x) and embed it directly in the mobileconfig, bypassing the runtime `openssl pkcs12 -export` in `internal/pkcs12/pkcs12.go`.

## Mobileconfig Profile Structure

The `.mobileconfig` contains three payloads:

1. **CA Certificate** (`com.apple.security.root`) — DER-encoded CA cert for trust anchor.
2. **Client Identity** (`com.apple.security.pkcs12`) — PKCS#12 with client cert + private key + CA chain.
3. **IKEv2 VPN** (`com.apple.vpn.managed`) — VPN configuration referencing the identity payload.

### Critical Mobileconfig Rules

- **No `IPv4`, `IPv6`, or `Routes` keys** as siblings of `IKEv2` inside the VPN payload dict — macOS silently discards the entire VPN payload if unrecognized top-level keys are present.
- **No `EnforceRoutes`** — this causes macOS to install a default route through the VPN, which breaks IPv4 connectivity (including DNS to the server at 192.168.100.70).
- **No `UseConfigurationAttributeInternalIPSubnet`** — combined with other settings, this also breaks IPv4 routing.
- **No `DNS` dict** in the VPN payload — on Sequoia, this is ignored for profile-installed IKEv2 VPNs.
- Routing is handled entirely by IKEv2 traffic selector negotiation (server's `local_ts`/`remote_ts`).

## macOS Sequoia Discoveries

### IPv6 Reachability and getaddrinfo()

macOS's `getaddrinfo()` (used by curl, wget, browsers, Python, etc.) checks network reachability before returning AAAA results. If macOS doesn't consider IPv6 "reachable" (checked via `scutil --nwi`), it silently drops AAAA results even though DNS resolves them correctly.

- `dig AAAA` and `ping6` work because they bypass `getaddrinfo()`.
- `curl`, `wget`, browsers, and `python3 socket.getaddrinfo()` all fail.
- **Fix**: run `networksetup -setv6automatic Wi-Fi` on the client to enable IPv6 reachability. This must be done once; it persists across reboots.

### IKEv2 Identity Type

macOS IKEv2 sends `LocalIdentifier` as `ID_FQDN` type (bare string like `macbook-test`), **not** as `ID_DER_ASN1_DN` (`CN=macbook-test`). The server must be configured with `id = %any` in the `remote {}` block, and the client certificate should include `subjectAltName=DNS:<client-id>` to match.

### Server-Side Client Cert Pre-loading

The client certificate must be deployed to `/etc/swanctl/x509/` on the server (not just in the CA trust chain). Without the pre-loaded end-entity cert, strongSwan logs `no trusted RSA public key found for 'macbook-test'` and never attempts chain validation.

### Traffic Selector Impact on IPv4

Setting `local_ts = ::/0` on the server causes macOS to treat the VPN as a full tunnel, routing **all** traffic (including IPv4) through the IPSec tunnel. This breaks IPv4 connectivity entirely (DNS, web, etc.). The correct setting is `local_ts = fd00:abcd::/32` — only the synthetic prefix routes through the tunnel.

## Working Server Configuration

```ini
pools {
    client_pool {
        addrs = fd00:abcd:0:1::1:0-fd00:abcd:0:1::ffff:ffff
        dns = 192.168.100.70
    }
}
connections {
    prototype {
        version = 2
        proposals = aes256-sha256-ecp384
        rekey_time = 4h
        pools = client_pool
        local {
            auth = pubkey
            certs = server.crt
            id = %any
        }
        remote {
            auth = pubkey
            cacerts = ca.crt
            id = %any
        }
        children {
            prototype {
                esp_proposals = aes256gcm128
                local_ts = fd00:abcd::/32
                remote_ts = fd00:abcd::/32
                mode = tunnel
                if_id_in = 1
                if_id_out = 1
                start_action = none
                dpd_action = clear
            }
        }
    }
}
```

## Permanent Side Effects (not undone by `stop`)

`stop` only covers session-level cleanup. The following persist until manually removed:

- **Installed VPN profile** in System Settings > VPN & Device Management. Remove via System Settings UI or `sudo profiles remove -identifier net.prototype.prototype-net`.
- **CA root certificate** trust anchor and **client identity** in Keychain — both are payload-bound to the profile and are removed automatically when the profile is deleted.
- `~/.prototype-net/prototype-net.mobileconfig` — contains the embedded client private key (mode `0600`). Delete manually when decommissioning.
- `~/.prototype-net/config.json` — no key material; persists so that `start`/`stop` can be rerun without `setup`.

## Build

```bash
# From workspace root:
make agent-build          # outputs target/macos-agent and target/vpnctl

# Or directly:
cd macos-agent && go build -o ../target/macos-agent .
swiftc -o target/vpnctl -framework NetworkExtension -target arm64-apple-macosx15.0 macos-agent/vpnctl/main.swift
codesign --force --sign - --entitlements macos-agent/vpnctl/vpnctl.entitlements target/vpnctl
```

Requirements: Go 1.21+, Swift (Xcode), OpenSSL 3.x via Homebrew (for PKCS#12 generation).

## Dependencies

| Module | Purpose |
|--------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/BurntSushi/toml` | Parsing `contract.toml` |
| `github.com/google/uuid` | Generating UUIDs for mobileconfig payload identifiers |

## Conventions

- **macOS-only**: all external commands (`networksetup`, `scutil`, `dscacheutil`, `killall mDNSResponder`, `netstat`) are macOS-specific.
- **No local daemon**: the agent is a one-shot CLI; it does not run in the background.
- **Error handling**: `anyhow`-style — all errors are wrapped with `fmt.Errorf("context: %w", err)` and surface up to Cobra's top-level handler.
- **No hardcoded address constants**: the synthetic prefix is always read from `contract.toml` via `internal/contract`.

## TODO / Known Issues

- **VPN connect/disconnect**: `vpnctl start/stop` gets SIGKILL'd on Sequoia due to missing `com.apple.developer.networking.vpn.api` restricted entitlement. Need either an Apple Developer account to get a provisioning profile, or accept UI-based connect/disconnect.
- **PKCS#12 generation**: The `internal/pkcs12/pkcs12.go` runtime generation doesn't work on macs with only LibreSSL. Should either pre-generate on the build machine or bundle a statically-linked OpenSSL.
- **IPv6 reachability**: Requires one-time `networksetup -setv6automatic Wi-Fi` on the client. Should be automated in the `start` subcommand.
- **DNS setup**: The `networksetup -setdnsservers` approach works but the resolver may not be active until VPN connects. Need to investigate proper ordering.
