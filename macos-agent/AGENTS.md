# macos-agent

A Go CLI tool that automates the macOS client-side workflow for the prototype_net IPv6 NAT66 transparent proxy system. It handles one-time VPN profile installation and the session-level connect/disconnect lifecycle, including DNS redirection.

## Purpose

The agent bridges the gap between the server-side prototype_net infrastructure and a macOS end user. It:

1. Parses a server-issued **client bundle** (JSON containing TLS certs/keys) and the workspace `contract.toml`.
2. Generates a signed **Apple `.mobileconfig` profile** (IKEv2 VPN + split-tunnel route for the synthetic `fd00:abcd::/32` prefix + CA cert trust + client identity PKCS#12).
3. Opens the profile in System Settings for one-time user installation.
4. On `start`: redirects macOS system DNS to the prototype-net DNS server and brings up the IKEv2 tunnel.
5. On `stop`: tears down the tunnel, restores original DNS, and flushes the resolver cache.

## Subcommands

| Command | Description |
|---------|-------------|
| `setup` | One-time provisioning. Requires `--server-ip`, `--dns-ip`, `--bundle-file`, and optionally `--contract-file` (default `./contract.toml`). Writes `~/.prototype-net/config.json` and `~/.prototype-net/prototype-net.mobileconfig`. |
| `start` | Backs up DNS, sets system DNS to `dns_ip`, starts the IKEv2 VPN via `scutil --nc start`, polls until `Connected` (15 s timeout), and verifies the synthetic IPv6 route is present. |
| `stop` | Stops VPN via `scutil --nc stop`, restores DNS from backup, flushes resolver cache (`dscacheutil -flushcache` + `killall mDNSResponder`). |
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
└── internal/
    ├── bundle/bundle.go             Parses the client bundle JSON (ClientID, PEM certs/keys, CA)
    ├── contract/contract.go         Reads contract.toml; exposes SyntheticPrefix()
    ├── dns/dns.go                   BackupAndSet / Restore / FlushCache via networksetup
    ├── mobileconfig/
    │   ├── mobileconfig.go          Generates .mobileconfig XML from template
    │   └── mobileconfig.xml.tmpl    Apple plist template (IKEv2 + split-tunnel + certs)
    ├── network/network.go           ActiveService() and DNSServers() via networksetup
    ├── pkcs12/pkcs12.go             Generates PKCS#12 from PEM using openssl CLI (temp dir)
    ├── state/state.go               Reads/writes ~/.prototype-net/{config,dns-backup}.json
    └── vpn/vpn.go                   Start / Stop / Status / HasIPv6Route via scutil / netstat
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

VPN is managed via `scutil --nc`:

- `scutil --nc start <profile>` — initiates the connection; `Start()` polls `scutil --nc status` every 1 s up to 15 s.
- `scutil --nc stop <profile>` — terminates the connection.
- `scutil --nc status <profile>` — returns `Connected`, `Disconnected`, `Connecting`, etc.

The split-tunnel route (`fd00:abcd::/32` → `utun*`) is installed by the macOS VPN subsystem from the mobileconfig `<key>Routes</key>` payload when the VPN connects, and is automatically removed on disconnect. The agent never calls `route add` directly.

## Permanent Side Effects (not undone by `stop`)

`stop` only covers session-level cleanup. The following persist until manually removed:

- **Installed VPN profile** in System Settings > VPN & Device Management. Remove via System Settings UI or `sudo profiles remove -identifier net.prototype.prototype-net`.
- **CA root certificate** trust anchor and **client identity** in Keychain — both are payload-bound to the profile and are removed automatically when the profile is deleted.
- `~/.prototype-net/prototype-net.mobileconfig` — contains the embedded client private key (mode `0600`). Delete manually when decommissioning.
- `~/.prototype-net/config.json` — no key material; persists so that `start`/`stop` can be rerun without `setup`.

## Build

```bash
# From workspace root:
make agent-build          # outputs target/macos-agent

# Or directly:
cd macos-agent && go build -o ../target/macos-agent .
```

Requirements: Go 1.21+, `openssl` CLI on `$PATH` (used by `pkcs12.Generate` to produce the PKCS#12 blob).

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
