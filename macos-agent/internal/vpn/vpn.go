// Package vpn queries macOS IKEv2 VPN connection status.
//
// On macOS Sequoia 15.x, profile-installed IKEv2 VPNs are managed by
// NEVPNManager and do not appear in the legacy `scutil --nc` interface.
// This package uses a companion `vpnctl` Swift binary (built from
// macos-agent/vpnctl/main.swift) that talks to NEVPNManager directly.
//
// Note: vpnctl start/stop are SIGKILL'd on Sequoia due to missing
// restricted entitlements. VPN must be connected/disconnected via
// System Settings UI. This package only provides status querying and
// a WaitForConnection helper that polls + prompts the user.
//
// Resolution order:
//  1. Look for `vpnctl` next to the running binary.
//  2. Fall back to `scutil --nc` (works on older macOS / manually-created VPNs).
package vpn

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultPollInterval = 2 * time.Second
	defaultTimeout      = 90 * time.Second
)

// vpnctlPath returns the path to the vpnctl binary if it exists next to
// the running executable, or "" if not found.
func vpnctlPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), "vpnctl")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// runVpnctl runs `vpnctl <action> <profileName>` and returns trimmed stdout.
func runVpnctl(action, profileName string) (string, error) {
	p := vpnctlPath()
	if p == "" {
		return "", fmt.Errorf("vpnctl binary not found next to macos-agent")
	}
	out, err := exec.Command(p, action, profileName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("vpnctl %s %q: %w\n%s", action, profileName, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// useVpnctl returns true if the vpnctl binary exists (prefer it over scutil).
func useVpnctl() bool {
	return vpnctlPath() != ""
}

// Status returns the current VPN connection status string
// for the named profile (e.g. "Connected", "Disconnected").
func Status(profileName string) (string, error) {
	if useVpnctl() {
		return runVpnctl("status", profileName)
	}
	return scutilStatus(profileName)
}

// IsConnected returns true if the VPN is currently connected.
func IsConnected(profileName string) (bool, error) {
	status, err := Status(profileName)
	if err != nil {
		return false, err
	}
	return status == "Connected", nil
}

// WaitForConnection polls VPN status until connected or timeout.
// It prints a prompt instructing the user to connect via System Settings.
// Returns nil when connected, or an error on timeout.
func WaitForConnection(profileName string, timeout time.Duration) error {
	if timeout == 0 {
		timeout = defaultTimeout
	}

	// Check if already connected.
	connected, err := IsConnected(profileName)
	if err == nil && connected {
		return nil
	}

	fmt.Println()
	fmt.Println("    *** Please connect the VPN via System Settings ***")
	fmt.Println("    System Settings > VPN > prototype-net > Connect")
	fmt.Println()
	fmt.Printf("    Waiting up to %s for VPN to connect...\n", timeout)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(defaultPollInterval)
		connected, err := IsConnected(profileName)
		if err != nil {
			// Status query failed — keep trying.
			continue
		}
		if connected {
			return nil
		}
	}

	return fmt.Errorf("VPN did not connect within %s — connect it in System Settings and try again", timeout)
}

// WaitForDisconnection polls VPN status until disconnected or timeout.
// It prints a prompt instructing the user to disconnect via System Settings.
// Returns nil when disconnected, or an error on timeout.
func WaitForDisconnection(profileName string, timeout time.Duration) error {
	if timeout == 0 {
		timeout = defaultTimeout
	}

	// Check if already disconnected.
	connected, err := IsConnected(profileName)
	if err != nil || !connected {
		return nil
	}

	fmt.Println()
	fmt.Println("    *** Please disconnect the VPN via System Settings ***")
	fmt.Println("    System Settings > VPN > prototype-net > Disconnect")
	fmt.Println()
	fmt.Printf("    Waiting up to %s for VPN to disconnect...\n", timeout)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(defaultPollInterval)
		connected, err := IsConnected(profileName)
		if err != nil {
			continue
		}
		if !connected {
			return nil
		}
	}

	return fmt.Errorf("VPN did not disconnect within %s — disconnect it in System Settings and try again", timeout)
}

// HasIPv6Route checks if an IPv6 route exists for the given prefix.
func HasIPv6Route(prefix string) (bool, error) {
	out, err := exec.Command("netstat", "-rn", "-f", "inet6").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("netstat -rn -f inet6: %w", err)
	}

	addr := prefix
	if idx := strings.Index(prefix, "/"); idx >= 0 {
		addr = prefix[:idx]
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, addr) {
			return true, nil
		}
	}

	return false, nil
}

// --- scutil fallback (legacy macOS) ---

func scutilStatus(profileName string) (string, error) {
	out, err := exec.Command("scutil", "--nc", "status", profileName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil --nc status %q: %w\n%s", profileName, err, out)
	}
	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	if len(lines) == 0 {
		return "", fmt.Errorf("empty output from scutil --nc status")
	}
	return strings.TrimSpace(lines[0]), nil
}
