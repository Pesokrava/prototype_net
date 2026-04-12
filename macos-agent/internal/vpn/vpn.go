// Package vpn manages the macOS IKEv2 VPN connection via scutil --nc.
package vpn

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const defaultTimeout = 15 * time.Second

// Status returns the current VPN connection status string
// for the named profile (e.g. "Connected", "Disconnected").
func Status(profileName string) (string, error) {
	out, err := exec.Command("scutil", "--nc", "status", profileName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil --nc status %q: %w\n%s", profileName, err, out)
	}

	// The first line of output is the status keyword.
	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	if len(lines) == 0 {
		return "", fmt.Errorf("empty output from scutil --nc status")
	}

	return strings.TrimSpace(lines[0]), nil
}

// Start initiates the VPN connection and polls until connected or timeout.
func Start(profileName string) error {
	out, err := exec.Command("scutil", "--nc", "start", profileName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil --nc start %q: %w\n%s", profileName, err, out)
	}

	// Poll for connection status.
	deadline := time.Now().Add(defaultTimeout)
	for time.Now().Before(deadline) {
		status, err := Status(profileName)
		if err != nil {
			return fmt.Errorf("polling VPN status: %w", err)
		}
		if status == "Connected" {
			return nil
		}
		if status == "Disconnected" || status == "Invalid" {
			return fmt.Errorf("VPN connection failed (status: %s)", status)
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("VPN connection timed out after %s", defaultTimeout)
}

// Stop terminates the VPN connection.
func Stop(profileName string) error {
	out, err := exec.Command("scutil", "--nc", "stop", profileName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil --nc stop %q: %w\n%s", profileName, err, out)
	}
	return nil
}

// IsConnected returns true if the VPN is currently connected.
func IsConnected(profileName string) (bool, error) {
	status, err := Status(profileName)
	if err != nil {
		return false, err
	}
	return status == "Connected", nil
}

// HasIPv6Route checks if an IPv6 route exists for the given prefix.
func HasIPv6Route(prefix string) (bool, error) {
	out, err := exec.Command("netstat", "-rn", "-f", "inet6").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("netstat -rn -f inet6: %w", err)
	}

	// Strip the prefix length suffix for matching (e.g. "fd00:abcd::" from "fd00:abcd::/32").
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
