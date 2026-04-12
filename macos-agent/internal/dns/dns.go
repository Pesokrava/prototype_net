// Package dns handles DNS server backup and restore via macOS networksetup.
package dns

import (
	"fmt"
	"os/exec"
	"strings"

	"prototype-net/macos-agent/internal/network"
	"prototype-net/macos-agent/internal/state"
)

// BackupAndSet saves the current DNS servers for the active network service,
// then sets DNS to the specified IP. Returns the service name that was modified.
func BackupAndSet(dnsIP string) (string, error) {
	service, err := network.ActiveService()
	if err != nil {
		return "", fmt.Errorf("detecting active network service: %w", err)
	}

	// Get current DNS servers.
	servers, err := network.DNSServers(service)
	if err != nil {
		return "", fmt.Errorf("getting current DNS servers: %w", err)
	}

	// Save backup.
	backup := &state.DNSBackup{
		Service: service,
		Servers: servers,
	}
	if err := state.SaveDNSBackup(backup); err != nil {
		return "", fmt.Errorf("saving DNS backup: %w", err)
	}

	// Set DNS to the prototype-net DNS server.
	if err := setDNS(service, dnsIP); err != nil {
		return "", fmt.Errorf("setting DNS: %w", err)
	}

	return service, nil
}

// Restore restores DNS servers from the saved backup.
func Restore() error {
	backup, err := state.LoadDNSBackup()
	if err != nil {
		return fmt.Errorf("loading DNS backup: %w", err)
	}

	if err := restoreDNS(backup.Service, backup.Servers); err != nil {
		return fmt.Errorf("restoring DNS: %w", err)
	}

	if err := state.RemoveDNSBackup(); err != nil {
		return fmt.Errorf("removing DNS backup file: %w", err)
	}

	return nil
}

// FlushCache flushes the macOS DNS resolver cache.
func FlushCache() error {
	if err := exec.Command("dscacheutil", "-flushcache").Run(); err != nil {
		return fmt.Errorf("dscacheutil -flushcache: %w", err)
	}
	// killall mDNSResponder — ignore error if it's not running.
	_ = exec.Command("killall", "mDNSResponder").Run()
	return nil
}

// setDNS sets the DNS server for the given network service.
func setDNS(service, ip string) error {
	out, err := exec.Command("networksetup", "-setdnsservers", service, ip).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup -setdnsservers %q %q: %w\n%s", service, ip, err, out)
	}
	return nil
}

// restoreDNS restores DNS servers for the given network service.
func restoreDNS(service string, servers []string) error {
	args := []string{"-setdnsservers", service}
	if len(servers) == 0 {
		// "Empty" means DHCP-provided DNS — pass "Empty" to networksetup.
		args = append(args, "Empty")
	} else {
		args = append(args, servers...)
	}

	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return nil
}
