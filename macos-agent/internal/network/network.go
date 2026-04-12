// Package network detects the active macOS network service
// (e.g. "Wi-Fi", "Ethernet") by correlating the default route
// interface with networksetup's service list.
package network

import (
	"fmt"
	"os/exec"
	"strings"
)

// ActiveService returns the name of the macOS network service
// currently handling the default route (e.g. "Wi-Fi").
func ActiveService() (string, error) {
	// Step 1: Find the default route interface.
	iface, err := defaultRouteInterface()
	if err != nil {
		return "", fmt.Errorf("finding default route interface: %w", err)
	}

	// Step 2: Map interface to network service name.
	service, err := serviceForInterface(iface)
	if err != nil {
		return "", fmt.Errorf("mapping interface %q to service: %w", iface, err)
	}

	return service, nil
}

// defaultRouteInterface returns the network interface used for the default route.
func defaultRouteInterface() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route -n get default: %w\n%s", err, out)
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("could not find 'interface:' in route output")
}

// serviceForInterface maps a BSD interface name (e.g. "en0") to a
// macOS network service name (e.g. "Wi-Fi").
func serviceForInterface(iface string) (string, error) {
	out, err := exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("networksetup -listallhardwareports: %w\n%s", err, out)
	}

	lines := strings.Split(string(out), "\n")
	var currentService string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			currentService = strings.TrimPrefix(line, "Hardware Port: ")
		}
		if strings.HasPrefix(line, "Device:") {
			device := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if device == iface {
				return currentService, nil
			}
		}
	}

	return "", fmt.Errorf("no network service found for interface %q", iface)
}

// DNSServers returns the current DNS servers for the given network service.
func DNSServers(service string) ([]string, error) {
	out, err := exec.Command("networksetup", "-getdnsservers", service).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("networksetup -getdnsservers %q: %w\n%s", service, err, out)
	}

	output := strings.TrimSpace(string(out))

	// "There aren't any DNS Servers set on <service>." means empty/DHCP.
	if strings.Contains(output, "There aren't any DNS Servers") {
		return nil, nil
	}

	var servers []string
	for _, line := range strings.Split(output, "\n") {
		s := strings.TrimSpace(line)
		if s != "" {
			servers = append(servers, s)
		}
	}

	return servers, nil
}
