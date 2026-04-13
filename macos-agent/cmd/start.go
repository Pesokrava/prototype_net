package cmd

import (
	"fmt"
	"os/exec"

	"prototype-net/macos-agent/internal/dns"
	"prototype-net/macos-agent/internal/network"
	"prototype-net/macos-agent/internal/state"
	"prototype-net/macos-agent/internal/vpn"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start VPN and configure DNS",
	Long: `Read saved configuration, ensure IPv6 is enabled, backup current
DNS settings, set DNS to the prototype-net server, and wait for the user
to connect the VPN via System Settings.`,
	RunE: runStart,
}

func runStart(cmd *cobra.Command, args []string) error {
	// Step 1: Load config.
	cfg, err := state.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Step 2: Ensure IPv6 is enabled on the active network service.
	// macOS's getaddrinfo() silently drops AAAA results unless the system
	// considers IPv6 "reachable". Running `networksetup -setv6automatic`
	// once fixes this. It's idempotent and persists across reboots.
	fmt.Println("==> Ensuring IPv6 is enabled...")
	service, err := network.ActiveService()
	if err != nil {
		return fmt.Errorf("detecting active network service: %w", err)
	}
	if out, err := exec.Command("networksetup", "-setv6automatic", service).CombinedOutput(); err != nil {
		fmt.Printf("    warning: could not enable IPv6 on %q: %v\n%s", service, err, out)
	} else {
		fmt.Printf("    IPv6 automatic enabled on %q\n", service)
	}

	// Step 3: Check if VPN is already connected.
	alreadyConnected, _ := vpn.IsConnected(cfg.ProfileName)
	if alreadyConnected {
		fmt.Println("==> VPN is already connected.")
	}

	// Step 4: Backup DNS and set prototype-net DNS server.
	fmt.Printf("==> Backing up DNS and setting DNS to %s...\n", cfg.DNSIP)
	svc, err := dns.BackupAndSet(cfg.DNSIP)
	if err != nil {
		return fmt.Errorf("DNS backup and set: %w", err)
	}
	fmt.Printf("    Active service: %s\n", svc)

	// Step 5: Flush DNS cache so the new DNS server is used immediately.
	fmt.Println("==> Flushing DNS cache...")
	if err := dns.FlushCache(); err != nil {
		fmt.Printf("    warning: cache flush failed: %v\n", err)
	}

	// Step 6: Wait for VPN connection (prompt user to connect via UI).
	if !alreadyConnected {
		fmt.Printf("==> Waiting for VPN '%s' to connect...\n", cfg.ProfileName)
		if err := vpn.WaitForConnection(cfg.ProfileName, 0); err != nil {
			// VPN didn't connect — restore DNS before failing.
			fmt.Println("    VPN connection timed out, restoring DNS...")
			if restoreErr := dns.Restore(); restoreErr != nil {
				fmt.Printf("    warning: DNS restore also failed: %v\n", restoreErr)
			}
			return fmt.Errorf("waiting for VPN: %w", err)
		}
		fmt.Println("    VPN connected.")
	}

	// Step 7: Verify route.
	hasRoute, err := vpn.HasIPv6Route(cfg.SyntheticPrefix)
	if err != nil {
		fmt.Printf("    warning: could not check IPv6 route: %v\n", err)
	} else if hasRoute {
		fmt.Printf("    IPv6 route for %s is present.\n", cfg.SyntheticPrefix)
	} else {
		fmt.Printf("    warning: IPv6 route for %s not found. Traffic may not route correctly.\n", cfg.SyntheticPrefix)
	}

	fmt.Println("==> Start complete.")
	return nil
}
