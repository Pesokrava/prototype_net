package cmd

import (
	"fmt"

	"prototype-net/macos-agent/internal/dns"
	"prototype-net/macos-agent/internal/state"
	"prototype-net/macos-agent/internal/vpn"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start VPN and configure DNS",
	Long: `Read saved configuration, backup current DNS settings,
set DNS to the prototype-net server, and start the VPN connection.`,
	RunE: runStart,
}

func runStart(cmd *cobra.Command, args []string) error {
	// Step 1: Load config.
	cfg, err := state.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Step 2: Backup DNS and set prototype-net DNS server.
	fmt.Printf("==> Backing up DNS and setting DNS to %s...\n", cfg.DNSIP)
	service, err := dns.BackupAndSet(cfg.DNSIP)
	if err != nil {
		return fmt.Errorf("DNS backup and set: %w", err)
	}
	fmt.Printf("    Active service: %s\n", service)

	// Step 3: Start VPN.
	fmt.Printf("==> Starting VPN '%s'...\n", cfg.ProfileName)
	if err := vpn.Start(cfg.ProfileName); err != nil {
		// Try to restore DNS on VPN failure.
		fmt.Println("    VPN start failed, restoring DNS...")
		if restoreErr := dns.Restore(); restoreErr != nil {
			fmt.Printf("    warning: DNS restore also failed: %v\n", restoreErr)
		}
		return fmt.Errorf("starting VPN: %w", err)
	}
	fmt.Println("    VPN connected.")

	// Step 4: Verify route.
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
