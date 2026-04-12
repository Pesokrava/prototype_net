package cmd

import (
	"fmt"

	"prototype-net/macos-agent/internal/dns"
	"prototype-net/macos-agent/internal/state"
	"prototype-net/macos-agent/internal/vpn"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop VPN and restore DNS",
	Long: `Stop the VPN connection, restore original DNS servers,
and flush the DNS resolver cache.`,
	RunE: runStop,
}

func runStop(cmd *cobra.Command, args []string) error {
	// Step 1: Load config.
	cfg, err := state.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Step 2: Stop VPN.
	fmt.Printf("==> Stopping VPN '%s'...\n", cfg.ProfileName)
	if err := vpn.Stop(cfg.ProfileName); err != nil {
		return fmt.Errorf("stopping VPN: %w", err)
	}
	fmt.Println("    VPN stopped.")

	// Step 3: Restore DNS.
	if state.DNSBackupExists() {
		fmt.Println("==> Restoring DNS...")
		if err := dns.Restore(); err != nil {
			return fmt.Errorf("restoring DNS: %w", err)
		}
		fmt.Println("    DNS restored.")
	} else {
		fmt.Println("    No DNS backup found, skipping DNS restore.")
	}

	// Step 4: Flush resolver cache.
	fmt.Println("==> Flushing DNS cache...")
	if err := dns.FlushCache(); err != nil {
		fmt.Printf("    warning: cache flush failed: %v\n", err)
	} else {
		fmt.Println("    DNS cache flushed.")
	}

	fmt.Println("==> Stop complete.")
	return nil
}
