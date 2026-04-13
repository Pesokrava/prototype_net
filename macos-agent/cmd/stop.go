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
	Long: `Check VPN status, prompt the user to disconnect via System Settings
if still connected, restore original DNS servers, and flush the DNS
resolver cache.`,
	RunE: runStop,
}

func runStop(cmd *cobra.Command, args []string) error {
	// Step 1: Load config.
	cfg, err := state.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Step 2: Check VPN status and wait for user to disconnect.
	fmt.Printf("==> Checking VPN '%s' status...\n", cfg.ProfileName)
	connected, err := vpn.IsConnected(cfg.ProfileName)
	if err != nil {
		fmt.Printf("    warning: could not check VPN status: %v\n", err)
		fmt.Println("    Proceeding with DNS restore anyway.")
	} else if connected {
		fmt.Println("    VPN is still connected.")
		if err := vpn.WaitForDisconnection(cfg.ProfileName, 0); err != nil {
			return fmt.Errorf("waiting for VPN disconnect: %w", err)
		}
		fmt.Println("    VPN disconnected.")
	} else {
		fmt.Println("    VPN is already disconnected.")
	}

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
