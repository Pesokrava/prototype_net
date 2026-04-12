package cmd

import (
	"fmt"
	"strings"

	"prototype-net/macos-agent/internal/network"
	"prototype-net/macos-agent/internal/state"
	"prototype-net/macos-agent/internal/vpn"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show VPN and DNS status",
	Long:  `Display current VPN connection status, DNS configuration, and route presence.`,
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	// Config file presence.
	fmt.Println("--- Local State ---")
	if state.ConfigExists() {
		fmt.Println("  Config:     ~/.prototype-net/config.json  [exists]")
	} else {
		fmt.Println("  Config:     ~/.prototype-net/config.json  [missing — run 'setup' first]")
		return nil
	}
	if state.DNSBackupExists() {
		fmt.Println("  DNS backup: ~/.prototype-net/dns-backup.json  [exists]")
	} else {
		fmt.Println("  DNS backup: ~/.prototype-net/dns-backup.json  [none]")
	}

	cfg, err := state.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// VPN status.
	fmt.Println("")
	fmt.Println("--- VPN ---")
	vpnStatus, err := vpn.Status(cfg.ProfileName)
	if err != nil {
		fmt.Printf("  Status:  error — %v\n", err)
	} else {
		fmt.Printf("  Profile: %s\n", cfg.ProfileName)
		fmt.Printf("  Status:  %s\n", vpnStatus)
	}

	// Network service + DNS.
	fmt.Println("")
	fmt.Println("--- Network ---")
	service, err := network.ActiveService()
	if err != nil {
		fmt.Printf("  Active service: error — %v\n", err)
	} else {
		fmt.Printf("  Active service: %s\n", service)

		servers, err := network.DNSServers(service)
		if err != nil {
			fmt.Printf("  DNS servers:    error — %v\n", err)
		} else if len(servers) == 0 {
			fmt.Println("  DNS servers:    (DHCP default)")
		} else {
			fmt.Printf("  DNS servers:    %s\n", strings.Join(servers, ", "))
		}
	}

	// Route check.
	fmt.Println("")
	fmt.Println("--- Routing ---")
	hasRoute, err := vpn.HasIPv6Route(cfg.SyntheticPrefix)
	if err != nil {
		fmt.Printf("  Synthetic prefix route (%s): error — %v\n", cfg.SyntheticPrefix, err)
	} else if hasRoute {
		fmt.Printf("  Synthetic prefix route (%s): present\n", cfg.SyntheticPrefix)
	} else {
		fmt.Printf("  Synthetic prefix route (%s): absent\n", cfg.SyntheticPrefix)
	}

	return nil
}
