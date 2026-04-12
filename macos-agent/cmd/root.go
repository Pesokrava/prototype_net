// Package cmd defines the Cobra root command and registers all subcommands.
package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "macos-agent",
	Short: "prototype-net macOS VPN agent",
	Long: `A CLI agent that automates VPN profile setup, connect/disconnect,
and DNS handling for the prototype-net IPv6 NAT66 transparent proxy.`,
}

func init() {
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(statusCmd)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
