package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "wgmgt",
	Short: "Deploy, manage, and visualize kernel WireGuard",
	Long: "WGMGT is a helper tool for deploying, managing, and visualizing " +
		"kernel WireGuard on Linux servers, Docker, and Merlin/OpenWrt routers. " +
		"If the running kernel does not include WireGuard, WGMGT reports the " +
		"system as incompatible (no userspace fallback).",
}

// Execute runs the root command and exits with a non-zero code on failure.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
