package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Set at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("wgmgt %s (%s) %s/%s\n", version, commit, runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
