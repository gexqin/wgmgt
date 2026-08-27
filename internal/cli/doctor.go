package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"wgmgt/internal/wgkern"
)

var errIncompatible = errors.New("system incompatible: kernel WireGuard not found")

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check kernel WireGuard compatibility",
	RunE: func(cmd *cobra.Command, args []string) error {
		r := wgkern.Detect()
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Kernel: %s\n", r.KernelRelease)
		for _, n := range r.Notes {
			fmt.Fprintf(out, "  - %s\n", n)
		}
		switch r.Status {
		case wgkern.StatusAvailable:
			fmt.Fprintln(out, "Verdict: COMPATIBLE — kernel WireGuard is usable")
			return nil
		case wgkern.StatusLoadable:
			fmt.Fprintln(out, "Verdict: COMPATIBLE — module present but not loaded")
			fmt.Fprintln(out, "  load it with: sudo modprobe wireguard")
			return nil
		default:
			fmt.Fprintln(out, "Verdict: INCOMPATIBLE — no kernel WireGuard on this system")
			return errIncompatible
		}
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
