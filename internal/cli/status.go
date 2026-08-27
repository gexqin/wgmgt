package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/wgctl"
)

var statusCmd = &cobra.Command{
	Use:   "status [interface]",
	Short: "Show managed interfaces and live peer state",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		name, err := resolveIface(st, arg(args))
		if err != nil {
			return err
		}
		ifc, err := st.GetInterface(name)
		if err != nil {
			return err
		}
		peers, err := st.ListPeers(name)
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		up := wgctl.Exists(name)
		state := "down"
		if up {
			state = "up"
		}
		fmt.Fprintf(out, "%s: %s, %s, port %d, %d peers\n",
			ifc.Name, state, ifc.Address, ifc.ListenPort, len(peers))
		if !up {
			return nil
		}

		live, err := wgctl.DeviceStatus(name)
		if err != nil {
			return err
		}
		for _, p := range peers {
			s, ok := live[p.PublicKey]
			if !ok {
				continue // configured in DB but not applied to the device
			}
			fmt.Fprintf(out, "  %-12s handshake %-6s rx %-8s tx %-8s %s\n",
				p.Name, humanDuration(timeSince(s.LastHandshake)),
				humanBytes(s.Rx), humanBytes(s.Tx),
				orDash(s.Endpoint))
		}
		return nil
	},
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
