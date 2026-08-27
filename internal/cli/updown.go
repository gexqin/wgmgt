package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/wgctl"
)

var upCmd = &cobra.Command{
	Use:   "up [interface]",
	Short: "Bring a managed interface up",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRoot(); err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		name, err := resolveIface(st, arg(args))
		if err != nil {
			return err
		}
		ifc, err := st.GetInterface("", name)
		if err != nil {
			return err
		}
		peers, err := st.ListPeers("", name)
		if err != nil {
			return err
		}
		if err := wgctl.Up(ifc, peers); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s up (%s, %d peers)\n", name, ifc.Address, len(peers))
		return nil
	},
}

var downCmd = &cobra.Command{
	Use:   "down [interface]",
	Short: "Bring a managed interface down (removes the device)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRoot(); err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		name, err := resolveIface(st, arg(args))
		if err != nil {
			return err
		}
		ifc, err := st.GetInterface("", name)
		if err != nil {
			return err
		}
		if err := wgctl.Down(ifc); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s down\n", name)
		return nil
	},
}

func arg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

func init() {
	rootCmd.AddCommand(upCmd, downCmd)
}
