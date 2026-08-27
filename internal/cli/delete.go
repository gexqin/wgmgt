package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
)

// errKeepExisting makes init exit cleanly when the user chooses to keep an
// already-managed interface instead of re-creating it.
var errKeepExisting = errors.New("kept existing interface")

var deleteFlags struct {
	yes bool
}

var deleteCmd = &cobra.Command{
	Use:   "delete [interface]",
	Short: "Delete a managed interface (device if up, peers, conf file, DB record)",
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
		ifc, err := st.GetInterface("", name)
		if err != nil {
			return err
		}
		peers, err := st.ListPeers("", name)
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		fmt.Fprintln(out, describeInterface(ifc, len(peers)))
		if !deleteFlags.yes && !confirm(fmt.Sprintf("Delete %s and its %d peer(s)?", name, len(peers)), false) {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}
		if err := removeInterface(cmd, st, ifc); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s deleted\n", name)
		return nil
	},
}

// removeInterface tears down a managed interface for good: device (if up,
// running PostDown and cleaning policy rules via Down), peers and DB record
// (cascade), and the conf file. Root is only required when the device is up.
func removeInterface(cmd *cobra.Command, st *store.Store, ifc *store.Interface) error {
	if wgctl.Exists(ifc.Name) {
		if err := requireRoot(); err != nil {
			return err
		}
		if err := wgctl.Down(ifc); err != nil {
			return fmt.Errorf("bring %s down: %w", ifc.Name, err)
		}
	}
	if err := st.DeleteInterface("", ifc.Name); err != nil {
		return fmt.Errorf("delete from store: %w", err)
	}
	if err := os.Remove(confPath(ifc.Name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The DB row is already gone; don't fail the whole delete over a file.
		fmt.Fprintf(cmd.OutOrStderr(), "warning: could not remove conf file: %v\n", err)
	}
	return nil
}

func init() {
	deleteCmd.Flags().BoolVarP(&deleteFlags.yes, "yes", "y", false, "skip confirmation")
	rootCmd.AddCommand(deleteCmd)
}
