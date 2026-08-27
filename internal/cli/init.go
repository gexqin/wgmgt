package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
	"github.com/gexqin/wgmgt/internal/wgkern"
)

var initFlags struct {
	name    string
	address string
	port    int
	mtu     int
	dns     string
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a WireGuard interface (wizard with flag overrides)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if r := wgkern.Detect(); r.Status == wgkern.StatusMissing {
			return errIncompatible
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()

		if err := offerStopForeignWG(cmd, st); err != nil {
			return err
		}

		name := initFlags.name
		if !cmd.Flags().Changed("name") {
			name = prompt("Interface name", "wg0")
		}
		if !store.ValidIfaceName(name) {
			return fmt.Errorf("invalid interface name %q (max 15 chars, [a-zA-Z0-9_-])", name)
		}
		if existing, err := st.GetInterface("", name); err == nil {
			if err := offerDeleteExisting(cmd, st, existing); err != nil {
				if errors.Is(err, errKeepExisting) {
					return nil
				}
				return err
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		address := initFlags.address
		if !cmd.Flags().Changed("address") {
			address = prompt("Tunnel address (CIDR)", "10.0.0.1/24")
		}
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", address, err)
		}

		port := initFlags.port
		if !cmd.Flags().Changed("port") {
			port, _ = strconv.Atoi(prompt("Listen port", "51820"))
		}
		if port < 0 || port > 65535 {
			return fmt.Errorf("invalid port %d", port)
		}

		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		ifc := &store.Interface{
			Enabled:    true,
			Name:       name,
			PrivateKey: key.String(),
			ListenPort: port,
			Address:    prefix.String(),
			MTU:        initFlags.mtu,
			DNS:        initFlags.dns,
		}
		if err := st.CreateInterface(ifc); err != nil {
			return fmt.Errorf("store interface: %w", err)
		}
		if err := newApp(st).SyncConf(name); err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Interface %s created\n", name)
		fmt.Fprintf(out, "  Address:     %s\n", ifc.Address)
		fmt.Fprintf(out, "  Listen port: %d\n", ifc.ListenPort)
		fmt.Fprintf(out, "  Public key:  %s\n", key.PublicKey().String())
		fmt.Fprintf(out, "  Conf file:   %s\n", confPath(name))
		fmt.Fprintf(out, "\nNext: `wgmgt peer add %s` then `sudo wgmgt up %s`\n", name, name)
		return nil
	},
}

// offerDeleteExisting is called from init when the chosen name is already
// managed by wgmgt. The user can delete the old config and re-initialize
// (init then continues its wizard with a clean slate), or keep it (init
// exits with next-step hints). Non-interactive runs keep it — same safety
// default as before, when init simply refused.
func offerDeleteExisting(cmd *cobra.Command, st *store.Store, ifc *store.Interface) error {
	peers, err := st.ListPeers("", ifc.Name)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "\nInterface %q is already managed by wgmgt:\n  %s\n", ifc.Name, describeInterface(ifc, len(peers)))
	if !confirm("Delete it and re-initialize?", false) {
		fmt.Fprintf(out, "Keeping it. Next: `wgmgt peer add %s` then `sudo wgmgt up %s` (or `wgmgt delete %s` to remove it)\n",
			ifc.Name, ifc.Name, ifc.Name)
		return errKeepExisting
	}
	return removeInterface(cmd, st, ifc)
}

// offerStopForeignWG warns about WireGuard devices that are up but not
// managed by wgmgt (typically a wg-quick service) and offers to stop them —
// a service left running would fight wgmgt over the device and its routing.
func offerStopForeignWG(cmd *cobra.Command, st *store.Store) error {
	devices, err := wgctl.RunningDevices()
	if err != nil {
		// Read-only probing; don't block init on it.
		fmt.Fprintf(cmd.OutOrStderr(), "warning: cannot list running WireGuard devices: %v\n", err)
		return nil
	}
	managed, err := st.ListInterfaces("")
	if err != nil {
		return err
	}
	ours := make(map[string]bool, len(managed))
	for _, ifc := range managed {
		ours[ifc.Name] = true
	}
	var foreign []string
	for _, name := range devices {
		if !ours[name] {
			foreign = append(foreign, name)
		}
	}
	if len(foreign) == 0 {
		return nil
	}

	out := cmd.OutOrStderr()
	fmt.Fprintf(out, "\nWireGuard device(s) already up but not managed by wgmgt: %s\n",
		strings.Join(foreign, ", "))
	fmt.Fprintf(out, "A wg-quick service left running will fight wgmgt over the device.\n")
	if !confirm("Stop them now?", false) {
		fmt.Fprintf(out, "Leaving them running; a name collision will make `wgmgt up` fail.\n")
		return nil
	}
	if err := requireRoot(); err != nil {
		return err
	}
	for _, name := range foreign {
		byService, err := wgctl.StopExternal(name)
		if err != nil {
			fmt.Fprintf(out, "  %s: %v\n", name, err)
			continue
		}
		if byService {
			fmt.Fprintf(out, "  %s: stopped wg-quick@%s.service (consider `systemctl disable` to keep it down across reboots)\n", name, name)
		} else {
			fmt.Fprintf(out, "  %s: device removed\n", name)
		}
	}
	return nil
}

func init() {
	initCmd.Flags().StringVar(&initFlags.name, "name", "wg0", "interface name")
	initCmd.Flags().StringVar(&initFlags.address, "address", "10.0.0.1/24", "tunnel address in CIDR form")
	initCmd.Flags().IntVar(&initFlags.port, "port", 51820, "UDP listen port (0 = ephemeral)")
	initCmd.Flags().IntVar(&initFlags.mtu, "mtu", 0, "MTU (0 = kernel default)")
	initCmd.Flags().StringVar(&initFlags.dns, "dns", "", "DNS advertised to peers")
	rootCmd.AddCommand(initCmd)
}
