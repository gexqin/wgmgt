package cli

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgkern"
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

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

		name := initFlags.name
		if !cmd.Flags().Changed("name") {
			name = prompt("Interface name", "wg0")
		}
		if !nameRe.MatchString(name) {
			return fmt.Errorf("invalid interface name %q (max 15 chars, [a-zA-Z0-9_-])", name)
		}
		if _, err := st.GetInterface("", name); err == nil {
			return fmt.Errorf("interface %q already exists", name)
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
		if !cmd.Flags().Changed("port") && port == 0 {
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

func init() {
	initCmd.Flags().StringVar(&initFlags.name, "name", "wg0", "interface name")
	initCmd.Flags().StringVar(&initFlags.address, "address", "10.0.0.1/24", "tunnel address in CIDR form")
	initCmd.Flags().IntVar(&initFlags.port, "port", 51820, "UDP listen port (0 = ephemeral)")
	initCmd.Flags().IntVar(&initFlags.mtu, "mtu", 0, "MTU (0 = kernel default)")
	initCmd.Flags().StringVar(&initFlags.dns, "dns", "", "DNS advertised to peers")
	rootCmd.AddCommand(initCmd)
}
