package cli

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/confgen"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
)

var peerCmd = &cobra.Command{
	Use:   "peer",
	Short: "Manage peers of an interface",
}

var peerAddFlags struct {
	name           string
	allowedIPs     string
	endpoint       string
	keepalive      int
	presharedKey   bool
	publicKey      string
	serverEndpoint string
	output         string
}

var peerAddCmd = &cobra.Command{
	Use:   "add [interface]",
	Short: "Add a peer (generates its keys, prints a client conf)",
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
		if peerAddFlags.name == "" {
			return fmt.Errorf("--name is required")
		}

		allowedIPs := peerAddFlags.allowedIPs
		if allowedIPs == "" {
			allowedIPs, err = nextFreeIP(st, ifc)
			if err != nil {
				return err
			}
		}
		for _, s := range strings.Split(allowedIPs, ",") {
			if _, err := netip.ParsePrefix(strings.TrimSpace(s)); err != nil {
				return fmt.Errorf("invalid allowed IP %q: %w", s, err)
			}
		}

		// Either import a peer that manages its own keys (--public-key),
		// or generate a fresh keypair and hand the client conf to the user.
		imported := peerAddFlags.publicKey != ""
		var clientKey wgtypes.Key
		if imported {
			if _, err := wgtypes.ParseKey(peerAddFlags.publicKey); err != nil {
				return fmt.Errorf("invalid --public-key: %w", err)
			}
		} else {
			var err error
			clientKey, err = wgtypes.GeneratePrivateKey()
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}
		}
		p := &store.Peer{
			Interface:  name,
			Name:       peerAddFlags.name,
			AllowedIPs: allowedIPs,
			Endpoint:   peerAddFlags.endpoint,
			Keepalive:  peerAddFlags.keepalive,
		}
		if imported {
			p.PublicKey = peerAddFlags.publicKey
		} else {
			p.PublicKey = clientKey.PublicKey().String()
			p.ClientPrivateKey = clientKey.String()
		}
		if peerAddFlags.presharedKey {
			psk, err := wgtypes.GenerateKey()
			if err != nil {
				return fmt.Errorf("generate preshared key: %w", err)
			}
			p.PresharedKey = psk.String()
		}
		if peerAddFlags.serverEndpoint != "" {
			if err := st.UpdateServerEndpoint(name, peerAddFlags.serverEndpoint); err != nil {
				return err
			}
			ifc.ServerEndpoint = peerAddFlags.serverEndpoint
		}
		if err := st.AddPeer(p); err != nil {
			return fmt.Errorf("store peer: %w", err)
		}
		if err := syncConf(st, name); err != nil {
			return err
		}

		if imported {
			if p.PresharedKey != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "PresharedKey = %s\n", p.PresharedKey)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "# peer %q imported (public key %s, allowed IPs: %s)\n", p.Name, p.PublicKey, p.AllowedIPs)
			return nil
		}
		serverEndpoint := ifc.ServerEndpoint
		if serverEndpoint == "" {
			serverEndpoint = fmt.Sprintf("<server-public-ip>:%d", ifc.ListenPort)
		}
		clientConf, err := confgen.Client(ifc, p, serverEndpoint)
		if err != nil {
			return err
		}
		if peerAddFlags.output != "" {
			if err := os.WriteFile(peerAddFlags.output, []byte(clientConf), 0o600); err != nil {
				return fmt.Errorf("write client conf: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Client conf written to %s (chmod 600)\n", peerAddFlags.output)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), clientConf)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "# peer %q added (allowed IPs: %s)\n", p.Name, p.AllowedIPs)
		return nil
	},
}

var peerListCmd = &cobra.Command{
	Use:   "list [interface]",
	Short: "List peers (with live handshake/traffic when up)",
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
		peers, err := st.ListPeers(name)
		if err != nil {
			return err
		}

		var live map[string]wgctl.PeerStatus
		if wgctl.Exists(name) {
			if live, err = wgctl.DeviceStatus(name); err != nil {
				return err
			}
		}
		out := cmd.OutOrStdout()
		if len(peers) == 0 {
			fmt.Fprintln(out, "no peers yet; add one with `wgmgt peer add`")
			return nil
		}
		fmt.Fprintf(out, "%-3s %-12s %-14s %-24s %s\n", "ID", "NAME", "PUBLIC KEY", "ALLOWED IPS", "LIVE (handshake / rx / tx)")
		for _, p := range peers {
			liveCol := "-"
			if s, ok := live[p.PublicKey]; ok {
				liveCol = fmt.Sprintf("%s / %s / %s",
					humanDuration(timeSince(s.LastHandshake)), humanBytes(s.Rx), humanBytes(s.Tx))
			}
			fmt.Fprintf(out, "%-3d %-12s %-14s %-24s %s\n",
				p.ID, p.Name, shortKey(p.PublicKey), p.AllowedIPs, liveCol)
		}
		return nil
	},
}

var peerRmCmd = &cobra.Command{
	Use:   "rm <interface> <peer>",
	Short: "Remove a peer (by name, public key, or ID)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		p, err := st.DeletePeer(args[0], args[1])
		if err != nil {
			return err
		}
		if err := syncConf(st, args[0]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "peer %q removed\n", p.Name)
		return nil
	},
}

var peerConfCmd = &cobra.Command{
	Use:   "conf <interface> <peer>",
	Short: "Re-print a peer's client conf",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		ifc, err := st.GetInterface(args[0])
		if err != nil {
			return err
		}
		p, err := st.GetPeer(args[0], args[1])
		if err != nil {
			return err
		}
		serverEndpoint := ifc.ServerEndpoint
		if serverEndpoint == "" {
			serverEndpoint = fmt.Sprintf("<server-public-ip>:%d", ifc.ListenPort)
		}
		clientConf, err := confgen.Client(ifc, p, serverEndpoint)
		if err != nil {
			return err
		}
		fmt.Fprint(cmd.OutOrStdout(), clientConf)
		return nil
	},
}

func init() {
	peerAddCmd.Flags().StringVar(&peerAddFlags.name, "name", "", "peer label (required)")
	peerAddCmd.Flags().StringVar(&peerAddFlags.allowedIPs, "allowed-ips", "", "comma-separated CIDRs (default: next free IP in the tunnel subnet)")
	peerAddCmd.Flags().StringVar(&peerAddFlags.endpoint, "endpoint", "", "peer's public endpoint host:port (roaming peers can omit)")
	peerAddCmd.Flags().StringVar(&peerAddFlags.publicKey, "public-key", "", "import a peer that manages its own keys (no client conf generated)")
	peerAddCmd.Flags().IntVar(&peerAddFlags.keepalive, "keepalive", 0, "persistent keepalive seconds (0 = off)")
	peerAddCmd.Flags().BoolVar(&peerAddFlags.presharedKey, "preshared-key", false, "also generate a preshared key")
	peerAddCmd.Flags().StringVar(&peerAddFlags.serverEndpoint, "server-endpoint", "", "this host's public endpoint, stored for client confs")
	peerAddCmd.Flags().StringVar(&peerAddFlags.output, "output", "", "write client conf to file instead of stdout")
	peerCmd.AddCommand(peerAddCmd, peerListCmd, peerRmCmd, peerConfCmd)
	rootCmd.AddCommand(peerCmd)
}

// nextFreeIP picks the next unused host address in the interface's tunnel
// subnet (IPv4 only; IPv6 interfaces must use --allowed-ips).
func nextFreeIP(st *store.Store, ifc *store.Interface) (string, error) {
	prefix, err := netip.ParsePrefix(ifc.Address)
	if err != nil {
		return "", fmt.Errorf("interface address %q: %w", ifc.Address, err)
	}
	addr := prefix.Addr()
	if !addr.Is4() {
		return "", fmt.Errorf("automatic IP assignment needs an IPv4 tunnel; pass --allowed-ips")
	}
	peers, err := st.ListPeers(ifc.Name)
	if err != nil {
		return "", err
	}
	used := map[netip.Addr]bool{addr: true}
	for _, p := range peers {
		for _, s := range strings.Split(p.AllowedIPs, ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(strings.TrimSuffix(s, "/32"))); err == nil {
				used[a] = true
			}
		}
	}
	base := addr.As4()
	for i := 2; i < 255; i++ {
		cand := netip.AddrFrom4([4]byte{base[0], base[1], base[2], byte(i)})
		if !used[cand] {
			return netip.PrefixFrom(cand, 32).String(), nil
		}
	}
	return "", fmt.Errorf("tunnel subnet %s is full; pass --allowed-ips", prefix.Masked())
}

func shortKey(pub string) string {
	if len(pub) <= 12 {
		return pub
	}
	return pub[:8] + "…" + pub[len(pub)-3:]
}
