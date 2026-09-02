package cli

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/confgen"
	"github.com/gexqin/wgmgt/internal/fileutil"
	"github.com/gexqin/wgmgt/internal/humanize"
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
		a := newApp(st)
		name, err := resolveIface(st, arg(args))
		if err != nil {
			return err
		}
		ifc, err := st.GetInterface("", name)
		if err != nil {
			return err
		}
		if !store.ValidPeerName(peerAddFlags.name) {
			return fmt.Errorf("invalid --name %q: must match ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", peerAddFlags.name)
		}
		if peerAddFlags.keepalive < 0 || peerAddFlags.keepalive > 65535 {
			return fmt.Errorf("--keepalive must be between 0 and 65535")
		}
		if err := validateCLIEndpoint(peerAddFlags.endpoint); err != nil {
			return fmt.Errorf("invalid --endpoint: %w", err)
		}
		if err := validateCLIEndpoint(peerAddFlags.serverEndpoint); err != nil {
			return fmt.Errorf("invalid --server-endpoint: %w", err)
		}

		allowedIPs := peerAddFlags.allowedIPs
		if allowedIPs == "" {
			allowedIPs, err = a.NextFreeIP(ifc)
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
			if err := st.UpdateServerEndpoint("", name, peerAddFlags.serverEndpoint); err != nil {
				return err
			}
			ifc.ServerEndpoint = peerAddFlags.serverEndpoint
		}
		if err := st.AddPeer(p); err != nil {
			return fmt.Errorf("store peer: %w", err)
		}
		if err := a.SyncConf(name); err != nil {
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
			if err := fileutil.WriteAtomic(peerAddFlags.output, []byte(clientConf), 0o600); err != nil {
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

func validateCLIEndpoint(value string) error {
	if value == "" {
		return nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("must be host:port (IPv6 addresses need brackets)")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
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
		peers, err := st.ListPeers("", name)
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
					humanize.Duration(humanize.Since(s.LastHandshake)), humanize.Bytes(s.Rx), humanize.Bytes(s.Tx))
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
		p, err := st.DeletePeer("", args[0], args[1])
		if err != nil {
			return err
		}
		if err := newApp(st).SyncConf(args[0]); err != nil {
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
		ifc, err := st.GetInterface("", args[0])
		if err != nil {
			return err
		}
		p, err := st.GetPeer("", args[0], args[1])
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

func shortKey(pub string) string {
	if len(pub) <= 12 {
		return pub
	}
	return pub[:8] + "…" + pub[len(pub)-3:]
}
