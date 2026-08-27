// Package confgen renders wg-quick-compatible configuration files from
// stored state. The conf files are generated artifacts: SQLite remains the
// single source of truth.
package confgen

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gexqin/wgmgt/internal/store"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Interface renders the server-side wg-quick conf for an interface and its
// peers. The output is also what `wg-quick up <file>` accepts.
func Interface(ifc *store.Interface, peers []store.Peer) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", ifc.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", ifc.Address)
	if ifc.ListenPort != 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", ifc.ListenPort)
	}
	if ifc.MTU != 0 {
		fmt.Fprintf(&b, "MTU = %d\n", ifc.MTU)
	}
	if ifc.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", ifc.DNS)
	}
	if ifc.RouteTable != "" {
		fmt.Fprintf(&b, "Table = %s\n", ifc.RouteTable)
	}
	if ifc.Fwmark != "" {
		fmt.Fprintf(&b, "FwMark = %s\n", ifc.Fwmark)
	}
	if ifc.PostUp != "" {
		fmt.Fprintf(&b, "PostUp = %s\n", ifc.PostUp)
	}
	if ifc.PostDown != "" {
		fmt.Fprintf(&b, "PostDown = %s\n", ifc.PostDown)
	}
	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", p.AllowedIPs)
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.Keepalive != 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return b.String()
}

// Client renders a client-side conf for a peer of ifc. serverEndpoint is
// this host's public WireGuard endpoint (may be host:port or a
// space-separated list of them). The client's Address is its first allowed
// IP; AllowedIPs is the tunnel subnet, so traffic to sibling peers and the
// server flows through the tunnel. Full-tunnel (0.0.0.0/0) is a client-side
// choice the user can make by editing the generated conf.
func Client(ifc *store.Interface, p *store.Peer, serverEndpoint string) (string, error) {
	clientIP := p.AllowedIPs
	if i := strings.IndexByte(clientIP, ','); i >= 0 {
		clientIP = clientIP[:i]
	}
	tunnelPrefix, err := netip.ParsePrefix(ifc.Address)
	if err != nil {
		return "", fmt.Errorf("interface address %q: %w", ifc.Address, err)
	}
	serverKey, err := wgtypes.ParseKey(ifc.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("interface private key: %w", err)
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.ClientPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", clientIP)
	if ifc.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", ifc.DNS)
	}
	if ifc.MTU != 0 {
		fmt.Fprintf(&b, "MTU = %d\n", ifc.MTU)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverKey.PublicKey().String())
	if p.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", serverEndpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", tunnelPrefix.Masked().String())
	if p.Keepalive != 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
	}
	return b.String(), nil
}
