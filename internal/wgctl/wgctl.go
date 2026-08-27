// Package wgctl applies stored configuration to the kernel WireGuard stack
// via netlink — no wg-quick / shellouts required. The generated conf files
// remain available for interop with wg-quick.
package wgctl

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/store"
)

// Up brings an interface up natively: create link if needed, assign the
// tunnel address, configure the device and peers, then set the link up and
// install routes for peer allowed IPs not covered by the tunnel subnet.
// PostUp, when set, runs after everything succeeded.
func Up(ifc *store.Interface, peers []store.Peer) error {
	link, err := ensureLink(ifc.Name)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(ifc.Address)
	if err != nil {
		return fmt.Errorf("interface address %q: %w", ifc.Address, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("assign address: %w", err)
	}
	if ifc.MTU != 0 {
		if err := netlink.LinkSetMTU(link, ifc.MTU); err != nil {
			return fmt.Errorf("set MTU: %w", err)
		}
	}

	cfg, err := deviceConfig(ifc, peers)
	if err != nil {
		return err
	}
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()
	if err := c.ConfigureDevice(ifc.Name, *cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}

	if err := installRoutes(link, ifc, peers); err != nil {
		return err
	}

	if ifc.PostUp != "" {
		if err := runHook(ifc.PostUp); err != nil {
			return fmt.Errorf("PostUp: %w", err)
		}
	}
	return nil
}

// Down runs PostDown (best effort), then removes the device — addresses
// and routes go with it.
func Down(ifc *store.Interface) error {
	link, err := netlink.LinkByName(ifc.Name)
	if err != nil {
		return fmt.Errorf("interface %q is not up", ifc.Name)
	}
	if ifc.PostDown != "" {
		if err := runHook(ifc.PostDown); err != nil {
			fmt.Fprintf(os.Stderr, "warning: PostDown failed: %v\n", err)
		}
	}
	return netlink.LinkDel(link)
}

// ApplyPeers hot-applies the full peer list to a running device, so peer
// changes take effect without bouncing the interface.
func ApplyPeers(ifc *store.Interface, peers []store.Peer) error {
	cfg, err := deviceConfig(ifc, peers)
	if err != nil {
		return err
	}
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()
	if err := c.ConfigureDevice(ifc.Name, *cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	return nil
}

// Exists reports whether the device is currently up.
func Exists(name string) bool {
	_, err := netlink.LinkByName(name)
	return err == nil
}

// PeerStatus is live kernel state for one peer.
type PeerStatus struct {
	LastHandshake time.Time
	Rx, Tx        int64
	Endpoint      string
}

// DeviceStatus returns live state of every peer of a running device.
// Returns an error if the device is not up.
func DeviceStatus(name string) (map[string]PeerStatus, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	d, err := c.Device(name)
	if err != nil {
		return nil, err
	}
	out := make(map[string]PeerStatus, len(d.Peers))
	for _, p := range d.Peers {
		s := PeerStatus{LastHandshake: p.LastHandshakeTime, Rx: p.ReceiveBytes, Tx: p.TransmitBytes}
		if p.Endpoint != nil {
			s.Endpoint = p.Endpoint.String()
		}
		out[p.PublicKey.String()] = s
	}
	return out, nil
}

// --- internals ---

func ensureLink(name string) (netlink.Link, error) {
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}
	err := netlink.LinkAdd(link)
	if errors.Is(err, syscall.EEXIST) {
		return netlink.LinkByName(name)
	}
	if err != nil {
		return nil, fmt.Errorf("create link: %w", err)
	}
	return link, nil
}

func deviceConfig(ifc *store.Interface, peers []store.Peer) (*wgtypes.Config, error) {
	key, err := wgtypes.ParseKey(ifc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("interface private key: %w", err)
	}
	cfg := &wgtypes.Config{
		PrivateKey:   &key,
		ListenPort:   &ifc.ListenPort,
		ReplacePeers: true,
		Peers:        make([]wgtypes.PeerConfig, 0, len(peers)),
	}
	for _, p := range peers {
		pc, err := peerConfig(p)
		if err != nil {
			return nil, err
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	return cfg, nil
}

func peerConfig(p store.Peer) (wgtypes.PeerConfig, error) {
	pub, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("peer %q public key: %w", p.Name, err)
	}
	pc := wgtypes.PeerConfig{
		PublicKey:         pub,
		ReplaceAllowedIPs: true,
	}
	if p.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(p.PresharedKey)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("peer %q preshared key: %w", p.Name, err)
		}
		pc.PresharedKey = &psk
	}
	if p.Endpoint != "" {
		ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("peer %q endpoint: %w", p.Name, err)
		}
		pc.Endpoint = ep
	}
	if p.Keepalive != 0 {
		ka := time.Duration(p.Keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka
	}
	for _, s := range strings.Split(p.AllowedIPs, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("peer %q allowed IP %q: %w", p.Name, s, err)
		}
		pc.AllowedIPs = append(pc.AllowedIPs, ipNet(prefix))
	}
	return pc, nil
}

func ipNet(p netip.Prefix) net.IPNet {
	return net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

// installRoutes adds a route per peer allowed-IP network that is not already
// covered by the tunnel subnet. Default routes are skipped with a warning:
// policy routing (fwmark/Table tricks) is out of scope for M1.
func installRoutes(link netlink.Link, ifc *store.Interface, peers []store.Peer) error {
	tunnel, err := netip.ParsePrefix(ifc.Address)
	if err != nil {
		return fmt.Errorf("interface address %q: %w", ifc.Address, err)
	}
	tunnel = tunnel.Masked()

	seen := map[string]bool{}
	for _, p := range peers {
		for _, s := range strings.Split(p.AllowedIPs, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				return fmt.Errorf("peer %q allowed IP %q: %w", p.Name, s, err)
			}
			if prefix.Bits() == 0 {
				fmt.Fprintf(os.Stderr, "warning: peer %q: default route via allowed IP %q skipped (policy routing not supported yet)\n", p.Name, s)
				continue
			}
			if prefix.Addr().Is4() == tunnel.Addr().Is4() &&
				tunnel.Contains(prefix.Addr()) && prefix.Bits() >= tunnel.Bits() {
				continue // covered by the connected route
			}
			n := ipNet(prefix.Masked())
			if seen[n.String()] {
				continue
			}
			seen[n.String()] = true
			route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: &n}
			if err := netlink.RouteAdd(&route); err != nil && !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("add route %s: %w", n.String(), err)
			}
		}
	}
	return nil
}

func runHook(cmd string) error {
	c := exec.Command("sh", "-c", cmd)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
