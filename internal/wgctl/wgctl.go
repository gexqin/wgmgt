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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/store"
)

// defaultPolicyTable is the routing table used for full-tunnel policy
// routing (same value wg-quick picks). The table number doubles as the
// firewall mark on the WireGuard UDP socket so tunnel transport escapes
// into the main table.
const defaultPolicyTable = 51820

const (
	rulePrioTunnel   = 32765 // not fwmark <table> → table <table>
	rulePrioMainSupp = 32764 // table main, suppress_prefixlength 0
)

// Up brings an interface up natively: create link if needed, assign the
// tunnel address, configure the device and peers, then set the link up and
// install routes for peer allowed IPs not covered by the tunnel subnet.
// Default routes (0.0.0.0/0, ::/0) engage wg-quick-style policy routing:
// fwmark on the socket, default route in a separate table, and rules that
// keep marked traffic (the tunnel itself) on the main table.
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

	policyV4, policyV6 := DefaultRouteFamilies(peers)
	table := policyTable(ifc)

	cfg, err := deviceConfig(ifc, peers)
	if err != nil {
		return err
	}
	if policyV4 || policyV6 {
		mark := table
		cfg.FirewallMark = &mark
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

	if err := installRoutes(link, ifc, peers, policyV4, policyV6, table); err != nil {
		return err
	}

	if ifc.PostUp != "" {
		if err := runHook(ifc.PostUp); err != nil {
			return fmt.Errorf("PostUp: %w", err)
		}
	}
	return nil
}

// Down runs PostDown (best effort), removes policy-routing rules, then the
// device — addresses and routes go with it.
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
	cleanPolicyRules(policyTable(ifc))
	return netlink.LinkDel(link)
}

// ApplyPeers hot-applies the full peer list to a running device, so peer
// changes take effect without bouncing the interface. Routes for newly
// added allowed IPs are synced too — without this, traffic to an
// outside-the-tunnel-subnet allowed IP would silently leave unencrypted
// via the default route.
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
	if v4, v6 := DefaultRouteFamilies(peers); !v4 && !v6 {
		// Policy-routing mode carries its own table routes; plain mode
		// needs the main-table routes refreshed (EEXIST makes it a no-op
		// for routes already installed).
		if link, err := netlink.LinkByName(ifc.Name); err == nil {
			return installRoutes(link, ifc, peers, false, false, 0)
		}
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

// installRoutes adds a route per peer allowed-IP network not already covered
// by the tunnel subnet. When a default route is present, wg-quick-style
// policy routing is installed instead: the default (and everything else)
// lives in a separate table, fwmark keeps the tunnel's own UDP on the main
// table, and "table main suppress_prefixlength 0" preserves more-specific
// main-table routes (like the one to the controller).
func installRoutes(link netlink.Link, ifc *store.Interface, peers []store.Peer, policyV4, policyV6 bool, table int) error {
	if policyV4 || policyV6 {
		if err := cleanPolicyRules(table); err != nil {
			return err
		}
		if policyV4 {
			if err := addPolicyRoute(link, table, unix.AF_INET); err != nil {
				return err
			}
		}
		if policyV6 {
			if err := addPolicyRoute(link, table, unix.AF_INET6); err != nil {
				return err
			}
		}
		return installPolicyRules(table, policyV4, policyV6)
	}

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

// DefaultRouteFamilies reports whether the peer set contains an IPv4/IPv6
// default route.
func DefaultRouteFamilies(peers []store.Peer) (v4, v6 bool) {
	for _, p := range peers {
		for _, s := range strings.Split(p.AllowedIPs, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil || prefix.Bits() != 0 {
				continue
			}
			if prefix.Addr().Is4() {
				v4 = true
			} else {
				v6 = true
			}
		}
	}
	return v4, v6
}

// policyTable resolves the routing table: a numeric route_table setting
// wins, otherwise the wg-quick default.
func policyTable(ifc *store.Interface) int {
	if n, err := strconv.Atoi(strings.TrimSpace(ifc.RouteTable)); err == nil && n > 0 {
		return n
	}
	return defaultPolicyTable
}

// addPolicyRoute puts the family's default route into the policy table.
func addPolicyRoute(link netlink.Link, table, family int) error {
	var dst net.IPNet
	if family == unix.AF_INET {
		dst = net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	} else {
		dst = net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: &dst, Table: table}
	if err := netlink.RouteAdd(&route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("add policy route (table %d): %w", table, err)
	}
	return nil
}

// installPolicyRules adds the two wg-quick rules per family:
//
//	32765: not fwmark <table> lookup <table>   (unmarked traffic → tunnel)
//	32764: lookup main suppress_prefixlength 0 (keep specific main routes)
func installPolicyRules(table int, v4, v6 bool) error {
	families := []int{}
	if v4 {
		families = append(families, unix.AF_INET)
	}
	if v6 {
		families = append(families, unix.AF_INET6)
	}
	for _, family := range families {
		mark := uint32(table)
		r1 := netlink.NewRule()
		r1.Family, r1.Priority, r1.Table = family, rulePrioTunnel, table
		r1.Mark, r1.Mask, r1.Invert = mark, &r1Mask, true
		if err := netlink.RuleAdd(r1); err != nil {
			return fmt.Errorf("add rule not-fwmark: %w", err)
		}
		r2 := netlink.NewRule()
		r2.Family, r2.Priority, r2.Table = family, rulePrioMainSupp, unix.RT_TABLE_MAIN
		r2.SuppressPrefixlen = 0
		if err := netlink.RuleAdd(r2); err != nil {
			return fmt.Errorf("add rule main-suppress: %w", err)
		}
	}
	return nil
}

// r1Mask makes "fwmark <table>" match exactly the table's mark bit.
var r1Mask uint32 = 0xffffffff

// cleanPolicyRules removes the policy rules (idempotent, errors ignored:
// missing rules are the common case).
func cleanPolicyRules(table int) error {
	mark := uint32(table)
	mask := uint32(0xffffffff)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		r1 := netlink.NewRule()
		r1.Family, r1.Priority, r1.Table = family, rulePrioTunnel, table
		r1.Mark, r1.Mask, r1.Invert = mark, &mask, true
		_ = netlink.RuleDel(r1)

		r2 := netlink.NewRule()
		r2.Family, r2.Priority, r2.Table = family, rulePrioMainSupp, unix.RT_TABLE_MAIN
		r2.SuppressPrefixlen = 0
		_ = netlink.RuleDel(r2)
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
