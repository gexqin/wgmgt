// Package wgctl applies stored configuration to the kernel WireGuard stack
// via netlink — no wg-quick / shellouts required. The generated conf files
// remain available for interop with wg-quick.
package wgctl

import (
	"errors"
	"fmt"
	"hash/fnv"
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
const defaultPolicyTableBase = 51820

// Up brings an interface up natively: create link if needed, assign the
// tunnel address, configure the device and peers, then set the link up and
// install routes for peer allowed IPs not covered by the tunnel subnet.
// Default routes (0.0.0.0/0, ::/0) engage wg-quick-style policy routing:
// fwmark on the socket, default route in a separate table, and rules that
// keep marked traffic (the tunnel itself) on the main table.
// PostUp, when set, runs after everything succeeded.
func Up(ifc *store.Interface, peers []store.Peer) (retErr error) {
	link, created, err := ensureLink(ifc)
	if err != nil {
		return err
	}
	if created {
		defer func() {
			if retErr != nil {
				_ = cleanPolicyRules(ifc)
				_ = netlink.LinkDel(link)
			}
		}()
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
		mark := policyMark(ifc, table)
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
	if err := verifyOwnedLink(link, ifc); err != nil {
		return err
	}
	if ifc.PostDown != "" {
		if err := runHook(ifc.PostDown); err != nil {
			fmt.Fprintf(os.Stderr, "warning: PostDown failed: %v\n", err)
		}
	}
	if err := cleanPolicyRules(ifc); err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

// ApplyPeers hot-applies the full peer list to a running device, so peer
// changes take effect without bouncing the interface. Routes for newly
// added allowed IPs are synced too — without this, traffic to an
// outside-the-tunnel-subnet allowed IP would silently leave unencrypted
// via the default route.
func ApplyPeers(ifc *store.Interface, peers []store.Peer) error {
	link, err := netlink.LinkByName(ifc.Name)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", ifc.Name, err)
	}
	if err := verifyOwnedLink(link, ifc); err != nil {
		return err
	}
	cfg, err := deviceConfig(ifc, peers)
	if err != nil {
		return err
	}
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	old, err := c.Device(ifc.Name)
	if err != nil {
		return fmt.Errorf("read device before update: %w", err)
	}
	oldV4, oldV6 := defaultRouteFamiliesDevice(old)
	newV4, newV6 := DefaultRouteFamilies(peers)
	if oldV4 != newV4 || oldV6 != newV6 {
		_ = c.Close()
		if err := Down(ifc); err != nil {
			return fmt.Errorf("routing mode changed, rebuild down: %w", err)
		}
		return Up(ifc, peers)
	}
	defer c.Close()
	oldRoutes, err := routeSetFromDevice(ifc, old)
	if err != nil {
		return err
	}
	if err := c.ConfigureDevice(ifc.Name, *cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	if !newV4 && !newV6 {
		// Policy-routing mode carries its own table routes; plain mode
		// needs the main-table routes fully reconciled.
		newRoutes, err := routeSetFromPeers(ifc, peers)
		if err != nil {
			return err
		}
		for key, dst := range oldRoutes {
			if _, keep := newRoutes[key]; keep {
				continue
			}
			route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: &dst}
			if err := netlink.RouteDel(&route); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("remove stale route %s: %w", key, err)
			}
		}
		return installRoutes(link, ifc, peers, false, false, 0)
	}
	return nil
}

// Exists reports whether the device is currently up.
func Exists(name string) bool {
	link, err := netlink.LinkByName(name)
	return err == nil && link.Type() == "wireguard"
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

func ensureLink(ifc *store.Interface) (netlink.Link, bool, error) {
	if existing, err := netlink.LinkByName(ifc.Name); err == nil {
		if err := verifyOwnedLink(existing, ifc); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	}
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: ifc.Name}}
	err := netlink.LinkAdd(link)
	if errors.Is(err, syscall.EEXIST) {
		existing, findErr := netlink.LinkByName(ifc.Name)
		if findErr != nil {
			return nil, false, findErr
		}
		if err := verifyOwnedLink(existing, ifc); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("create link: %w", err)
	}
	return link, true, nil
}

// verifyOwnedLink refuses to mutate or delete an arbitrary same-name link.
// Existing WireGuard devices are adopted only when their public key matches
// the private key in WGMGT's desired state.
func verifyOwnedLink(link netlink.Link, ifc *store.Interface) error {
	if link.Type() != "wireguard" {
		return fmt.Errorf("refusing to manage %q: existing link type is %s, not wireguard", ifc.Name, link.Type())
	}
	if ifc.PrivateKey == "" {
		return fmt.Errorf("refusing to manage existing WireGuard interface %q without an ownership key", ifc.Name)
	}
	privateKey, err := wgtypes.ParseKey(ifc.PrivateKey)
	if err != nil {
		return fmt.Errorf("interface private key: %w", err)
	}
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl ownership check: %w", err)
	}
	defer c.Close()
	dev, err := c.Device(ifc.Name)
	if err != nil {
		return fmt.Errorf("read existing WireGuard interface %q: %w", ifc.Name, err)
	}
	if dev.PublicKey != privateKey.PublicKey() {
		return fmt.Errorf("refusing to manage %q: existing WireGuard public key does not match WGMGT state", ifc.Name)
	}
	return nil
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
		if err := cleanPolicyRules(ifc); err != nil {
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
		return installPolicyRules(ifc, table, policyV4, policyV6)
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
			if err := netlink.RouteReplace(&route); err != nil {
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

func defaultRouteFamiliesDevice(d *wgtypes.Device) (v4, v6 bool) {
	for _, peer := range d.Peers {
		for _, n := range peer.AllowedIPs {
			ones, bits := n.Mask.Size()
			if ones != 0 {
				continue
			}
			if bits == 32 {
				v4 = true
			} else if bits == 128 {
				v6 = true
			}
		}
	}
	return v4, v6
}

// policyTable resolves the routing table: a numeric route_table setting
// wins, otherwise the wg-quick default.
func policyTable(ifc *store.Interface) int {
	if n, err := strconv.ParseUint(strings.TrimSpace(ifc.RouteTable), 10, 31); err == nil && n > 0 {
		return int(n)
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(ifc.Name))
	return defaultPolicyTableBase + int(h.Sum32()%10000)
}

func policyMark(ifc *store.Interface, table int) int {
	if n, err := strconv.ParseUint(strings.TrimSpace(ifc.Fwmark), 0, 31); err == nil && n > 0 {
		return int(n)
	}
	return table
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
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("add policy route (table %d): %w", table, err)
	}
	return nil
}

// installPolicyRules adds two interface-specific rules per family. Stable
// priorities and routing tables keep multiple full-tunnel interfaces from
// deleting or reusing one another's policy state.
//
//	<priority>: not fwmark <table> lookup <table> (unmarked traffic → tunnel)
//	<priority>: lookup main suppress_prefixlength 0 (keep specific main routes)
func installPolicyRules(ifc *store.Interface, table int, v4, v6 bool) error {
	prioMain, prioTunnel := policyPriorities(ifc)
	families := []int{}
	if v4 {
		families = append(families, unix.AF_INET)
	}
	if v6 {
		families = append(families, unix.AF_INET6)
	}
	for _, family := range families {
		mark := uint32(policyMark(ifc, table)) // #nosec G115 -- both inputs are parsed/bounded to 32 bits.
		r1 := netlink.NewRule()
		r1.Family, r1.Priority, r1.Table = family, prioTunnel, table
		r1.Mark, r1.Mask, r1.Invert = mark, &r1Mask, true
		if err := netlink.RuleAdd(r1); err != nil {
			_ = cleanPolicyRules(ifc)
			return fmt.Errorf("add rule not-fwmark: %w", err)
		}
		r2 := netlink.NewRule()
		r2.Family, r2.Priority, r2.Table = family, prioMain, unix.RT_TABLE_MAIN
		r2.SuppressPrefixlen = 0
		if err := netlink.RuleAdd(r2); err != nil {
			_ = cleanPolicyRules(ifc)
			return fmt.Errorf("add rule main-suppress: %w", err)
		}
	}
	return nil
}

func policyPriorities(ifc *store.Interface) (mainSupp, tunnel int) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ifc.Name))
	base := 10000 + int(h.Sum32()%10000)*2
	return base, base + 1
}

// r1Mask makes "fwmark <table>" match exactly the table's mark bit.
var r1Mask uint32 = 0xffffffff

// cleanPolicyRules removes the policy rules (idempotent, errors ignored:
// missing rules are the common case).
func cleanPolicyRules(ifc *store.Interface) error {
	table := policyTable(ifc)
	prioMain, prioTunnel := policyPriorities(ifc)
	mark := uint32(policyMark(ifc, table)) // #nosec G115 -- both inputs are parsed/bounded to 32 bits.
	mask := uint32(0xffffffff)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		r1 := netlink.NewRule()
		r1.Family, r1.Priority, r1.Table = family, prioTunnel, table
		r1.Mark, r1.Mask, r1.Invert = mark, &mask, true
		_ = netlink.RuleDel(r1)

		r2 := netlink.NewRule()
		r2.Family, r2.Priority, r2.Table = family, prioMain, unix.RT_TABLE_MAIN
		r2.SuppressPrefixlen = 0
		_ = netlink.RuleDel(r2)
	}
	return nil
}

func routeSetFromPeers(ifc *store.Interface, peers []store.Peer) (map[string]net.IPNet, error) {
	var nets []net.IPNet
	for _, p := range peers {
		for _, value := range strings.Split(p.AllowedIPs, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err != nil {
				return nil, fmt.Errorf("peer %q allowed IP %q: %w", p.Name, value, err)
			}
			nets = append(nets, ipNet(prefix.Masked()))
		}
	}
	return plainRouteSet(ifc, nets)
}

func routeSetFromDevice(ifc *store.Interface, d *wgtypes.Device) (map[string]net.IPNet, error) {
	var nets []net.IPNet
	for _, p := range d.Peers {
		nets = append(nets, p.AllowedIPs...)
	}
	return plainRouteSet(ifc, nets)
}

func plainRouteSet(ifc *store.Interface, nets []net.IPNet) (map[string]net.IPNet, error) {
	tunnel, err := netip.ParsePrefix(ifc.Address)
	if err != nil {
		return nil, fmt.Errorf("interface address %q: %w", ifc.Address, err)
	}
	tunnel = tunnel.Masked()
	out := make(map[string]net.IPNet)
	for _, n := range nets {
		prefix, err := netip.ParsePrefix(n.String())
		if err != nil {
			return nil, err
		}
		if prefix.Bits() == 0 {
			continue
		}
		if prefix.Addr().Is4() == tunnel.Addr().Is4() && tunnel.Contains(prefix.Addr()) && prefix.Bits() >= tunnel.Bits() {
			continue
		}
		network := ipNet(prefix.Masked())
		out[network.String()] = network
	}
	return out, nil
}

func runHook(cmd string) error {
	c := exec.Command("sh", "-c", cmd)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
