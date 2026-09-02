// Package app hosts orchestration shared by the CLI and the web UI:
// regenerating conf files, hot-applying peers, assigning addresses.
// It operates on a single client's interfaces (client "" = this host).
package app

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/gexqin/wgmgt/internal/confgen"
	"github.com/gexqin/wgmgt/internal/fileutil"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
)

// App ties the store to a conf output directory.
type App struct {
	Store   *store.Store
	ConfDir string
}

// SyncConf regenerates the wg-quick conf for a local interface after a
// change and hot-applies the peer list if the device is currently up.
// (Remote-client interfaces are applied by their agent, not here.)
func (a *App) SyncConf(name string) error {
	ifc, err := a.Store.GetInterface("", name)
	if err != nil {
		return err
	}
	peers, err := a.Store.ListPeers("", name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.ConfDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(a.ConfDir, 0o700); err != nil {
		return fmt.Errorf("secure conf directory: %w", err)
	}
	path := filepath.Join(a.ConfDir, name+".conf")
	if err := fileutil.WriteAtomic(path, []byte(confgen.Interface(ifc, peers)), 0o600); err != nil {
		return fmt.Errorf("write conf: %w", err)
	}
	if wgctl.Exists(name) {
		if err := wgctl.ApplyPeers(ifc, peers); err != nil {
			return fmt.Errorf("hot-apply to running device: %w", err)
		}
	}
	return nil
}

// NextFreeIP picks the next unused host address in the interface's tunnel
// subnet (IPv4 only; IPv6 interfaces must specify allowed IPs explicitly).
func (a *App) NextFreeIP(ifc *store.Interface) (string, error) {
	prefix, err := netip.ParsePrefix(ifc.Address)
	if err != nil {
		return "", fmt.Errorf("interface address %q: %w", ifc.Address, err)
	}
	addr := prefix.Addr()
	if !addr.Is4() {
		return "", fmt.Errorf("automatic IP assignment needs an IPv4 tunnel")
	}
	peers, err := a.Store.ListPeers(ifc.Client, ifc.Name)
	if err != nil {
		return "", err
	}
	used := map[netip.Addr]bool{addr: true}
	for _, p := range peers {
		for _, s := range strings.Split(p.AllowedIPs, ",") {
			s = strings.TrimSpace(s)
			if p2, err := netip.ParsePrefix(s); err == nil {
				used[p2.Addr()] = true
			} else if a2, err := netip.ParseAddr(s); err == nil {
				used[a2] = true
			}
		}
	}
	masked := prefix.Masked()
	hostCount := uint64(1) << uint(32-masked.Bits())
	if hostCount > 1<<20 {
		return "", fmt.Errorf("tunnel subnet %s is too large for automatic assignment; specify an address", masked)
	}
	start, end := uint64(0), hostCount
	if masked.Bits() <= 30 { // reserve the IPv4 network and broadcast addresses
		start, end = 1, hostCount-1
	}
	network4 := masked.Addr().As4()
	network := binary.BigEndian.Uint32(network4[:])
	for offset := start; offset < end; offset++ {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], network+uint32(offset))
		cand := netip.AddrFrom4(raw)
		if !used[cand] {
			return netip.PrefixFrom(cand, 32).String(), nil
		}
	}
	return "", fmt.Errorf("tunnel subnet %s is full", prefix.Masked())
}
