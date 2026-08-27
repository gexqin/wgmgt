package wgctl

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// RunningDevices lists the names of WireGuard devices currently up,
// whoever put them there (wgmgt, wg-quick, or manual `wg` calls).
func RunningDevices() ([]string, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()
	devices, err := c.Devices()
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	names := make([]string, 0, len(devices))
	for _, d := range devices {
		names = append(names, d.Name)
	}
	return names, nil
}

// StopExternal tears down a WireGuard device not managed by wgmgt. When a
// wg-quick systemd unit owns it, the unit is stopped so wg-quick removes
// its own policy routing; otherwise the link is deleted outright, which
// takes addresses and routes down with it.
func StopExternal(name string) (byService bool, err error) {
	unit := "wg-quick@" + name + ".service"
	if err := exec.Command("systemctl", "is-active", "--quiet", unit).Run(); err == nil {
		if out, err := exec.Command("systemctl", "stop", unit).CombinedOutput(); err != nil {
			return false, fmt.Errorf("stop %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
		}
		return true, nil
	}
	if !Exists(name) {
		return false, nil // already gone (e.g. the unit stopped the device)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, fmt.Errorf("find link %q: %w", name, err)
	}
	return false, netlink.LinkDel(link)
}
