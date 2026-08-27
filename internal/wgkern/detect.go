// Package wgkern detects whether the running kernel provides WireGuard.
package wgkern

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Status describes the availability of kernel WireGuard support.
type Status int

const (
	// StatusAvailable means the module is loaded or built in — usable now.
	StatusAvailable Status = iota
	// StatusLoadable means the module exists but is not loaded; loading
	// requires root.
	StatusLoadable
	// StatusMissing means no kernel WireGuard was found — incompatible.
	StatusMissing
)

// Report is the result of a compatibility check.
type Report struct {
	KernelRelease string   // e.g. "6.6.87.2-microsoft-standard-WSL2"
	Status        Status   // final verdict
	Notes         []string // what each probe found, in order
}

// Detect checks the running system for kernel WireGuard support.
func Detect() Report {
	rel := kernelRelease()
	r := detect(rel, "/proc/modules", filepath.Join("/lib/modules", rel))

	// The netlink probe is definitive for "usable right now": if the
	// wireguard generic-netlink family answers, the module is loaded or
	// built in, regardless of what the module files say.
	if r.Status != StatusAvailable {
		if err := probeNetlink(); err == nil {
			r.Notes = append(r.Notes, "netlink: wireguard family responding")
			r.Status = StatusAvailable
		}
	}
	return r
}

// detect runs the file-based probes. Split from Detect for testability.
func detect(release, procModulesPath, moduleDir string) Report {
	r := Report{KernelRelease: release}

	if hasLoadedModule(procModulesPath) {
		r.Notes = append(r.Notes, "/proc/modules: wireguard loaded")
		r.Status = StatusAvailable
		return r
	}
	if hasModuleLine(filepath.Join(moduleDir, "modules.builtin")) {
		r.Notes = append(r.Notes, "modules.builtin: wireguard built into kernel")
		r.Status = StatusAvailable
		return r
	}
	if hasModuleLine(filepath.Join(moduleDir, "modules.dep")) {
		r.Notes = append(r.Notes, "modules.dep: wireguard module present but not loaded")
		r.Status = StatusLoadable
		return r
	}

	r.Status = StatusMissing
	if major, minor, ok := parseKernelVersion(release); ok && (major < 5 || (major == 5 && minor < 6)) {
		r.Notes = append(r.Notes, "kernel predates WireGuard mainline merge (v5.6); no out-of-tree module found")
	} else {
		r.Notes = append(r.Notes, "no wireguard module found for this kernel")
	}
	return r
}

// probeNetlink reports whether the wireguard generic-netlink family answers.
func probeNetlink() error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_GENERIC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// Resolve the family ID the same way wgctrl does; module absent ->
	// ENOENT.
	return genlFamilyGet(fd, "wireguard")
}

// kernelRelease returns the running kernel release (uname -r).
func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}

// parseKernelVersion extracts major.minor from a release string like
// "6.6.87.2-microsoft-standard-WSL2".
func parseKernelVersion(release string) (major, minor int, ok bool) {
	dot := strings.IndexByte(release, '.')
	if dot < 0 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(release[:dot])
	if err != nil {
		return 0, 0, false
	}
	rest := release[dot+1:]
	for i := 0; i < len(rest); i++ {
		if !isDigit(rest[i]) {
			minor, err = strconv.Atoi(rest[:i])
			if err != nil {
				return 0, 0, false
			}
			return major, minor, true
		}
	}
	minor, err = strconv.Atoi(rest)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// hasLoadedModule reports whether "wireguard" appears as a module name in
// /proc/modules (first field of a line).
func hasLoadedModule(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == "wireguard" {
			return true
		}
	}
	return false
}

// hasModuleLine reports whether a modules.builtin/modules.dep file mentions
// a wireguard module path (basename "wireguard.ko*").
func hasModuleLine(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		base := filepath.Base(strings.SplitN(line, ":", 2)[0])
		if strings.HasPrefix(base, "wireguard.ko") {
			return true
		}
	}
	return false
}
