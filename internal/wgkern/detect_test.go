package wgkern

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		release             string
		major, minor        int
		ok                  bool
	}{
		{"6.6.87.2-microsoft-standard-WSL2", 6, 6, true},
		{"5.15.0-91-generic", 5, 15, true},
		{"5.4.0", 5, 4, true},
		{"6", 0, 0, false}, // no dot
		{"garbage", 0, 0, false},
	}
	for _, c := range cases {
		major, minor, ok := parseKernelVersion(c.release)
		if ok != c.ok || major != c.major || minor != c.minor {
			t.Errorf("parseKernelVersion(%q) = %d, %d, %v; want %d, %d, %v",
				c.release, major, minor, ok, c.major, c.minor, c.ok)
		}
	}
}

func TestDetectLoadedModule(t *testing.T) {
	dir := t.TempDir()
	pm := filepath.Join(dir, "modules")
	write(t, pm, "module_a 123 0 - Live 0x0000\nwireguard 24576 0 - Live 0x0000\n")
	write(t, filepath.Join(dir, "modules.dep"), "")

	r := detect("6.6.0", pm, dir)
	if r.Status != StatusAvailable {
		t.Errorf("status = %v, want StatusAvailable", r.Status)
	}
}

func TestDetectBuiltin(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "modules"), "")
	write(t, filepath.Join(dir, "modules.builtin"), "kernel/net/wireguard/wireguard.ko\n")

	r := detect("6.6.0", filepath.Join(dir, "modules"), dir)
	if r.Status != StatusAvailable {
		t.Errorf("status = %v, want StatusAvailable", r.Status)
	}
}

func TestDetectLoadable(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "modules"), "")
	write(t, filepath.Join(dir, "modules.dep"), "kernel/net/wireguard/wireguard.ko.zst: udp_tunnel\n")

	r := detect("6.6.0", filepath.Join(dir, "modules"), dir)
	if r.Status != StatusLoadable {
		t.Errorf("status = %v, want StatusLoadable", r.Status)
	}
}

func TestDetectMissing(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "modules"), "")
	write(t, filepath.Join(dir, "modules.dep"), "kernel/fs/ext4/ext4.ko:\n")

	r := detect("4.19.0", filepath.Join(dir, "modules"), dir)
	if r.Status != StatusMissing {
		t.Errorf("status = %v, want StatusMissing", r.Status)
	}
	if len(r.Notes) == 0 {
		t.Error("expected a note for the old-kernel case")
	}

	r = detect("6.6.0", filepath.Join(dir, "modules"), dir)
	if r.Status != StatusMissing {
		t.Errorf("status = %v, want StatusMissing", r.Status)
	}
}

func TestHasLoadedModuleEmptyFile(t *testing.T) {
	dir := t.TempDir()
	pm := filepath.Join(dir, "modules")
	write(t, pm, "\n\n")
	if hasLoadedModule(pm) {
		t.Error("empty /proc/modules must not panic or match")
	}
}
