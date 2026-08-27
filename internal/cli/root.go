package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/confgen"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
)

const (
	defaultDBPath  = "/etc/wireguard/wgmgt/wgmgt.db"
	defaultConfDir = "/etc/wireguard/wgmgt"
)

var (
	dbPath  string
	confDir string
)

var rootCmd = &cobra.Command{
	Use:   "wgmgt",
	Short: "Deploy, manage, and visualize kernel WireGuard",
	Long: "WGMGT is a helper tool for deploying, managing, and visualizing " +
		"kernel WireGuard on Linux servers, Docker, and Merlin/OpenWrt routers. " +
		"If the running kernel does not include WireGuard, WGMGT reports the " +
		"system as incompatible (no userspace fallback).",
}

// Execute runs the root command and exits with a non-zero code on failure.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", defaultDBPath, "path to the wgmgt SQLite database")
	rootCmd.PersistentFlags().StringVar(&confDir, "conf-dir", defaultConfDir, "directory for generated conf files")
}

// openStore opens the database, creating parent directories first.
func openStore() (*store.Store, error) {
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return store.Open(dbPath)
}

func confPath(name string) string { return filepath.Join(confDir, name+".conf") }

// resolveIface picks the interface to operate on: the argument if given,
// otherwise the only managed interface (an error if there are none or several).
func resolveIface(st *store.Store, arg string) (string, error) {
	if arg != "" {
		if _, err := st.GetInterface(arg); err != nil {
			return "", err
		}
		return arg, nil
	}
	list, err := st.ListInterfaces()
	if err != nil {
		return "", err
	}
	switch len(list) {
	case 0:
		return "", fmt.Errorf("no interfaces managed yet; run `wgmgt init` first")
	case 1:
		return list[0].Name, nil
	default:
		names := ""
		for i, i2 := range list {
			if i > 0 {
				names += ", "
			}
			names += i2.Name
		}
		return "", fmt.Errorf("multiple interfaces (%s); specify one", names)
	}
}

// syncConf regenerates the wg-quick conf for an interface after a change and
// hot-applies the peer list if the device is currently up.
func syncConf(st *store.Store, name string) error {
	ifc, err := st.GetInterface(name)
	if err != nil {
		return err
	}
	peers, err := st.ListPeers(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(confPath(name), []byte(confgen.Interface(ifc, peers)), 0o600); err != nil {
		return fmt.Errorf("write conf: %w", err)
	}
	if wgctl.Exists(name) {
		if err := wgctl.ApplyPeers(ifc, peers); err != nil {
			return fmt.Errorf("hot-apply to running device: %w", err)
		}
	}
	return nil
}

// requireRoot returns a friendly error when not running as root.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root (try sudo)")
	}
	return nil
}
