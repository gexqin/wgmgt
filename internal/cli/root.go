package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/app"
	"github.com/gexqin/wgmgt/internal/store"
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
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("secure state directory: %w", err)
		}
	}
	return store.Open(dbPath)
}

// newApp wires the store to the conf output directory.
func newApp(st *store.Store) *app.App {
	return &app.App{Store: st, ConfDir: confDir}
}

func confPath(name string) string { return filepath.Join(confDir, name+".conf") }

// resolveIface picks the interface to operate on: the argument if given,
// otherwise the only managed interface (an error if there are none or several).
func resolveIface(st *store.Store, arg string) (string, error) {
	if arg != "" {
		if _, err := st.GetInterface("", arg); err != nil {
			return "", err
		}
		return arg, nil
	}
	list, err := st.ListInterfaces("")
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

// requireRoot returns a friendly error when not running as root.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root (try sudo)")
	}
	return nil
}
