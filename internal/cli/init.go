package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/certs"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
	"github.com/gexqin/wgmgt/internal/wgkern"
)

var initFlags struct {
	name    string
	address string
	port    int
	mtu     int
	dns     string
	sanDNS  string
	sanIP   string
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a WireGuard interface (wizard with flag overrides)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if r := wgkern.Detect(); r.Status == wgkern.StatusMissing {
			return errIncompatible
		}
		st, err := openStore()
		if errors.Is(err, store.ErrLegacySchema) {
			// Pre-rename database: offer the same full reset (resetAll is
			// disk-driven, so it works without opening the old db).
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "\n%v.\n", err)
			if !confirm("Delete it (stop running wgmgt processes, remove all managed interfaces and the whole state dir) and re-initialize from scratch?", false) {
				fmt.Fprintf(out, "Aborted. Remove %s manually, then re-run `wgmgt init`.\n", dbPath)
				return nil
			}
			if err := resetAll(cmd); err != nil {
				return err
			}
			st, err = openStore()
		}
		if err != nil {
			return err
		}
		// Closure, not `defer st.Close()`: the re-init path replaces st with
		// a fresh store after wiping the old one.
		defer func() { st.Close() }()

		if err := offerStopForeignWG(cmd, st); err != nil {
			return err
		}

		name := initFlags.name
		if !cmd.Flags().Changed("name") {
			name = prompt("Interface name", "wg0")
		}
		if !store.ValidIfaceName(name) {
			return fmt.Errorf("invalid interface name %q (max 15 chars, [a-zA-Z0-9_-])", name)
		}
		if existing, err := st.GetInterface("", name); err == nil {
			keep, err := offerReset(cmd, st, existing)
			if err != nil {
				return err
			}
			if keep {
				return nil
			}
			// Full reset: wipe devices, conf files, the database and the
			// controller PKI so everything regenerates from scratch.
			st.Close()
			if err := resetAll(cmd); err != nil {
				return err
			}
			if st, err = openStore(); err != nil {
				return err
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		address := initFlags.address
		if !cmd.Flags().Changed("address") {
			address = prompt("Tunnel address (CIDR)", "10.0.0.1/24")
		}
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", address, err)
		}

		port := initFlags.port
		if !cmd.Flags().Changed("port") {
			port, _ = strconv.Atoi(prompt("Listen port", "51820"))
		}
		if port < 0 || port > 65535 {
			return fmt.Errorf("invalid port %d", port)
		}

		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		ifc := &store.Interface{
			Enabled:    true,
			Name:       name,
			PrivateKey: key.String(),
			ListenPort: port,
			Address:    prefix.String(),
			MTU:        initFlags.mtu,
			DNS:        initFlags.dns,
		}
		if err := st.CreateInterface(ifc); err != nil {
			return fmt.Errorf("store interface: %w", err)
		}
		if err := newApp(st).SyncConf(name); err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Interface %s created\n", name)
		fmt.Fprintf(out, "  Address:     %s\n", ifc.Address)
		fmt.Fprintf(out, "  Listen port: %d\n", ifc.ListenPort)
		fmt.Fprintf(out, "  Public key:  %s\n", key.PublicKey().String())
		fmt.Fprintf(out, "  Conf file:   %s\n", confPath(name))
		fmt.Fprintf(out, "\nNext: `wgmgt peer add %s` then `sudo wgmgt up %s`\n", name, name)

		return setupControllerCA(cmd)
	},
}

// setupControllerCA is init's controller PKI step: the CA (kept when it
// already exists — regenerating invalidates every enrolled agent and is
// the full reset's job) and the server certificate with explicit SANs,
// DNS names and IPs asked separately so agents can dial by either. Every
// interactive init asks for both directly; non-interactive runs skip the
// step unless --san-dns/--san-ip is given.
func setupControllerCA(cmd *cobra.Command) error {
	dnsNames := splitList(initFlags.sanDNS)
	ips := splitList(initFlags.sanIP)
	if len(dnsNames) == 0 && len(ips) == 0 {
		if !isTerminal(os.Stdin) {
			return nil
		}
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "\nController setup — CA and server certificate for `wgmgt server`.\n")
		defDNS, _ := os.Hostname()
		dnsNames = splitList(prompt("SAN DNS names (comma-separated)", defDNS))
		ips = splitList(prompt("SAN IP addresses (comma-separated)", ""))
	}

	serverDir := filepath.Join(confDir, "server")
	if err := os.MkdirAll(serverDir, 0o700); err != nil {
		return err
	}
	caExisted := false
	if _, err := os.Stat(filepath.Join(serverDir, "ca.pem")); err == nil {
		caExisted = true
	}
	ca, err := certs.LoadOrNewCA(serverDir)
	if err != nil {
		return err
	}
	kept, err := certs.IssueServerCert(serverDir, dnsNames, ips)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if caExisted {
		fmt.Fprintf(out, "Controller CA: existing one kept — sha256:%s\n", ca.CAFingerprint())
	} else {
		fmt.Fprintf(out, "Controller CA: generated — sha256:%s\n", ca.CAFingerprint())
	}
	sans := strings.Join(append(append(dnsNames, ips...), "localhost", "127.0.0.1", "::1"), ", ")
	if kept {
		fmt.Fprintf(out, "Server certificate: existing one already covers %s — kept\n", sans)
	} else {
		fmt.Fprintf(out, "Server certificate: issued for %s\n", sans)
	}
	fmt.Fprintf(out, "Agents pin the CA fingerprint via --ca-hash (join commands print it).\n")
	fmt.Fprintf(out, "Start the controller bound to one of the names above, e.g.:\n")
	fmt.Fprintf(out, "  sudo wgmgt server --api <name-or-ip>:8443\n")
	return nil
}

// splitList splits a comma-separated flag/prompt value, trimming spaces
// and dropping empty fields.
func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// offerReset is called from init when the chosen name is already managed
// by wgmgt. Re-initializing is a FULL reset: every managed interface, the
// database and the controller state dir are wiped so they regenerate cleanly.
// The user can keep the existing state instead (init exits with next-step
// hints). Non-interactive runs keep it — same safety default as before,
// when init simply refused.
func offerReset(cmd *cobra.Command, st *store.Store, ifc *store.Interface) (keep bool, err error) {
	peers, err := st.ListPeers("", ifc.Name)
	if err != nil {
		return false, err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "\nInterface %q is already managed by wgmgt:\n  %s\n", ifc.Name, describeInterface(ifc, len(peers)))
	if others, err := st.ListInterfaces(""); err == nil && len(others) > 1 {
		fmt.Fprintf(out, "Also managed (a reset deletes these too):")
		for _, o := range others {
			if o.Name != ifc.Name {
				fmt.Fprintf(out, " %s", o.Name)
			}
		}
		fmt.Fprintln(out)
	}
	if !confirm("Delete ALL wgmgt state (stop running wgmgt processes; delete interfaces, peers, databases and the whole state dir) and re-initialize?", false) {
		fmt.Fprintf(out, "Keeping it. Next: `wgmgt peer add %s` then `sudo wgmgt up %s` (or `wgmgt delete %s` to remove it)\n",
			ifc.Name, ifc.Name, ifc.Name)
		return true, nil
	}
	return false, nil
}

// resetAll wipes everything wgmgt owns on this machine: any running wgmgt
// processes (server/agent/web hold certificates, the database and the
// applied config in memory and would keep serving — or re-applying —
// deleted state), running devices and generated conf files of all managed
// interfaces, and the whole state directory (databases, controller PKI in
// <conf-dir>/server) so everything regenerates from scratch. The managed
// set is taken from the *.conf files in conf-dir — the same definition the
// agent uses — so this works even when the database cannot be opened
// (legacy schema). The caller must (re)open the store afterwards.
func resetAll(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()

	if stopped, respawned, err := killWgmgtProcs(); err != nil {
		fmt.Fprintf(cmd.OutOrStderr(), "warning: could not stop running wgmgt processes: %v\n", err)
	} else {
		if len(stopped) > 0 {
			fmt.Fprintf(out, "Stopped wgmgt process(es): %s\n", strings.Join(stopped, ", "))
		}
		if len(respawned) > 0 {
			fmt.Fprintf(cmd.OutOrStderr(), "warning: wgmgt process(es) %s reappeared after being stopped — a service manager (systemd/docker) is restarting them; stop and disable that unit, then re-run `wgmgt init`\n", strings.Join(respawned, ", "))
		}
	}

	// Down managed devices; the conf files mark the managed set.
	managed := 0
	entries, err := os.ReadDir(confDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".conf")
		if name == e.Name() {
			continue
		}
		managed++
		if wgctl.Exists(name) {
			if err := requireRoot(); err != nil {
				return err
			}
			if err := wgctl.Down(&store.Interface{Name: name}); err != nil {
				return fmt.Errorf("bring %s down: %w", name, err)
			}
		}
	}

	// Wipe the whole state directory — it holds only wgmgt-generated files
	// (confs, the local database, the controller state dir <conf-dir>/server
	// with its PKI and database). The wholesale removal is guarded: it only
	// happens when the directory is recognizably ours (default layout with
	// the database inside, or literally named "wgmgt"); exotic --conf-dir
	// values get the targeted cleanup instead.
	if stateDirIsOurs() {
		if err := os.RemoveAll(confDir); err != nil {
			return fmt.Errorf("remove %s: %w", confDir, err)
		}
	} else {
		for _, e := range entries {
			if name := strings.TrimSuffix(e.Name(), ".conf"); name != e.Name() {
				if err := os.Remove(filepath.Join(confDir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
					fmt.Fprintf(cmd.OutOrStderr(), "warning: could not remove %s: %v\n", e.Name(), err)
				}
			}
		}
		if err := os.RemoveAll(filepath.Join(confDir, "server")); err != nil {
			return fmt.Errorf("remove %s: %w", filepath.Join(confDir, "server"), err)
		}
	}
	// The database can live outside conf-dir via --db.
	if filepath.Dir(dbPath) != confDir {
		for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", p, err)
			}
		}
	}
	fmt.Fprintf(out, "Wiped %d managed interface(s) and the whole state directory %s — regenerating\n", managed, confDir)
	return nil
}

// stateDirIsOurs guards the wholesale RemoveAll of conf-dir: the default
// layout keeps the database inside it, and the default directory is
// literally named wgmgt.
func stateDirIsOurs() bool {
	return filepath.Base(confDir) == "wgmgt" || filepath.Dir(dbPath) == confDir
}

// killWgmgtProcs stops every other running wgmgt process (server, agent,
// web console). A full reset must kill them first: they hold certificates
// and database state in memory and would keep serving deleted files — or,
// for a local agent, re-apply the config being wiped. Returns the stopped
// PIDs plus any that reappeared right afterwards (a service manager with a
// restart policy); respawn is reported, not fought.
func killWgmgtProcs() (stopped, respawned []string, err error) {
	self := os.Getpid()
	scan := func() []int {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return nil
		}
		var pids []int
		for _, e := range entries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid == self {
				continue
			}
			comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
			if err == nil && strings.TrimSpace(string(comm)) == "wgmgt" {
				pids = append(pids, pid)
			}
		}
		return pids
	}
	pids := scan()
	if len(pids) == 0 {
		return nil, nil, nil
	}
	for _, pid := range pids {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return stopped, respawned, err
		}
		stopped = append(stopped, strconv.Itoa(pid))
	}
	// Grace period, then force whatever is still alive, then watch for
	// respawns (systemd Restart=always, docker --restart).
	time.Sleep(500 * time.Millisecond)
	for _, pid := range pids {
		if err := syscall.Kill(pid, 0); err == nil {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, pid := range scan() {
		respawned = append(respawned, strconv.Itoa(pid))
	}
	return stopped, respawned, nil
}

// offerStopForeignWG warns about WireGuard devices that are up but not
// managed by wgmgt (typically a wg-quick service) and offers to stop them —
// a service left running would fight wgmgt over the device and its routing.
func offerStopForeignWG(cmd *cobra.Command, st *store.Store) error {
	devices, err := wgctl.RunningDevices()
	if err != nil {
		// Read-only probing; don't block init on it.
		fmt.Fprintf(cmd.OutOrStderr(), "warning: cannot list running WireGuard devices: %v\n", err)
		return nil
	}
	managed, err := st.ListInterfaces("")
	if err != nil {
		return err
	}
	ours := make(map[string]bool, len(managed))
	for _, ifc := range managed {
		ours[ifc.Name] = true
	}
	var foreign []string
	for _, name := range devices {
		if !ours[name] {
			foreign = append(foreign, name)
		}
	}
	if len(foreign) == 0 {
		return nil
	}

	out := cmd.OutOrStderr()
	fmt.Fprintf(out, "\nWireGuard device(s) already up but not managed by wgmgt: %s\n",
		strings.Join(foreign, ", "))
	fmt.Fprintf(out, "A wg-quick service left running will fight wgmgt over the device.\n")
	if !confirm("Stop them now?", false) {
		fmt.Fprintf(out, "Leaving them running; a name collision will make `wgmgt up` fail.\n")
		return nil
	}
	if err := requireRoot(); err != nil {
		return err
	}
	for _, name := range foreign {
		byService, err := wgctl.StopExternal(name)
		if err != nil {
			fmt.Fprintf(out, "  %s: %v\n", name, err)
			continue
		}
		if byService {
			fmt.Fprintf(out, "  %s: stopped wg-quick@%s.service (consider `systemctl disable` to keep it down across reboots)\n", name, name)
		} else {
			fmt.Fprintf(out, "  %s: device removed\n", name)
		}
	}
	return nil
}

func init() {
	initCmd.Flags().StringVar(&initFlags.name, "name", "wg0", "interface name")
	initCmd.Flags().StringVar(&initFlags.address, "address", "10.0.0.1/24", "tunnel address in CIDR form")
	initCmd.Flags().IntVar(&initFlags.port, "port", 51820, "UDP listen port (0 = ephemeral)")
	initCmd.Flags().IntVar(&initFlags.mtu, "mtu", 0, "MTU (0 = kernel default)")
	initCmd.Flags().StringVar(&initFlags.dns, "dns", "", "DNS advertised to peers")
	initCmd.Flags().StringVar(&initFlags.sanDNS, "san-dns", "", "controller server certificate SAN DNS names, comma-separated (enables the CA setup step in non-interactive runs)")
	initCmd.Flags().StringVar(&initFlags.sanIP, "san-ip", "", "controller server certificate SAN IP addresses, comma-separated")
	rootCmd.AddCommand(initCmd)
}
