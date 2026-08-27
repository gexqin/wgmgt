package cli

import (
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/app"
	"github.com/gexqin/wgmgt/internal/certs"
	"github.com/gexqin/wgmgt/internal/control"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/web"
)

const defaultServerDir = "/etc/wireguard/wgmgt/server"

var serverFlags struct {
	dir     string
	api     string
	webAddr string
}

var enrollFlags struct{ out string }

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the controller (agent API + web console)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRoot(); err != nil {
			return err
		}
		dir := serverFlags.dir
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}

		// TLS material: SANs cover the hostname plus a specific API bind
		// address, so agents can dial either.
		hosts := []string{}
		if h, _ := os.Hostname(); h != "" {
			hosts = append(hosts, h)
		}
		if h, _, err := net.SplitHostPort(serverFlags.api); err == nil && h != "" && h != "0.0.0.0" && h != "::" && h != "localhost" {
			hosts = append(hosts, h)
		}
		srvCert, caPool, err := certs.EnsureServerCerts(dir, hosts)
		if err != nil {
			return fmt.Errorf("server certificates: %w", err)
		}

		st, err := store.Open(filepath.Join(dir, "db.sqlite"))
		if err != nil {
			return err
		}
		defer st.Close()

		reports := control.NewReports()
		api := control.NewAPI(st, reports)
		apiSrv := api.Server(serverFlags.api, srvCert, caPool)

		webApp := &app.App{Store: st, ConfDir: dir}
		webSrv, err := web.NewController(webApp, reports)
		if err != nil {
			return err
		}

		errCh := make(chan error, 2)
		go func() {
			errCh <- apiSrv.ListenAndServeTLS(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
		}()
		go func() {
			errCh <- http.ListenAndServe(serverFlags.webAddr, webSrv.Handler())
		}()

		out := cmd.OutOrStderr()
		fmt.Fprintf(out, "WGMGT controller\n")
		fmt.Fprintf(out, "  agent API (mTLS): https://%s\n", displayAddr(serverFlags.api))
		fmt.Fprintf(out, "  web console:      %s\n", webSrv.URL(serverFlags.webAddr))
		if host, _, err := net.SplitHostPort(serverFlags.webAddr); err == nil && host != "" && host != "localhost" && host != "127.0.0.1" && host != "::1" {
			fmt.Fprintf(out, "\nWARNING: the web console is PLAIN HTTP on a non-loopback address.\n"+
				"The URL token (and every client conf it serves, private keys included)\n"+
				"is readable by anything on the path. Bind a reverse proxy with TLS in\n"+
				"front, or keep --web on loopback and tunnel in via SSH.\n")
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		select {
		case s := <-sig:
			fmt.Fprintf(out, "\nshutting down (%v)\n", s)
			apiSrv.Close()
			return nil
		case err := <-errCh:
			return err
		}
	},
}

var serverEnrollCmd = &cobra.Command{
	Use:   "enroll <node-name>",
	Short: "Issue an agent certificate and print its start command",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		dir := serverFlags.dir
		ca, err := certs.LoadOrNewCA(dir)
		if err != nil {
			return err
		}
		certPEM, keyPEM, err := ca.NewAgentCert(name)
		if err != nil {
			return err
		}
		outDir := enrollFlags.out
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return err
		}
		certPath := filepath.Join(outDir, name+".pem")
		keyPath := filepath.Join(outDir, name+".key")
		caPath := filepath.Join(outDir, "ca.pem")
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o644); err != nil {
			return err
		}

		// Register the node with its certificate fingerprint.
		fp, err := certs.Fingerprint(certPEM)
		if err != nil {
			return err
		}
		st, err := store.Open(filepath.Join(dir, "db.sqlite"))
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.EnsureNode(name, fp); err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Agent certificate issued for %q (fingerprint %s…)\n", name, fp[:16])
		fmt.Fprintf(out, "  %s\n  %s\n  %s\n", certPath, keyPath, caPath)
		fmt.Fprintf(out, "\nCopy these files to the node, then run there:\n")
		fmt.Fprintf(out, "  sudo wgmgt agent --server https://<controller>:8443 --ca ca.pem --cert %[1]s.pem --key %[1]s.key\n", name)
		return nil
	},
}

func init() {
	serverCmd.PersistentFlags().StringVar(&serverFlags.dir, "dir", defaultServerDir, "controller state directory (certs + database)")
	serverCmd.PersistentFlags().StringVar(&serverFlags.api, "api", ":8443", "mTLS listen address for agents")
	serverCmd.PersistentFlags().StringVar(&serverFlags.webAddr, "web", "127.0.0.1:8080", "web console listen address")
	serverEnrollCmd.Flags().StringVar(&enrollFlags.out, "out", ".", "directory to write the agent certificate files into")
	serverCmd.AddCommand(serverEnrollCmd)
	rootCmd.AddCommand(serverCmd)
}

// displayAddr renders a listen address for humans (":8443" → "localhost:8443").
func displayAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil && host == "" {
		return "localhost" + addr
	}
	return addr
}
