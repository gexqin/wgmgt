package cli

import (
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/web"
)

var webFlags struct {
	port   int
	global bool
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Serve the embedded web UI (token-protected)",
	Long: "Serve the embedded web UI. The listen URL contains a per-run random " +
		"token — anyone without that URL gets a 404. Defaults to loopback only; " +
		"pass --global to expose it on all interfaces at your own risk.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRoot(); err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		srv, err := web.New(newApp(st))
		if err != nil {
			return err
		}
		host := "127.0.0.1"
		if webFlags.global {
			host = "0.0.0.0"
		}
		if webFlags.port < 1 || webFlags.port > 65535 {
			return fmt.Errorf("invalid web port %d", webFlags.port)
		}
		listen := net.JoinHostPort(host, strconv.Itoa(webFlags.port))
		fmt.Fprintf(cmd.OutOrStderr(), "WGMGT web UI: %s\n", srv.URL(listen))
		if webFlags.global {
			fmt.Fprintf(cmd.OutOrStderr(), "WARNING: PLAIN HTTP on all interfaces — the URL token (and every client\nconf it serves, private keys included) is readable on the path. Prefer\nloopback + SSH tunnel, or a TLS reverse proxy.\n")
		}
		return srv.HTTPServer(listen).ListenAndServe()
	},
}

func init() {
	webCmd.Flags().IntVar(&webFlags.port, "port", 8080, "listen port")
	webCmd.Flags().BoolVar(&webFlags.global, "global", false, "listen on all interfaces (default loopback only)")
	rootCmd.AddCommand(webCmd)
}
