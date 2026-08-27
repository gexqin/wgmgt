package cli

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/web"
)

var webFlags struct {
	listen string
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Serve the embedded web UI (token-protected)",
	Long: "Serve the embedded web UI. The listen URL contains a per-run random " +
		"token — anyone without that URL gets a 404. Defaults to loopback only; " +
		"change --listen to expose on a network at your own risk.",
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
		fmt.Fprintf(cmd.OutOrStderr(), "WGMGT web UI: %s\n", srv.URL(webFlags.listen))
		return http.ListenAndServe(webFlags.listen, srv.Handler())
	},
}

func init() {
	webCmd.Flags().StringVar(&webFlags.listen, "listen", "127.0.0.1:8080", "listen address (default loopback only)")
	rootCmd.AddCommand(webCmd)
}
