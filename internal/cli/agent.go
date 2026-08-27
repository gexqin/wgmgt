package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/gexqin/wgmgt/internal/agent"
)

var agentFlags struct {
	server   string
	ca       string
	cert     string
	key      string
	interval time.Duration
	confDir  string
}

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run the agent: pull config from the controller and apply it",
	Long: "The agent is stateless besides its certificate and generated conf " +
		"files. It connects out to the controller over mTLS, pulls its node's " +
		"desired configuration on an interval, applies it via netlink, and " +
		"reports live status with each poll.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRoot(); err != nil {
			return err
		}
		caPEM, err := os.ReadFile(agentFlags.ca)
		if err != nil {
			return fmt.Errorf("--ca: %w", err)
		}
		certPEM, err := os.ReadFile(agentFlags.cert)
		if err != nil {
			return fmt.Errorf("--cert: %w", err)
		}
		keyPEM, err := os.ReadFile(agentFlags.key)
		if err != nil {
			return fmt.Errorf("--key: %w", err)
		}
		a, err := agent.New(agentFlags.server, caPEM, certPEM, keyPEM, agentFlags.interval, agentFlags.confDir)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		fmt.Fprintf(cmd.OutOrStderr(), "wgmgt agent: polling %s every %s\n", agentFlags.server, agentFlags.interval)
		return a.Run(ctx)
	},
}

func init() {
	agentCmd.Flags().StringVar(&agentFlags.server, "server", "", "controller URL, e.g. https://ctrl:8443 (required)")
	agentCmd.Flags().StringVar(&agentFlags.ca, "ca", "ca.pem", "controller CA certificate")
	agentCmd.Flags().StringVar(&agentFlags.cert, "cert", "", "agent certificate (required)")
	agentCmd.Flags().StringVar(&agentFlags.key, "key", "", "agent private key (required)")
	agentCmd.Flags().DurationVar(&agentFlags.interval, "interval", 30*time.Second, "poll interval")
	agentCmd.Flags().StringVar(&agentFlags.confDir, "conf-dir", "/etc/wireguard/wgmgt-agent", "directory for generated conf files")
	_ = agentCmd.MarkFlagRequired("server")
	_ = agentCmd.MarkFlagRequired("cert")
	_ = agentCmd.MarkFlagRequired("key")
	rootCmd.AddCommand(agentCmd)
}
