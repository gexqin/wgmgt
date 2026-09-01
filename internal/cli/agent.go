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
	server        string
	ca            string
	cert          string
	key           string
	token         string
	caHash        string
	interval      time.Duration
	verifyTimeout time.Duration
	confDir       string
}

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run the agent: pull config from the controller and apply it",
	Long: "The agent is stateless besides its certificate and generated conf " +
		"files. It connects out to the controller over mTLS and long-polls " +
		"for its client's desired configuration (changes arrive in " +
		"milliseconds), applies it via netlink, and reports live status " +
		"with each poll.\n\n" +
		"Bootstrap: with --token (and --ca-hash from the controller's join " +
		"command) the agent generates its own keypair, exchanges the " +
		"one-time token for a certificate, persists the material under " +
		"--conf-dir, and continues into the normal poll loop.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireRoot(); err != nil {
			return err
		}
		var caPEM, certPEM, keyPEM []byte
		if agentFlags.token != "" {
			if cmd.Flags().Changed("cert") || cmd.Flags().Changed("key") {
				return fmt.Errorf("--token cannot be combined with --cert/--key")
			}
			if agentFlags.caHash == "" {
				return fmt.Errorf("--token requires --ca-hash (pin the controller CA; the controller prints it in the join command)")
			}
			var ok bool
			// Restart safety: the token is burned, so reuse persisted
			// material when it is already there.
			if caPEM, certPEM, keyPEM, ok = agent.LoadMaterial(agentFlags.confDir); ok {
				fmt.Fprintf(cmd.OutOrStderr(), "wgmgt agent: found existing certificate material in %s; skipping enrollment\n", agentFlags.confDir)
			} else {
				var err error
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				caPEM, certPEM, keyPEM, err = agent.Enroll(ctx, agentFlags.server, agentFlags.token, agentFlags.caHash, agentFlags.confDir)
				cancel()
				if err != nil {
					return fmt.Errorf("enrollment failed: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStderr(), "wgmgt agent: enrolled; certificate material saved to %s\n", agentFlags.confDir)
			}
		} else {
			if agentFlags.cert == "" || agentFlags.key == "" {
				return fmt.Errorf("--cert and --key are required (or use --token for one-time enrollment)")
			}
			var err error
			if caPEM, err = os.ReadFile(agentFlags.ca); err != nil {
				return fmt.Errorf("--ca: %w", err)
			}
			if certPEM, err = os.ReadFile(agentFlags.cert); err != nil {
				return fmt.Errorf("--cert: %w", err)
			}
			if keyPEM, err = os.ReadFile(agentFlags.key); err != nil {
				return fmt.Errorf("--key: %w", err)
			}
		}
		a, err := agent.New(agentFlags.server, caPEM, certPEM, keyPEM, agentFlags.interval, agentFlags.verifyTimeout, agentFlags.confDir)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		fmt.Fprintf(cmd.OutOrStderr(), "wgmgt agent: long-polling %s (retry backoff %s, verify-timeout %s)\n",
			agentFlags.server, agentFlags.interval, agentFlags.verifyTimeout)
		return a.Run(ctx)
	},
}

func init() {
	agentCmd.Flags().StringVar(&agentFlags.server, "server", "", "controller URL, e.g. https://ctrl:8443 (required)")
	agentCmd.Flags().StringVar(&agentFlags.ca, "ca", "ca.pem", "controller CA certificate")
	agentCmd.Flags().StringVar(&agentFlags.cert, "cert", "", "agent certificate (with --token path: must not be set)")
	agentCmd.Flags().StringVar(&agentFlags.key, "key", "", "agent private key (with --token path: must not be set)")
	agentCmd.Flags().StringVar(&agentFlags.token, "token", "", "one-time enrollment token (bootstrap path; requires --ca-hash)")
	agentCmd.Flags().StringVar(&agentFlags.caHash, "ca-hash", "", "pinned controller CA fingerprint (sha256:<hex> or bare hex, from the join command)")
	agentCmd.Flags().DurationVar(&agentFlags.interval, "interval", 30*time.Second, "backoff between retries after a failed poll (normal cadence is server-driven long-polling)")
	agentCmd.Flags().DurationVar(&agentFlags.verifyTimeout, "verify-timeout", 180*time.Second,
		"dead-man switch: if the controller stays unreachable this long after a config change, roll back WireGuard (0 disables)")
	agentCmd.Flags().StringVar(&agentFlags.confDir, "conf-dir", "/etc/wireguard/wgmgt-agent", "directory for generated conf files and enrollment material")
	_ = agentCmd.MarkFlagRequired("server")
	rootCmd.AddCommand(agentCmd)
}
