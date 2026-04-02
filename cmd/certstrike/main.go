package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "certstrike",
	Short: "CertStrike — ADCS Exploitation & PKI Attack Framework",
	Long: `CertStrike is a pure Go ADCS exploitation framework with integrated C2.
ESC1-ESC14 detection and exploitation, certificate forging, and cert-auth C2.

Usage:
  certstrike pki --enum --target-dc dc01.corp.local --domain corp.local
  certstrike pki --forge --upn admin@corp.local --ca-key ca.pem --output cert.pem
  certstrike pki --exploit esc1 --template VulnTemplate --upn admin@corp.local
  certstrike c2 --bind 0.0.0.0 --port 8443 --protocol https
  certstrike agent --config stager.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("CertStrike v%s\n", version)
		return cmd.Help()
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
