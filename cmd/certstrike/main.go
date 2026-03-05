package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "certstrike",
	Short: "CertStrike — Next-Gen PKI, Certificate, and Mobile Attack Framework",
	Long: `CertStrike integrates Active Directory Certificate Services (ADCS) exploitation,
mobile forensic extraction/zero-click simulation, and an advanced C2 framework.

Usage:
  certstrike pki --enum --target-dc dc01.corp.local --domain corp.local
  certstrike pki --forge --upn admin@corp.local --ca-key ca.pem --output cert.pem
  certstrike mobile --extract --device-id emulator-5554 --output-dir ./out
  certstrike mobile --zero-click --target-ip 192.168.1.100 --payload-type pegasus
  certstrike c2 --bind 0.0.0.0 --port 8443 --protocol https
  certstrike c2 --generate-stager --output stager.json`,
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
