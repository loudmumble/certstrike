package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "certstrike",
	Short: "CertStrike is a next-gen PKI, Certificate, and Mobile Attack Framework",
	Long: `CertStrike integrates Active Directory Certificate Services (ADCS) exploitation,
mobile forensic extraction/zero-click simulation, and an advanced C2 framework.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to CertStrike v1.0.0")
		cmd.Help()
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
