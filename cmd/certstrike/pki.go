package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var pkiCmd = &cobra.Command{
	Use:   "pki",
	Short: "Advanced Certificate/PKI attack toolkit",
	Long:  "Contains functionality for ADCS enumeration (ESC1-ESC11), golden certificate forging, and mTLS interception.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[PKI Module] Ready for operations.")
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(pkiCmd)
}
