package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var mobileCmd = &cobra.Command{
	Use:   "mobile",
	Short: "Mobile Device Extraction and Zero-Click Simulation",
	Long:  "Integration with ClearBrite extractions, ADB logical bridging, and Pegasus-style vulnerability simulation.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[Mobile Module] Forensic extraction toolkit initialized.")
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(mobileCmd)
}
