package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var c2Cmd = &cobra.Command{
	Use:   "c2",
	Short: "Command and Control center",
	Long:  "Launch listeners, generate stagers, and manage sessions across multi-OS potato implants.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[C2 Server] Starting multiplexer console.")
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(c2Cmd)
}
