package main

import (
	"fmt"

	"github.com/loudmumble/certstrike/pkg/mobile"
	"github.com/spf13/cobra"
)

var mobileCmd = &cobra.Command{
	Use:   "mobile",
	Short: "Mobile device extraction and zero-click simulation",
	Long: `Forensic-grade logical device extraction via ADB and Pegasus-style
zero-click vulnerability simulation.

Examples:
  certstrike mobile --extract --device-id emulator-5554 --output-dir ./extraction
  certstrike mobile --zero-click --target-ip 192.168.1.100 --payload-type pegasus
  certstrike mobile --list-devices`,
	RunE: func(cmd *cobra.Command, args []string) error {
		doExtract, _ := cmd.Flags().GetBool("extract")
		doZeroClick, _ := cmd.Flags().GetBool("zero-click")
		doList, _ := cmd.Flags().GetBool("list-devices")

		if !doExtract && !doZeroClick && !doList {
			return cmd.Help()
		}

		if doList {
			devices, err := mobile.ListDevices()
			if err != nil {
				return fmt.Errorf("list devices: %w", err)
			}
			if len(devices) == 0 {
				fmt.Println("[*] No devices found. Ensure ADB is running and devices are connected.")
				return nil
			}
			fmt.Printf("[+] Found %d device(s):\n", len(devices))
			for _, d := range devices {
				fmt.Printf("  %-20s  OS: %-10s  Model: %s\n", d.ID, d.OS, d.Info["model"])
			}
			return nil
		}

		if doExtract {
			deviceID, _ := cmd.Flags().GetString("device-id")
			outputDir, _ := cmd.Flags().GetString("output-dir")
			if deviceID == "" {
				return fmt.Errorf("--device-id is required for extraction")
			}
			if outputDir == "" {
				outputDir = "./extraction"
			}
			return mobile.ClearBriteDump(deviceID, outputDir)
		}

		if doZeroClick {
			targetIP, _ := cmd.Flags().GetString("target-ip")
			payloadType, _ := cmd.Flags().GetString("payload-type")
			if targetIP == "" {
				return fmt.Errorf("--target-ip is required for zero-click simulation")
			}
			if payloadType == "" {
				payloadType = "pegasus"
			}
			return mobile.SimulateZeroClick(targetIP, payloadType)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(mobileCmd)

	mobileCmd.Flags().Bool("extract", false, "Perform forensic device extraction")
	mobileCmd.Flags().Bool("zero-click", false, "Run zero-click exploit simulation")
	mobileCmd.Flags().Bool("list-devices", false, "List connected ADB devices")
	mobileCmd.Flags().String("device-id", "", "Target device ID (from adb devices)")
	mobileCmd.Flags().String("output-dir", "", "Output directory for extraction artifacts")
	mobileCmd.Flags().String("target-ip", "", "Target IP for zero-click simulation")
	mobileCmd.Flags().String("payload-type", "pegasus", "Payload type: pegasus, predator, chrysaor")
}
