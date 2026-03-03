package pki

import (
	"crypto/x509"
	"fmt"
	"math/big"
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
func Enumerate(cfg *ADCSConfig) ([]string, error) {
	fmt.Printf("[*] Enumerating ADCS templates on %s\\%s...\n", cfg.Domain, cfg.TargetDC)
	// Simulated robust check
	time.Sleep(1 * time.Second)
	return []string{
		"Machine", "User", "WebServer", "EFSRecovery",
	}, nil
}

// ForgeCertificate simulates forging a golden certificate offline given a CA key.
func ForgeCertificate(caKey []byte, upn string) (*x509.Certificate, error) {
	fmt.Printf("[!] Forging Golden Certificate for UPN: %s\n", upn)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1337),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	return template, nil
}
