package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestEnumerate(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01.corp.local",
		Domain:   "corp.local",
		Username: "testuser",
		Password: "testpass",
	}

	templates, err := Enumerate(cfg)
	if err != nil {
		t.Fatalf("Enumerate failed: %v", err)
	}

	if len(templates) == 0 {
		t.Error("Expected at least one template, got none")
	}

	// Verify expected templates are present
	expectedTemplates := map[string]bool{
		"Machine": false, "User": false, "WebServer": false, "EFSRecovery": false,
	}
	for _, tmpl := range templates {
		if _, ok := expectedTemplates[tmpl]; ok {
			expectedTemplates[tmpl] = true
		}
	}
	for tmpl, found := range expectedTemplates {
		if !found {
			t.Errorf("Expected template %s not found in results", tmpl)
		}
	}
}

func TestForgeCertificate(t *testing.T) {
	// Generate a test CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Forge a certificate
	upn := "admin@corp.local"
	cert, err := ForgeCertificate(caKey, upn)
	if err != nil {
		t.Fatalf("ForgeCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected certificate, got nil")
	}

	// Verify certificate properties
	if cert.SerialNumber.Int64() != 1337 {
		t.Errorf("Expected serial number 1337, got %d", cert.SerialNumber.Int64())
	}

	if !cert.NotBefore.Before(cert.NotAfter) {
		t.Error("Certificate validity period is invalid")
	}

	if cert.IsCA {
		t.Error("Certificate should not be marked as CA")
	}

	// Verify key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Certificate should have DigitalSignature key usage")
	}

	// Verify extended key usage
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Error("Certificate should have ClientAuth extended key usage")
	}
}

func TestForgeCertificate_WithDifferentUPNs(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	testCases := []string{
		"user@domain.local",
		"administrator@corp.internal",
		"service.account@test.lab",
	}

	for _, upn := range testCases {
		t.Run(upn, func(t *testing.T) {
			cert, err := ForgeCertificate(caKey, upn)
			if err != nil {
				t.Errorf("ForgeCertificate failed for UPN %s: %v", upn, err)
			}
			if cert == nil {
				t.Errorf("Expected certificate for UPN %s, got nil", upn)
			}
		})
	}
}
