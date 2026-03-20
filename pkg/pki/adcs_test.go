package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestBuildCertTemplateBaseDN(t *testing.T) {
	expected := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
	got := buildCertTemplateBaseDN("corp.local")
	if got != expected {
		t.Errorf("Expected %s, got %s", expected, got)
	}
}

func TestBuildBindDN(t *testing.T) {
	tests := []struct {
		user, domain, expected string
	}{
		{"admin", "corp.local", "admin@corp.local"},
		{"admin@corp.local", "corp.local", "admin@corp.local"},
		{"CN=admin,DC=corp", "corp.local", "CN=admin,DC=corp"},
	}
	for _, tc := range tests {
		got := buildBindDN(tc.user, tc.domain)
		if got != tc.expected {
			t.Errorf("buildBindDN(%q, %q) = %q, want %q", tc.user, tc.domain, got, tc.expected)
		}
	}
}

func TestHasAuthenticationEKU(t *testing.T) {
	if !hasAuthenticationEKU(nil) {
		t.Error("nil EKUs should allow authentication")
	}
	if !hasAuthenticationEKU([]string{ekuClientAuth}) {
		t.Error("ClientAuth EKU should be authentication")
	}
	if hasAuthenticationEKU([]string{"1.2.3.4.5"}) {
		t.Error("Random OID should not be authentication EKU")
	}
}

func TestScoreESC(t *testing.T) {
	// ESC1: enrollee supplies subject + auth EKU + no approval + no signatures
	tmpl := CertTemplate{
		EnrolleeSuppliesSubject: true,
		AuthenticationEKU:       true,
		RequiresManagerApproval: false,
		AuthorizedSignatures:    0,
	}
	scoreESC(&tmpl)
	found := false
	for _, v := range tmpl.ESCVulns {
		if v == "ESC1" {
			found = true
		}
	}
	if !found {
		t.Error("Expected ESC1 vulnerability for template with all ESC1 conditions")
	}
	if tmpl.ESCScore < 10 {
		t.Errorf("Expected ESC score >= 10 for ESC1, got %d", tmpl.ESCScore)
	}
}

func TestEnumerate(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01.corp.local",
		Domain:   "corp.local",
		Username: "testuser",
		Password: "testpass",
	}

	_, err := Enumerate(cfg)
	if err != nil {
		t.Logf("Enumerate returned error (expected without DC): %v", err)
		return
	}
}

func TestForgeCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	upn := "admin@corp.local"
	cert, certKey, err := ForgeCertificate(caKey, upn)
	if err != nil {
		t.Fatalf("ForgeCertificate failed: %v", err)
	}

	if certKey == nil {
		t.Fatal("Expected private key, got nil")
	}
	if cert == nil {
		t.Fatal("Expected certificate, got nil")
	}
	if cert.SerialNumber.Int64() != 1337 {
		t.Errorf("Expected serial number 1337, got %d", cert.SerialNumber.Int64())
	}
	if cert.IsCA {
		t.Error("Certificate should not be marked as CA")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Missing DigitalSignature key usage")
	}

	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("Missing ClientAuth EKU")
	}
}

func TestForgeCertificate_WithDifferentUPNs(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, upn := range []string{"user@domain.local", "administrator@corp.internal", "svc@test.lab"} {
		t.Run(upn, func(t *testing.T) {
			cert, certKey, err := ForgeCertificate(caKey, upn)
			if err != nil {
				t.Errorf("ForgeCertificate failed for UPN %s: %v", upn, err)
			}
			if cert == nil {
				t.Errorf("Expected certificate for UPN %s", upn)
			}
			if certKey == nil {
				t.Errorf("Expected private key for UPN %s", upn)
			}
		})
	}
}
