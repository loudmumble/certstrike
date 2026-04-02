package pki

import (
	"fmt"
)

// EnumerationResult holds all scan results from a full ADCS enumeration pass.
// Designed for structured JSON output and report generation.
type EnumerationResult struct {
	Domain        string          `json:"domain"`
	TargetDC      string          `json:"target_dc"`
	Templates     []CertTemplate  `json:"templates"`
	ESC2Findings  []ESC2Finding   `json:"esc2_findings"`
	ESC3Findings  []ESC3Finding   `json:"esc3_findings"`
	ESC5Findings  []ESC5Finding   `json:"esc5_findings"`
	ESC6Findings  []ESC6Finding   `json:"esc6_findings"`
	ESC7Findings  []ESC7Finding   `json:"esc7_findings"`
	ESC8Findings  []ESC8Finding   `json:"esc8_findings"`
	ESC9Findings  []ESC9Finding   `json:"esc9_findings"`
	ESC10Findings []ESC10Finding  `json:"esc10_findings"`
	ESC11Findings []ESC11Finding  `json:"esc11_findings"`
	ESC12Findings []ESC12Finding  `json:"esc12_findings"`
	ESC13Findings []ESC13Finding  `json:"esc13_findings"`
	ESC14Findings []ESC14Finding  `json:"esc14_findings"`
	VulnCount     int             `json:"vuln_count"`
	TotalScore    int             `json:"total_score"`
}

// EnumerateAll performs a comprehensive ADCS scan: template enumeration plus all ESC scans.
// Returns a structured EnumerationResult suitable for JSON output or report generation.
func EnumerateAll(cfg *ADCSConfig) (EnumerationResult, error) {
	result := EnumerationResult{
		Domain:   cfg.Domain,
		TargetDC: cfg.TargetDC,
	}

	// Step 1: Enumerate templates (includes ESC1-4, ESC6, ESC7, ESC9 template-level checks)
	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return result, fmt.Errorf("enumerate templates: %w", err)
	}
	result.Templates = templates

	// Step 2: ESC2 — Any Purpose EKU templates
	stealthDelay(cfg)
	esc2, err := ScanESC2(cfg)
	if err != nil {
		fmt.Printf("[!] ESC2 scan failed: %v\n", err)
	} else {
		result.ESC2Findings = esc2
	}

	// Step 3: ESC3 — Enrollment Agent templates
	stealthDelay(cfg)
	esc3, err := ScanESC3(cfg)
	if err != nil {
		fmt.Printf("[!] ESC3 scan failed: %v\n", err)
	} else {
		result.ESC3Findings = esc3
	}

	// Step 4: ESC5 — CA object ACL inspection
	stealthDelay(cfg)
	esc5, err := ScanESC5(cfg)
	if err != nil {
		fmt.Printf("[!] ESC5 scan failed: %v\n", err)
	} else {
		result.ESC5Findings = esc5
	}

	// ESC12 — DCOM interface abuse on CA
	stealthDelay(cfg)
	esc12, err := ScanESC12(cfg)
	if err != nil {
		fmt.Printf("[!] ESC12 scan failed: %v\n", err)
	} else {
		result.ESC12Findings = esc12
	}

	// Step 5: ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2
	stealthDelay(cfg)
	esc6, err := ScanESC6(cfg)
	if err != nil {
		fmt.Printf("[!] ESC6 scan failed: %v\n", err)
	} else {
		result.ESC6Findings = esc6
	}

	// Step 6: ESC7 — Vulnerable CA ACLs
	stealthDelay(cfg)
	esc7, err := ScanESC7(cfg)
	if err != nil {
		fmt.Printf("[!] ESC7 scan failed: %v\n", err)
	} else {
		result.ESC7Findings = esc7
	}

	// Step 7: ESC8 — NTLM relay to web enrollment
	stealthDelay(cfg)
	esc8, err := ScanESC8(cfg)
	if err != nil {
		fmt.Printf("[!] ESC8 scan failed: %v\n", err)
	} else {
		result.ESC8Findings = esc8
	}

	// Step 4: ESC9 — CT_FLAG_NO_SECURITY_EXTENSION
	stealthDelay(cfg)
	esc9, err := ScanESC9(cfg)
	if err != nil {
		fmt.Printf("[!] ESC9 scan failed: %v\n", err)
	} else {
		result.ESC9Findings = esc9
	}

	// Step 5: ESC11 — NTLM relay to RPC interface
	stealthDelay(cfg)
	esc11, err := ScanESC11(cfg)
	if err != nil {
		fmt.Printf("[!] ESC11 scan failed: %v\n", err)
	} else {
		result.ESC11Findings = esc11
	}

	// Step 6: ESC10 — Weak certificate mapping methods
	stealthDelay(cfg)
	esc10, err := ScanESC10(cfg)
	if err != nil {
		fmt.Printf("[!] ESC10 scan failed: %v\n", err)
	} else {
		result.ESC10Findings = esc10
	}

	// Step 7: ESC13 — OID group link abuse
	stealthDelay(cfg)
	esc13, err := ScanESC13(cfg)
	if err != nil {
		fmt.Printf("[!] ESC13 scan failed: %v\n", err)
	} else {
		result.ESC13Findings = esc13
	}

	// Step 8: ESC14 — Weak explicit mappings
	stealthDelay(cfg)
	esc14, err := ScanESC14(cfg)
	if err != nil {
		fmt.Printf("[!] ESC14 scan failed: %v\n", err)
	} else {
		result.ESC14Findings = esc14
	}

	// Compute summary stats
	for _, t := range result.Templates {
		if t.ESCScore > 0 {
			result.VulnCount++
			result.TotalScore += t.ESCScore
		}
	}
	result.VulnCount += len(result.ESC2Findings) + len(result.ESC3Findings) +
		len(result.ESC5Findings) + len(result.ESC6Findings) + len(result.ESC7Findings) +
		len(result.ESC8Findings) + len(result.ESC9Findings) + len(result.ESC10Findings) +
		len(result.ESC11Findings) + len(result.ESC12Findings) + len(result.ESC13Findings) + len(result.ESC14Findings)

	return result, nil
}

// ExploitResult holds structured output from an exploitation run.
type ExploitResult struct {
	Exploit      string `json:"exploit"`
	Template     string `json:"template"`
	TargetUPN    string `json:"target_upn"`
	CertPath     string `json:"cert_path,omitempty"`
	KeyPath      string `json:"key_path,omitempty"`
	PFXPath      string `json:"pfx_path,omitempty"`
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
}

