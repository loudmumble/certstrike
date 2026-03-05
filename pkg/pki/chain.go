package pki

import (
	"fmt"
	"strings"
)

// AttackPath represents a prioritized ADCS attack chain.
type AttackPath struct {
	Priority    int          `json:"priority"`
	ESCType     string       `json:"esc_type"`
	Template    CertTemplate `json:"template"`
	Description string       `json:"description"`
	Impact      string       `json:"impact"`
	Difficulty  string       `json:"difficulty"`
	Steps       []string     `json:"steps"`
}

// ESCDescription maps ESC types to human-readable descriptions.
var ESCDescription = map[string]struct {
	Name       string
	Impact     string
	Difficulty string
}{
	"ESC1":      {"Misconfigured Certificate Templates", "Domain Admin impersonation via forged certificate", "Low"},
	"ESC2":      {"Misconfigured Certificate Templates (Any Purpose)", "Privilege escalation via any-purpose certificate", "Low"},
	"ESC3":      {"Enrollment Agent Templates", "Enroll on behalf of other users", "Medium"},
	"ESC4":      {"Vulnerable Certificate Template ACLs", "Modify template to enable ESC1, then exploit", "Medium"},
	"ESC4-CHECK": {"Template ACL Review Needed", "Potential WriteDacl/WriteOwner on template", "Unknown"},
	"ESC5":      {"Vulnerable PKI Object ACLs", "Modify CA or enrollment service configuration", "High"},
	"ESC6":      {"EDITF_ATTRIBUTESUBJECTALTNAME2", "CA allows arbitrary SAN in requests", "Low"},
	"ESC7":      {"Vulnerable CA ACLs", "ManageCA/ManageCertificates on CA server", "Medium"},
	"ESC8":      {"NTLM Relay to AD CS HTTP Endpoints", "Relay NTLM auth to web enrollment", "Medium"},
}

// BuildAttackChain analyzes enumerated templates and generates prioritized attack paths.
func BuildAttackChain(cfg *ADCSConfig) ([]AttackPath, error) {
	fmt.Println("[*] Building ADCS attack chain...")
	fmt.Printf("[*] Target: %s\\%s\n", cfg.Domain, cfg.TargetDC)

	templates, err := EnumerateTemplates(cfg)
	if err != nil {
		return nil, fmt.Errorf("enumerate: %w", err)
	}

	var paths []AttackPath
	priority := 1

	for _, tmpl := range templates {
		for _, vuln := range tmpl.ESCVulns {
			desc, ok := ESCDescription[vuln]
			if !ok {
				continue
			}

			path := AttackPath{
				Priority:    priority,
				ESCType:     vuln,
				Template:    tmpl,
				Description: desc.Name,
				Impact:      desc.Impact,
				Difficulty:  desc.Difficulty,
				Steps:       buildSteps(vuln, tmpl, cfg),
			}
			paths = append(paths, path)
			priority++
		}
	}

	// Sort by ESC score (higher = more exploitable = higher priority)
	for i := 0; i < len(paths)-1; i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j].Template.ESCScore > paths[i].Template.ESCScore {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}

	// Re-assign priority numbers after sorting
	for i := range paths {
		paths[i].Priority = i + 1
	}

	return paths, nil
}

func buildSteps(escType string, tmpl CertTemplate, cfg *ADCSConfig) []string {
	switch escType {
	case "ESC1":
		return []string{
			fmt.Sprintf("Identify template: %s (enrollee supplies subject + auth EKU)", tmpl.Name),
			"Request certificate with arbitrary SAN (e.g., administrator@" + cfg.Domain + ")",
			"Use forged certificate for Kerberos PKINIT or Schannel authentication",
			fmt.Sprintf("Command: certstrike pki --exploit esc1 --template %s --upn administrator@%s --target-dc %s --domain %s",
				tmpl.Name, cfg.Domain, cfg.TargetDC, cfg.Domain),
		}
	case "ESC2":
		return []string{
			fmt.Sprintf("Identify template: %s (Any Purpose EKU + enrollee supplies subject)", tmpl.Name),
			"Request certificate with Any Purpose EKU — can be used as client auth",
			"Authenticate as any user specified in the SAN",
		}
	case "ESC3":
		return []string{
			fmt.Sprintf("Identify template: %s (Certificate Request Agent EKU)", tmpl.Name),
			"Enroll for enrollment agent certificate",
			"Use agent certificate to enroll on behalf of other users in restricted templates",
		}
	case "ESC4", "ESC4-CHECK":
		return []string{
			fmt.Sprintf("Identify template: %s (WriteDacl/WriteOwner ACL)", tmpl.Name),
			"Modify template msPKI-Certificate-Name-Flag to enable ENROLLEE_SUPPLIES_SUBJECT",
			"Exploit modified template as ESC1",
			"Restore original template configuration",
			fmt.Sprintf("Command: certstrike pki --exploit esc4 --template %s --upn administrator@%s --target-dc %s --domain %s",
				tmpl.Name, cfg.Domain, cfg.TargetDC, cfg.Domain),
		}
	default:
		return []string{
			fmt.Sprintf("Review template: %s for %s vulnerability", tmpl.Name, escType),
			"Manual exploitation required — see documentation",
		}
	}
}

// PrintAttackChain prints a formatted attack chain report.
func PrintAttackChain(paths []AttackPath) {
	if len(paths) == 0 {
		fmt.Println("[*] No exploitable attack paths found.")
		return
	}

	fmt.Printf("\n╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║           ADCS ATTACK CHAIN — %d PATH(S) DETECTED           ║\n", len(paths))
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n\n")

	for _, path := range paths {
		fmt.Printf("━━━ [%d] %s on %q ━━━\n", path.Priority, path.ESCType, path.Template.Name)
		fmt.Printf("    Description: %s\n", path.Description)
		fmt.Printf("    Impact:      %s\n", path.Impact)
		fmt.Printf("    Difficulty:  %s\n", path.Difficulty)
		fmt.Printf("    Score:       %d\n", path.Template.ESCScore)
		fmt.Printf("    Vulns:       %s\n", strings.Join(path.Template.ESCVulns, ", "))
		fmt.Printf("    Steps:\n")
		for i, step := range path.Steps {
			fmt.Printf("      %d. %s\n", i+1, step)
		}
		fmt.Println()
	}
}
