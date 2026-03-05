package mobile

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Device represents an abstracted mobile endpoint discovered via ADB.
type Device struct {
	ID   string            `json:"id"`
	OS   string            `json:"os"`
	Info map[string]string `json:"info"`
}

// ExtractionManifest records what was extracted during a ClearBrite dump.
type ExtractionManifest struct {
	DeviceID   string            `json:"device_id"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time"`
	Artifacts  []string          `json:"artifacts"`
	DeviceInfo map[string]string `json:"device_info"`
}

// ListDevices enumerates connected ADB devices and returns their metadata.
func ListDevices() ([]Device, error) {
	out, err := exec.Command("adb", "devices", "-l").Output()
	if err != nil {
		return nil, fmt.Errorf("adb devices: %w (is ADB installed and in PATH?)", err)
	}

	var devices []Device
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		// Skip header line "List of devices attached"
		if strings.HasPrefix(line, "List of") || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		deviceID := fields[0]
		state := fields[1]
		if state != "device" {
			// Skip offline/unauthorized devices
			continue
		}

		info := make(map[string]string)
		// Parse key:value pairs from extended output
		for _, f := range fields[2:] {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) == 2 {
				info[parts[0]] = parts[1]
			}
		}

		// Query device properties
		osVersion := adbGetProp(deviceID, "ro.build.version.release")
		model := adbGetProp(deviceID, "ro.product.model")
		manufacturer := adbGetProp(deviceID, "ro.product.manufacturer")
		sdk := adbGetProp(deviceID, "ro.build.version.sdk")

		if model != "" {
			info["model"] = model
		}
		if manufacturer != "" {
			info["manufacturer"] = manufacturer
		}
		if sdk != "" {
			info["sdk"] = sdk
		}

		devices = append(devices, Device{
			ID:   deviceID,
			OS:   "Android " + osVersion,
			Info: info,
		})
	}

	return devices, nil
}

// adbGetProp retrieves a system property from an ADB device.
func adbGetProp(deviceID, prop string) string {
	out, err := exec.Command("adb", "-s", deviceID, "shell", "getprop", prop).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ClearBriteDump performs a forensic-grade logical device extraction via ADB.
// It pulls device info, installed packages, filesystem artifacts, and
// generates a structured extraction manifest.
func ClearBriteDump(deviceID string, outDir string) error {
	fmt.Printf("[+] ClearBrite logical extraction: device=%s output=%s\n", deviceID, outDir)

	// Create output directory structure
	dirs := []string{
		filepath.Join(outDir, "device_info"),
		filepath.Join(outDir, "packages"),
		filepath.Join(outDir, "filesystem"),
		filepath.Join(outDir, "databases"),
		filepath.Join(outDir, "media"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("create directory %s: %w", d, err)
		}
	}

	manifest := ExtractionManifest{
		DeviceID:   deviceID,
		StartTime:  time.Now(),
		Artifacts:  []string{},
		DeviceInfo: make(map[string]string),
	}

	// Phase 1: Device information collection
	fmt.Println("[*] Phase 1: Collecting device information...")
	deviceProps := map[string]string{
		"os_version":     "ro.build.version.release",
		"sdk_version":    "ro.build.version.sdk",
		"model":          "ro.product.model",
		"manufacturer":   "ro.product.manufacturer",
		"brand":          "ro.product.brand",
		"device":         "ro.product.device",
		"board":          "ro.product.board",
		"hardware":       "ro.hardware",
		"serial":         "ro.serialno",
		"build_id":       "ro.build.id",
		"fingerprint":    "ro.build.fingerprint",
		"security_patch": "ro.build.version.security_patch",
		"bootloader":     "ro.bootloader",
		"baseband":       "gsm.version.baseband",
		"imei":           "persist.radio.imei",
	}

	for key, prop := range deviceProps {
		val := adbGetProp(deviceID, prop)
		if val != "" {
			manifest.DeviceInfo[key] = val
		}
	}

	// Write device info to file
	infoPath := filepath.Join(outDir, "device_info", "properties.json")
	infoData, _ := json.MarshalIndent(manifest.DeviceInfo, "", "  ")
	if err := os.WriteFile(infoPath, infoData, 0600); err != nil {
		return fmt.Errorf("write device info: %w", err)
	}
	manifest.Artifacts = append(manifest.Artifacts, "device_info/properties.json")
	fmt.Printf("    Collected %d device properties\n", len(manifest.DeviceInfo))

	// Phase 2: Installed packages
	fmt.Println("[*] Phase 2: Enumerating installed packages...")
	if err := adbDumpToFile(deviceID, []string{"shell", "pm", "list", "packages", "-f"},
		filepath.Join(outDir, "packages", "installed.txt")); err != nil {
		fmt.Printf("    [!] Package enumeration failed: %v\n", err)
	} else {
		manifest.Artifacts = append(manifest.Artifacts, "packages/installed.txt")
	}

	// Dump package permissions
	if err := adbDumpToFile(deviceID, []string{"shell", "dumpsys", "package"},
		filepath.Join(outDir, "packages", "package_dump.txt")); err != nil {
		fmt.Printf("    [!] Package dump failed: %v\n", err)
	} else {
		manifest.Artifacts = append(manifest.Artifacts, "packages/package_dump.txt")
	}

	// Phase 3: Network and connectivity info
	fmt.Println("[*] Phase 3: Collecting network information...")
	networkCmds := map[string][]string{
		"wifi_networks.txt": {"shell", "dumpsys", "wifi"},
		"network_stats.txt": {"shell", "dumpsys", "netstats"},
		"connectivity.txt":  {"shell", "dumpsys", "connectivity"},
		"ip_config.txt":     {"shell", "ip", "addr", "show"},
		"arp_table.txt":     {"shell", "ip", "neigh", "show"},
		"routing_table.txt": {"shell", "ip", "route", "show"},
	}
	for filename, cmdArgs := range networkCmds {
		outPath := filepath.Join(outDir, "device_info", filename)
		if err := adbDumpToFile(deviceID, cmdArgs, outPath); err == nil {
			manifest.Artifacts = append(manifest.Artifacts, "device_info/"+filename)
		}
	}

	// Phase 4: Pull accessible filesystem artifacts
	fmt.Println("[*] Phase 4: Pulling filesystem artifacts...")
	pullTargets := []string{
		"/sdcard/DCIM",
		"/sdcard/Download",
		"/sdcard/Documents",
		"/sdcard/WhatsApp",
		"/sdcard/Telegram",
	}
	for _, target := range pullTargets {
		localDir := filepath.Join(outDir, "filesystem", filepath.Base(target))
		if err := os.MkdirAll(localDir, 0700); err != nil {
			continue
		}
		// adb pull is recursive by default
		pullCmd := exec.Command("adb", "-s", deviceID, "pull", target, localDir)
		if err := pullCmd.Run(); err != nil {
			fmt.Printf("    [!] Pull %s: not accessible or empty\n", target)
		} else {
			manifest.Artifacts = append(manifest.Artifacts, "filesystem/"+filepath.Base(target))
			fmt.Printf("    [+] Pulled %s\n", target)
		}
	}

	// Phase 5: Dumpsys for forensic analysis
	fmt.Println("[*] Phase 5: Collecting system dumps...")
	dumpsysCmds := map[string][]string{
		"battery.txt":   {"shell", "dumpsys", "battery"},
		"accounts.txt":  {"shell", "dumpsys", "account"},
		"location.txt":  {"shell", "dumpsys", "location"},
		"telephony.txt": {"shell", "dumpsys", "telephony.registry"},
		"sms_calls.txt": {"shell", "content", "query", "--uri", "content://sms"},
		"contacts.txt":  {"shell", "content", "query", "--uri", "content://contacts/phones"},
		"call_log.txt":  {"shell", "content", "query", "--uri", "content://call_log/calls"},
	}
	for filename, cmdArgs := range dumpsysCmds {
		outPath := filepath.Join(outDir, "databases", filename)
		if err := adbDumpToFile(deviceID, cmdArgs, outPath); err == nil {
			manifest.Artifacts = append(manifest.Artifacts, "databases/"+filename)
		}
	}

	// Phase 6: Screenshot and screen recording
	fmt.Println("[*] Phase 6: Capturing screen state...")
	screenshotPath := "/sdcard/certstrike_screenshot.png"
	localScreenshot := filepath.Join(outDir, "media", "screenshot.png")
	screenCmd := exec.Command("adb", "-s", deviceID, "shell", "screencap", "-p", screenshotPath)
	if err := screenCmd.Run(); err == nil {
		pullCmd := exec.Command("adb", "-s", deviceID, "pull", screenshotPath, localScreenshot)
		if err := pullCmd.Run(); err == nil {
			manifest.Artifacts = append(manifest.Artifacts, "media/screenshot.png")
			fmt.Println("    [+] Screenshot captured")
		}
		// Clean up remote screenshot
		exec.Command("adb", "-s", deviceID, "shell", "rm", screenshotPath).Run()
	}

	// Write manifest
	manifest.EndTime = time.Now()
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	manifestPath := filepath.Join(outDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestData, 0600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	duration := manifest.EndTime.Sub(manifest.StartTime)
	fmt.Printf("\n[+] ClearBrite extraction complete\n")
	fmt.Printf("    Duration: %s\n", duration.Round(time.Millisecond))
	fmt.Printf("    Artifacts: %d\n", len(manifest.Artifacts))
	fmt.Printf("    Manifest: %s\n", manifestPath)
	return nil
}

// adbDumpToFile runs an ADB command and writes stdout to a file.
func adbDumpToFile(deviceID string, args []string, outPath string) error {
	fullArgs := append([]string{"-s", deviceID}, args...)
	out, err := exec.Command("adb", fullArgs...).Output()
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, out, 0600)
}

// SimulateZeroClick performs a zero-click exploit simulation against a target.
// It probes the target's network services, identifies potential attack surfaces,
// and simulates payload delivery vectors without actual exploitation.
func SimulateZeroClick(targetIP string, payloadType string) error {
	fmt.Printf("[!] Zero-click simulation: target=%s payload=%s\n", targetIP, payloadType)

	// Phase 1: Service discovery via port scanning
	fmt.Println("[*] Phase 1: Service discovery...")
	ports := []int{22, 53, 80, 443, 5060, 5061, 8080, 8443}
	openPorts := []int{}
	for _, port := range ports {
		_ = fmt.Sprintf("%s:%d", targetIP, port) // reserved for direct TCP probe fallback
		// Use nmap if available, otherwise basic TCP probe
		out, err := exec.Command("nmap", "-Pn", "-p", fmt.Sprintf("%d", port),
			"--open", "-T4", targetIP).Output()
		if err == nil && strings.Contains(string(out), "open") {
			openPorts = append(openPorts, port)
			fmt.Printf("    [+] Port %d: open\n", port)
		}
	}

	if len(openPorts) == 0 {
		fmt.Println("    [!] No open ports discovered via nmap, attempting raw TCP probes...")
		// Fallback: use netcat-style probing
		for _, port := range ports {
			out, err := exec.Command("bash", "-c",
				fmt.Sprintf("echo | timeout 2 nc -w1 %s %d 2>/dev/null && echo open", targetIP, port)).Output()
			if err == nil && strings.Contains(string(out), "open") {
				openPorts = append(openPorts, port)
				fmt.Printf("    [+] Port %d: open\n", port)
			}
		}
	}

	// Phase 2: Attack surface analysis
	fmt.Println("[*] Phase 2: Attack surface analysis...")
	var vectors []string
	for _, port := range openPorts {
		switch port {
		case 5060, 5061:
			vectors = append(vectors, "SIP/VoIP (baseband attack vector)")
		case 443, 8443:
			vectors = append(vectors, "HTTPS (WebKit/browser exploit chain)")
		case 53:
			vectors = append(vectors, "DNS (cache poisoning / redirect)")
		case 80, 8080:
			vectors = append(vectors, "HTTP (MitM injection point)")
		case 22:
			vectors = append(vectors, "SSH (credential brute-force)")
		}
	}

	// Phase 3: Payload simulation
	fmt.Printf("[*] Phase 3: Simulating %s payload delivery...\n", payloadType)
	switch payloadType {
	case "pegasus":
		fmt.Println("    [*] Vector: iMessage / WhatsApp zero-click")
		fmt.Println("    [*] Stage 1: Initial exploit trigger via crafted message")
		fmt.Println("    [*] Stage 2: Sandbox escape via kernel vulnerability")
		fmt.Println("    [*] Stage 3: Persistence via system daemon injection")
	case "predator":
		fmt.Println("    [*] Vector: Browser-based exploit chain")
		fmt.Println("    [*] Stage 1: JavaScript engine type confusion")
		fmt.Println("    [*] Stage 2: Renderer process compromise")
		fmt.Println("    [*] Stage 3: Kernel exploit for privilege escalation")
	case "chrysaor":
		fmt.Println("    [*] Vector: Android Binder IPC exploitation")
		fmt.Println("    [*] Stage 1: Framaroot-derived root exploit")
		fmt.Println("    [*] Stage 2: SELinux policy bypass")
		fmt.Println("    [*] Stage 3: System partition modification")
	default:
		fmt.Printf("    [*] Vector: Generic %s payload delivery\n", payloadType)
	}

	// Phase 4: Results summary
	fmt.Println("\n[+] Simulation complete")
	fmt.Printf("    Target: %s\n", targetIP)
	fmt.Printf("    Open ports: %d\n", len(openPorts))
	fmt.Printf("    Attack vectors: %d\n", len(vectors))
	for _, v := range vectors {
		fmt.Printf("      - %s\n", v)
	}
	fmt.Println("    [!] This was a SIMULATION — no actual exploitation was performed")

	return nil
}
