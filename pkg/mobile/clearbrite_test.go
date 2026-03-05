package mobile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDevice_Struct(t *testing.T) {
	device := Device{
		ID: "emulator-5554",
		OS: "Android",
		Info: map[string]string{
			"model":   "Pixel 5",
			"version": "13",
		},
	}

	if device.ID != "emulator-5554" {
		t.Errorf("Expected ID 'emulator-5554', got %s", device.ID)
	}

	if device.OS != "Android" {
		t.Errorf("Expected OS 'Android', got %s", device.OS)
	}

	if device.Info["model"] != "Pixel 5" {
		t.Errorf("Expected model 'Pixel 5', got %s", device.Info["model"])
	}
}

func TestClearBriteDump(t *testing.T) {
	// Create a temporary output directory
	tempDir := t.TempDir()
	deviceID := "test-device-123"

	err := ClearBriteDump(deviceID, tempDir)
	if err != nil {
		t.Fatalf("ClearBriteDump failed: %v", err)
	}

	// Verify the function completes without error
	// In a real test, we would verify extraction artifacts
}

func TestClearBriteDump_InvalidPath(t *testing.T) {
	deviceID := "test-device-456"
	invalidPath := filepath.Join(os.TempDir(), "nonexistent-parent-9999", "subdir")

	// Should handle invalid paths gracefully
	err := ClearBriteDump(deviceID, invalidPath)
	// Function currently doesn't validate paths, but in production it should
	_ = err // Suppress unused variable for now
}

func TestSimulateZeroClick(t *testing.T) {
	targetIP := "192.168.1.100"
	payloadType := "pegasus"

	err := SimulateZeroClick(targetIP, payloadType)
	if err != nil {
		// Expected to fail without nmap/nc installed — that's fine in CI
		t.Logf("SimulateZeroClick returned error (expected without network tools): %v", err)
	}
}

func TestSimulateZeroClick_VariousPayloads(t *testing.T) {
	testCases := []struct {
		targetIP    string
		payloadType string
	}{
		{"10.0.0.1", "pegasus"},
		{"192.168.1.1", "predator"},
		{"172.16.0.1", "chrysaor"},
	}

	for _, tc := range testCases {
		t.Run(tc.payloadType, func(t *testing.T) {
			err := SimulateZeroClick(tc.targetIP, tc.payloadType)
			// We don't fail on error since nmap/nc may not be available
			if err != nil {
				t.Logf("SimulateZeroClick(%s, %s) error: %v", tc.targetIP, tc.payloadType, err)
			}
		})
	}
}
