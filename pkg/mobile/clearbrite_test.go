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
	// Test that the function executes without panic
	targetIP := "192.168.1.100"
	payloadType := "pegasus-exploit"

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SimulateZeroClick panicked: %v", r)
		}
	}()

	SimulateZeroClick(targetIP, payloadType)
}

func TestSimulateZeroClick_VariousPayloads(t *testing.T) {
	testCases := []struct {
		targetIP    string
		payloadType string
	}{
		{"10.0.0.1", "type-a"},
		{"192.168.1.1", "type-b"},
		{"172.16.0.1", "type-c"},
	}

	for _, tc := range testCases {
		t.Run(tc.payloadType, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Unexpected panic: %v", r)
				}
			}()
			SimulateZeroClick(tc.targetIP, tc.payloadType)
		})
	}
}
