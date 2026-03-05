package c2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListener_StructFields(t *testing.T) {
	listener := &Listener{
		BindAddress: "127.0.0.1",
		Port:        8888,
		Protocol:    "http",
		CertFile:    "/path/to/cert.pem",
		KeyFile:     "/path/to/key.pem",
		Running:     false,
	}

	if listener.BindAddress != "127.0.0.1" {
		t.Errorf("Expected BindAddress '127.0.0.1', got %s", listener.BindAddress)
	}
	if listener.Port != 8888 {
		t.Errorf("Expected Port 8888, got %d", listener.Port)
	}
	if listener.Protocol != "http" {
		t.Errorf("Expected Protocol 'http', got %s", listener.Protocol)
	}
	if listener.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected CertFile path, got %s", listener.CertFile)
	}
	if listener.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected KeyFile path, got %s", listener.KeyFile)
	}
}

func TestListener_HandleCheckin(t *testing.T) {
	listener := &Listener{
		BindAddress: "127.0.0.1",
		Port:        0,
		Protocol:    "http",
	}
	listener.sessions = make(map[string]*ImplantSession)
	listener.commands = make(map[string][]QueuedCommand)

	// Test new session registration
	body := `{"hostname":"WORKSTATION","username":"admin","os":"windows","arch":"amd64","pid":1234}`
	req := httptest.NewRequest(http.MethodPost, "/connect", strings.NewReader(body))
	w := httptest.NewRecorder()

	listener.handleCheckin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var resp CheckinResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.SessionID == "" {
		t.Error("Expected non-empty session ID")
	}
	if resp.Interval != 5 {
		t.Errorf("Expected interval 5, got %d", resp.Interval)
	}

	// Verify session was stored
	if len(listener.sessions) != 1 {
		t.Errorf("Expected 1 session, got %d", len(listener.sessions))
	}

	// Test existing session checkin
	body2 := `{"session_id":"` + resp.SessionID + `","hostname":"WORKSTATION","username":"admin","os":"windows","arch":"amd64","pid":1234}`
	req2 := httptest.NewRequest(http.MethodPost, "/connect", strings.NewReader(body2))
	w2 := httptest.NewRecorder()

	listener.handleCheckin(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Expected status 200 on re-checkin, got %d", w2.Code)
	}

	// Should still be 1 session (not a new one)
	if len(listener.sessions) != 1 {
		t.Errorf("Expected 1 session after re-checkin, got %d", len(listener.sessions))
	}
}

func TestListener_HandleCheckin_MethodNotAllowed(t *testing.T) {
	listener := &Listener{}
	listener.sessions = make(map[string]*ImplantSession)
	listener.commands = make(map[string][]QueuedCommand)

	req := httptest.NewRequest(http.MethodGet, "/connect", nil)
	w := httptest.NewRecorder()

	listener.handleCheckin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestListener_HandleListSessions(t *testing.T) {
	listener := &Listener{}
	listener.sessions = make(map[string]*ImplantSession)
	listener.commands = make(map[string][]QueuedCommand)

	// Add a test session
	listener.sessions["test-session-id-1234"] = &ImplantSession{
		ID:       "test-session-id-1234",
		Hostname: "WORKSTATION",
		Username: "admin",
		OS:       "windows",
		Arch:     "amd64",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	w := httptest.NewRecorder()

	listener.handleListSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var sessions []*ImplantSession
	if err := json.Unmarshal(w.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("Failed to parse sessions: %v", err)
	}

	if len(sessions) != 1 {
		t.Errorf("Expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Hostname != "WORKSTATION" {
		t.Errorf("Expected hostname 'WORKSTATION', got %s", sessions[0].Hostname)
	}
}

func TestListener_HandleQueueCommand(t *testing.T) {
	listener := &Listener{}
	listener.sessions = make(map[string]*ImplantSession)
	listener.commands = make(map[string][]QueuedCommand)

	sessionID := "abcdef0123456789abcdef0123456789"
	listener.sessions[sessionID] = &ImplantSession{
		ID:       sessionID,
		Hostname: "TARGET",
	}

	body := `{"session_id":"` + sessionID + `","command":"whoami","args":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/command", strings.NewReader(body))
	w := httptest.NewRecorder()

	listener.handleQueueCommand(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	// Verify command was queued
	if len(listener.commands[sessionID]) != 1 {
		t.Errorf("Expected 1 queued command, got %d", len(listener.commands[sessionID]))
	}
	if listener.commands[sessionID][0].Command != "whoami" {
		t.Errorf("Expected command 'whoami', got %s", listener.commands[sessionID][0].Command)
	}
}

func TestListener_HandleQueueCommand_SessionNotFound(t *testing.T) {
	listener := &Listener{}
	listener.sessions = make(map[string]*ImplantSession)
	listener.commands = make(map[string][]QueuedCommand)

	body := `{"session_id":"nonexistent","command":"whoami"}`
	req := httptest.NewRequest(http.MethodPost, "/api/command", strings.NewReader(body))
	w := httptest.NewRecorder()

	listener.handleQueueCommand(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestGenerateStagerConfig(t *testing.T) {
	stager := GenerateStagerConfig("https://c2.example.com:8443")

	if stager.C2URL != "https://c2.example.com:8443" {
		t.Errorf("Expected C2URL, got %s", stager.C2URL)
	}
	if stager.ID == "" {
		t.Error("Expected non-empty stager ID")
	}
	if stager.Interval != 5 {
		t.Errorf("Expected interval 5, got %d", stager.Interval)
	}
	if stager.Jitter != 20 {
		t.Errorf("Expected jitter 20, got %d", stager.Jitter)
	}
	if stager.Protocol != "https" {
		t.Errorf("Expected protocol 'https', got %s", stager.Protocol)
	}
}

func TestListener_SessionCount(t *testing.T) {
	listener := &Listener{}
	listener.sessions = make(map[string]*ImplantSession)

	if listener.sessionCount() != 0 {
		t.Errorf("Expected 0 sessions, got %d", listener.sessionCount())
	}

	listener.sessions["a"] = &ImplantSession{ID: "a"}
	listener.sessions["b"] = &ImplantSession{ID: "b"}

	if listener.sessionCount() != 2 {
		t.Errorf("Expected 2 sessions, got %d", listener.sessionCount())
	}
}
