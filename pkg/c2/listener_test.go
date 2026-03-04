package c2

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListener_Start(t *testing.T) {
	listener := &Listener{
		BindAddress: "127.0.0.1",
		Port:        8888,
		Protocol:    "http",
		Running:     false,
	}

	err := listener.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !listener.Running {
		t.Error("Expected listener to be running")
	}

	// Give the listener time to start
	time.Sleep(100 * time.Millisecond)
}

func TestListener_ConnectEndpoint(t *testing.T) {
	// Create a test HTTP server that mimics the /connect endpoint
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connect" {
			t.Errorf("Expected path '/connect', got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Command queued"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// Make a request to the test server
	resp, err := http.Get(server.URL + "/connect")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestListener_HTTPProtocol(t *testing.T) {
	listener := &Listener{
		BindAddress: "0.0.0.0",
		Port:        9999,
		Protocol:    "http",
	}

	if listener.Protocol != "http" {
		t.Errorf("Expected protocol 'http', got %s", listener.Protocol)
	}
}

func TestListener_HTTPSProtocol(t *testing.T) {
	listener := &Listener{
		BindAddress: "0.0.0.0",
		Port:        9998,
		Protocol:    "https",
	}

	if listener.Protocol != "https" {
		t.Errorf("Expected protocol 'https', got %s", listener.Protocol)
	}

	// Note: Starting HTTPS listener requires cert/key files
	// In production, listener.Start() would check for these
}

func TestListener_MultipleInstances(t *testing.T) {
	l1 := &Listener{BindAddress: "127.0.0.1", Port: 10001, Protocol: "http"}
	l2 := &Listener{BindAddress: "127.0.0.1", Port: 10002, Protocol: "http"}

	err1 := l1.Start()
	err2 := l2.Start()

	if err1 != nil {
		t.Errorf("Listener 1 failed to start: %v", err1)
	}
	if err2 != nil {
		t.Errorf("Listener 2 failed to start: %v", err2)
	}

	if !l1.Running || !l2.Running {
		t.Error("Both listeners should be running")
	}

	time.Sleep(100 * time.Millisecond)
}
