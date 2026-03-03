package c2

import (
	"fmt"
	"net/http"
)

// Listener configuration
type Listener struct {
	BindAddress string
	Port        int
	Protocol    string
	Running     bool
}

// Start spawns a generic HTTP/HTTPS C2 receiver on par with Sliver.
func (l *Listener) Start() error {
	l.Running = true
	fmt.Printf("[+] Bringing up C2 %s Listener on %s:%d...\n", l.Protocol, l.BindAddress, l.Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		// Mock implant checkin
		w.WriteHeader(200)
		fmt.Fprintf(w, "Command queued")
	})

	addr := fmt.Sprintf("%s:%d", l.BindAddress, l.Port)
	if l.Protocol == "https" {
		// In production this would require certstrike PKI certs.
		// return http.ListenAndServeTLS(addr, "cert.pem", "key.pem", mux)
	}

	go http.ListenAndServe(addr, mux)
	return nil
}
