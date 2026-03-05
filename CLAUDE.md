# CertStrike

## Overview
CertStrike is a next-generation PKI, certificate, and mobile attack framework with integrated C2 capabilities. It provides Active Directory Certificate Services (ADCS) exploitation, mobile forensic extraction, and command-and-control infrastructure.

## Architecture
- `cmd/certstrike/` — CLI entry points (cobra commands)
- `pkg/pki/` — ADCS enumeration, ESC exploitation, certificate forging
- `pkg/c2/` — HTTP/HTTPS C2 listener with session management, cert-auth implants
- `pkg/mobile/` — ADB-based mobile extraction (ClearBrite) and zero-click simulation
- `internal/mcp/` — MCP stdio server (6 tools)
- `internal/tui/` — Bubbletea operator console
- `implants/smartpotato/` — Windows privilege escalation implant

## Build
```bash
CGO_ENABLED=0 go build ./...
```

## Features

### PKI / ADCS
- **Native LDAP enumeration** — connects to DC LDAP port 389/636, no ldapsearch binary needed
- **ESC1-ESC4 vulnerability scoring** — automatic detection and prioritization
- **ESC1 exploitation** — forge certificates with arbitrary UPN via vulnerable templates
- **ESC4 exploitation** — modify template ACLs then exploit as ESC1, auto-restore
- **Attack chain auto-detection** — enumerate, score, generate prioritized attack paths
- **Golden certificate forging** — ECDSA certificates with UPN SAN for smart card auth

### C2 Framework
- HTTP/HTTPS listeners with auto-generated TLS certificates
- Session management (register, poll, command queue, result collection)
- **Certificate persistence** — cert-auth implants using forged certificates (Schannel mTLS)
- Stager configuration generation

### Mobile
- ClearBrite forensic extraction via ADB (device info, packages, network, filesystem, media)
- Zero-click simulation (Pegasus, Predator, Chrysaor attack chains)

### MCP Server
Tools: `pki_enumerate`, `pki_forge`, `c2_list_sessions`, `c2_queue_command`, `c2_get_results`, `mobile_extract`

### Operator Console (TUI)
Bubbletea-based console with views: Sessions, Commands, Listeners, Implants

## Key Commands
```bash
certstrike pki --enum --target-dc dc01.corp.local --domain corp.local
certstrike pki --forge --upn admin@corp.local
certstrike pki --exploit esc1 --template VulnTemplate --upn admin@domain.com
certstrike pki --exploit esc4 --template WritableTemplate --upn admin@domain.com
certstrike pki --auto-detect --target-dc dc01.corp.local --domain corp.local
certstrike c2 --port 8443 --protocol https
certstrike c2 --implant-type cert-auth --upn admin@corp.local --c2-url https://c2:8443
certstrike console
certstrike mcp
certstrike mobile --extract --device-id emulator-5554
```

## Dependencies
- github.com/spf13/cobra — CLI framework
- github.com/go-ldap/ldap/v3 — Native LDAP client (pure Go, no CGO)
- github.com/charmbracelet/bubbletea — TUI framework
- github.com/charmbracelet/lipgloss — TUI styling
- github.com/charmbracelet/bubbles — TUI components
