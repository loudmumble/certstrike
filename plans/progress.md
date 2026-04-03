# Ralph Progress Log

Started: 2026-04-03
Task: Verify all certstrike follow-up command and key generation fixes

## Codebase Patterns

- Pure Go, CGO_ENABLED=0 — no cgo dependencies
- PKI exploit functions return (cert, key, error) where key is crypto.Signer
- Follow-up commands printed by individual ESC exploit functions AND pkinit.go/unpac.go
- Autopwn orchestrates enumeration → candidate scoring → exploitation loop
- C2 and shadow credentials use ECDSA intentionally (not for AD auth)

## Key Files

- `pkg/pki/enroll.go` — Certificate enrollment, key generation, CSR
- `pkg/pki/adcs.go` — ForgeCertificate, WriteCertKeyPEM, WritePFX, ExploitESC1/4
- `pkg/pki/autopwn.go` — AutoPwn orchestration, candidate building
- `pkg/pki/pkinit.go` — PKINIT follow-up command output
- `pkg/pki/unpac.go` — UnPAC-the-hash follow-up command output
- `pkg/pki/esc{2,3,6,7,9,13}.go` — Individual ESC exploit functions
- `cmd/certstrike/pki.go` — CLI command handler for --esc and enum output
- `cmd/certstrike/autopwn.go` — CLI command handler for auto

---

## 2026-04-03 - Initial Session

### Changes Applied

1. **RSA 2048 keys** — switched all PKI exploit paths from ECDSA P256 to RSA 2048
2. **crypto.Signer** — all exploit function return types changed from *ecdsa.PrivateKey
3. **certipy-ad** — all follow-up commands now use certipy-ad (not certipy)
4. **PKINITtools** — replaced getTGT.py -pfx with gettgtpkinit.py -cert-pfx
5. **DC_IP placeholder** — all -dc-ip args use <DC_IP> placeholder (not hostname)
6. **Duplicate output** — removed second PKINIT/UnPAC print from cmd handler
7. **Self-signed skip** — autopwn skips self-signed certs, tries next candidate
8. **Interactive selection** — added -i flag for path selection in autopwn
9. **ESC12 fix** — enum now shows ntlmrelayx command instead of certstrike

---

## Iteration 1 — V-001 Verified ✓

All 9 acceptance criteria confirmed:
- RSA 2048 in enroll.go (line 72), ForgeCertificate (line 638), ForgeGoldenCertificate (line 768)
- No ecdsa.GenerateKey in PKI paths (enroll.go, adcs.go, mcp/server.go)
- C2 + shadow_credentials correctly retain ECDSA
- WriteCertKeyPEM uses MarshalPKCS8PrivateKey with "PRIVATE KEY" PEM type
- All 8 ExploitESC* functions return crypto.Signer
- TestPFX_RoundTrip asserts *rsa.PrivateKey
- Build + tests pass

## Iteration 2 — V-002 Verified ✓

All 7 acceptance criteria confirmed:
- No bare `certipy auth`/`certipy relay`/`certipy cert` commands in any .go file
- pkinit.go uses certipy-ad throughout (lines 31-32, 42-43, 75-77, 89-90)
- unpac.go uses certipy-ad (lines 20-21)
- All ESC exploit files (esc2, esc3, esc6, esc7, esc9, esc13, adcs.go) use certipy-ad in next steps
- pki.go scan-only handlers use certipy-ad for ESC8 (line 639), ESC11 (line 720), ESC12 (line 658)
- shadow_credentials.go uses certipy-ad (line 161)
- GeneratePKINITScript uses certipy-ad (lines 75-77, 89-90)
- Two generic "certipy" references in adcs.go comments (lines 495, 530) are documentation, not commands
- Build + tests pass

## Iteration 3 — V-003 Verified ✓

All 4 acceptance criteria confirmed:
- No `getTGT.py -pfx` anywhere in .go files (zero matches)
- pkinit.go uses `gettgtpkinit.py -cert-pfx` (lines 37-38, 81-83)
- PKINIT script uses gettgtpkinit.py not getTGT.py (lines 81-83, 89)
- secretsdump.py uses `-dc-ip <DC_IP>` and domain (line 48: `%s/%s@%s` with domain)
- unpac.go also correctly uses gettgtpkinit.py (line 29)
- Build + tests pass
