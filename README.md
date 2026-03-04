# CertStrike

**Next-Gen PKI, Certificate, and Mobile Attack Framework**

CertStrike is a robust, all-in-one exploitation framework specifically targeting certificate-based authentication mechanisms (PKI, Smart Cards, JWTs, mutual TLS) and mobile device extractions/C2. 

## Features

### 1. Certificate / PKI Attack Toolkit
- Active directory CS (ADCS) enumeration and exploitation (ESC1-ESC11 equivalents).
- Certificate forging and golden certificate attacks.
- Smart Card / PIV cloning and manipulation.
- mTLS interception and proxying.
- Certificate transparency log correlation for exposed assets.

### 2. Mobile Device Exploitation & Extraction
- **ClearBrite:** Forensic-grade logical and physical device extraction (Android/iOS).
- **Pegasus-like zero-click simulation:** Remote exploitation vector testing.
- **C2 Integration:** A robust C2 framework on par with Sliver, featuring multi-OS support (Linux, Windows, Android, iOS), highly obfuscated stagers, and seamless integration with the "Hog" ecosystem.

## Architecture
- `cmd/certstrike`: The primary CLI and C2 server entrypoint.
- `pkg/pki`: Core PKI, ASN.1, and X.509 manipulation libraries.
- `pkg/mobile`: Mobile device abstraction, ADB/iOS bridging, and forensic dumping.
- `pkg/c2`: The C2 listener, routing, and implant generation logic.
- `implants/`: Highly obfuscated "potato" variations and native mobile implants.

## Building

### Using Make (Recommended)

```bash
# Build main CLI
make build

# Build SmartPotato implant
make smartpotato

# Run tests
make test

# Cross-compile for all platforms
make cross-compile

# Build everything and run tests
make all
```

### Manual Build

```bash
go build -o certstrike ./cmd/certstrike
go build -o implants/smartpotato/smartpotato ./implants/smartpotato
```

## Usage

### PKI/Certificate Attacks

```bash
# Enumerate ADCS templates
certstrike pki --target-dc dc01.corp.local --domain corp.local --username user --password pass --enum

# Forge a golden certificate
certstrike pki --forge --upn administrator@corp.local --ca-key ca-key.pem --output admin-cert.pem
```

### Mobile Extraction

```bash
# ClearBrite forensic extraction
certstrike mobile --device-id emulator-5554 --extract --output-dir ./extraction

# Zero-click simulation
certstrike mobile --zero-click --target-ip 192.168.1.100 --payload-type pegasus
```

### C2 Operations

```bash
# Start HTTP listener
certstrike c2 --bind 0.0.0.0 --port 8080 --protocol http

# Start HTTPS listener with certs
certstrike c2 --bind 0.0.0.0 --port 8443 --protocol https --cert server.crt --key server.key

# Generate stager configuration
certstrike c2 --generate-stager --output stager.json
```

### SmartPotato Implant

```bash
# Run with auto-detection
./smartpotato auto

# Specific technique
./smartpotato juicy
./smartpotato rogue
```

## Development

### Project Structure

```
certstrike/
├── cmd/certstrike/          # CLI entry point and subcommands
│   ├── main.go              # Root cobra command
│   ├── pki.go               # PKI subcommand
│   ├── mobile.go            # Mobile subcommand
│   └── c2.go                # C2 subcommand
├── pkg/
│   ├── pki/                 # PKI/ADCS implementation
│   │   ├── adcs.go          # Template enumeration, cert forging
│   │   └── adcs_test.go
│   ├── mobile/              # Mobile device ops
│   │   ├── clearbrite.go    # ADB extraction, zero-click sim
│   │   └── clearbrite_test.go
│   └── c2/                  # C2 server
│       ├── listener.go      # HTTP/HTTPS listener, session mgmt
│       └── listener_test.go
├── implants/
│   └── smartpotato/         # Windows privilege escalation implant
│       └── main.go          # RC4 decrypt, AMSI/ETW bypass, potato techniques
├── scripts/                 # Build and test automation
│   ├── build.sh
│   └── test.sh
├── Makefile                 # Build targets
└── .gitignore
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Generate coverage report
./scripts/test.sh
```

## Security Notice

This tool is designed for authorized security testing and research only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

## License

MIT
