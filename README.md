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

```bash
go build -o certstrike cmd/certstrike/main.go
```
