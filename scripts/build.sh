#!/bin/bash
set -e

echo "==> Building CertStrike..."
make build

echo ""
echo "==> Building SmartPotato implant..."
make smartpotato

echo ""
echo "==> Build complete!"
echo "    certstrike: $(pwd)/certstrike"
echo "    smartpotato: $(pwd)/implants/smartpotato/smartpotato"
