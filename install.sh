#!/bin/bash
set -e

echo "[*] Building CertStrike..."
CGO_ENABLED=0 go build -o certstrike ./cmd/certstrike
echo "[+] Built: ./certstrike"

if [ "$1" = "--install" ]; then
    sudo cp certstrike /usr/local/bin/certstrike
    echo "[+] Installed to /usr/local/bin/certstrike"
fi
