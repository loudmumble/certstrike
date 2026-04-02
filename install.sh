#!/bin/bash
set -e

echo "[*] Removing old binary..."
sudo rm -f /usr/local/bin/certstrike

echo "[*] Building CertStrike..."
CGO_ENABLED=0 go build -o certstrike ./cmd/certstrike
echo "[+] Built: ./certstrike"

echo "[*] Installing..."
sudo cp certstrike /usr/local/bin/
echo "[+] Installed to /usr/local/bin/certstrike"
