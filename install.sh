#!/usr/bin/env bash
# install.sh - Automated installer for Orin Forensics Engine

set -e

echo "=== Orin Forensics Engine Installer ==="

# 1. Check if pipx is available
if ! command -v pipx &> /dev/null; then
    echo "[*] pipx is not installed. Attempting to install it..."
    if command -v apt-get &> /dev/null; then
        echo "[*] Running: sudo apt-get update && sudo apt-get install -y pipx"
        sudo apt-get update
        sudo apt-get install -y pipx
    else
        echo "[-] Error: pipx is missing and 'apt-get' was not found."
        echo "[-] Please install pipx manually using your package manager, then re-run this script."
        exit 1
    fi
fi

# 2. Install Orin
if [ "$EUID" -eq 0 ]; then
    echo "[*] Running as root. Installing Orin Forensics Engine globally into the system Python environment..."
    python3 -m pip install . --break-system-packages
else
    # Ensure pipx binary paths are configured in shell profiles
    echo "[*] Ensuring pipx paths are configured..."
    pipx ensurepath

    echo "[*] Installing Orin Forensics Engine locally via pipx..."
    if pipx list | grep -q "orin"; then
        echo "[*] Orin is already installed. Re-installing/upgrading..."
        pipx install --force . --pip-args="--no-build-isolation"
    else
        pipx install . --pip-args="--no-build-isolation"
    fi
fi

echo "========================================"
echo "[+] Installation complete!"
echo "[+] You can now run the 'orin' command in your terminal."
echo "[+] Note: If this is the first time installing pipx, please restart your terminal session to load the updated PATH."
echo "========================================"