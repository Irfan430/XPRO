#!/bin/bash

set -e

echo "==============================="
echo " XPRO Auto Installer"
echo "==============================="

# ---------- OS CHECK ----------
if ! command -v apt >/dev/null 2>&1; then
    echo "[!] apt package manager not found"
    exit 1
fi

# ---------- SYSTEM TOOLS ----------
SYSTEM_TOOLS=(
    nmap
    python3
    python3-pip
    python3-venv
    git
)

echo "[+] Updating system..."
sudo apt update

echo "[+] Checking system tools..."
for tool in "${SYSTEM_TOOLS[@]}"; do
    if ! command -v $tool >/dev/null 2>&1; then
        echo "[!] Missing: $tool → installing"
        sudo apt install -y $tool
    else
        echo "[✓] $tool already installed"
    fi
done

# ---------- VENV ----------
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

# ---------- PIP ----------
echo "[+] Upgrading pip..."
pip install --upgrade pip

# ---------- PYTHON REQUIREMENTS ----------
if [ ! -f "requirements.txt" ]; then
    echo "[!] requirements.txt not found"
    exit 1
fi

echo "[+] Installing Python requirements..."
pip install -r requirements.txt

# ---------- PYTHON MODULE CHECK ----------
PY_MODULES=(
    rich
    scapy
    nmap
    requests
    bs4
    pyfiglet
    psutil
    pandas
    paramiko
    smb
    dns
    whois
    jwt
    Crypto
    openpyxl
    colorama
    termcolor
    jinja2
    markdown
    reportlab
    selenium
    lxml
    urllib3
    aiohttp
)

echo "[+] Verifying Python modules..."
for module in "${PY_MODULES[@]}"; do
    python - <<EOF
try:
    __import__("$module")
except ImportError:
    print("[!] Missing Python module: $module")
    exit(1)
EOF
done

echo "==============================="
echo " ✓ XPRO installation complete"
echo " Activate with: source venv/bin/activate"
echo " Run with: python xpro.py"
echo "==============================="
