🛡️ XPRO – APEX SENTINEL  
Autonomous Cyber-Intelligence Unit | High-Performance Security Auditing Framework

🚀 QUICK START

One-Command Installation (Auto installs missing system + Python packages)
```bash
git clone https://github.com/Irfan430/XPRO.git
cd XPRO
chmod +x install.sh
./install.sh
source venv/bin/activate
python xpro.py

Direct Execution

python3 xpro.py

📖 USAGE

Basic Scanning

# Interactive mode
python3 xpro.py

# Network scan
python3 xpro.py --target 192.168.1.0/24

# Web audit
python3 xpro.py --url https://target.com --web-deep

Advanced Operations

# Enterprise scan with report
python3 xpro.py --target targets.txt --threads 64 --report all

# Compliance audit
python3 xpro.py --target 10.0.0.0/8 --compliance pci-dss

🏗️ ARCHITECTURE

XPRO ENGINE
├── High-Velocity Scanner
│   ├── Auto-thread scaling
│   ├── Parallel execution
│   └── Resource management
├── Security Modules
│   ├── Asset Discovery (Nmap)
│   ├── Web Testing
│   ├── Auth Testing
│   └── Infrastructure Audit
├── Tactical Intelligence
│   ├── CVSS Scoring
│   ├── Impact Analysis
│   └── Remediation Hints
└── Reporting Engine
├── HTML / PDF / JSON
└── Executive Summary

📊 REPORTING
XPRO_REPORTS/
├── YYYY-MM-DD_scan.html
├── YYYY-MM-DD_summary.pdf
└── YYYY-MM-DD_remediation.md

⚙️ CONFIGURATION (config.yaml)

performance:
  max_threads: 64
  timeout: 30
scanning:
  nmap_timing: 4
  port_range: "1-10000"
reporting:
  auto_generate: true
  formats: ["html", "pdf"]

🔄 UPDATE & MAINTENANCE

python3 xpro.py --update
python3 xpro.py --clean-reports --days 30

⚠️ LEGAL
XPRO is for authorized security testing only.
Unauthorized use is illegal.
License: GNU AGPL v3.0

