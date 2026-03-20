<div align="center">

# 🐰 BugzBunny

### Hop. Hunt. Hack.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)
![FastAPI](https://img.shields.io/badge/FastAPI-REST_API-009688?style=for-the-badge&logo=fastapi)
![Nuclei](https://img.shields.io/badge/Nuclei-Enabled-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.1.0-orange?style=for-the-badge)

**BugzBunny is a modular, async offensive security intelligence platform built for bug bounty hunters and penetration testers. It automates the entire recon-to-report pipeline with 16+ security modules, adaptive scan modes, a custom risk correlation engine, attack chain detection, REST API, Docker support, structured JSON telemetry, and professional PDF reports.**

</div>

---

## ✨ Features

| Module | Tool | Description |
|--------|------|-------------|
| 🔍 Subdomain Enumeration | `subfinder` | Passive subdomain discovery |
| 🌐 Live Host Detection | `curl` | Filter alive hosts |
| 🔌 Port Scanning | `nmap` | Detect open ports & services |
| 📁 Directory Fuzzing | `ffuf` | Brute force hidden paths |
| 🧬 Tech Fingerprinting | `whatweb` | Identify tech stack |
| 🛡️ WAF Detection | `wafw00f` | Detect web application firewalls |
| 🎯 Subdomain Takeover | `subjack` | Find takeover vulnerabilities |
| ⚠️ Vulnerability Scanning | `nuclei` | Detect CVEs & misconfigs |
| 🔎 CVE Lookup | `NVD API` | Map services to known CVEs |
| 🔐 JS Secrets | `custom` | Entropy-based secret detection |
| 🌍 CORS Check | `custom` | Detect CORS misconfigurations |
| 🎲 Risk Engine | `custom` | CVSS-style attack chain scoring |
| 🔗 Attack Chains | `custom` | Multi-step exploitable path detection |
| 📊 HTML Report | `jinja2` | Dark-themed HTML report |
| 📄 PDF Report | `weasyprint` | Professional A4 PDF report |
| 🗄️ Database | `SQLite` | 10-table normalized storage |
| 🔄 Diff Reports | `custom` | Track changes between scans |
| ⚡ Async Scanning | `asyncio` | Parallel execution (10x faster) |
| 🌐 REST API | `FastAPI` | Programmatic control + Swagger UI |
| 🐳 Docker | `docker` | Containerized deployment |
| 📋 Structured Logging | `custom` | JSON telemetry per module |
| 🎛️ Scan Modes | `custom` | Passive / Stealth / Active / Aggressive |

---

## 🎛️ Scan Modes

BugzBunny supports 4 adaptive scan modes — every module adjusts its behavior accordingly:
```bash
python main.py scan --target hackerone.com --mode passive
python main.py scan --target hackerone.com --mode stealth
python main.py scan --target hackerone.com --mode active       # default
python main.py scan --target hackerone.com --mode aggressive
```

| Module | passive | stealth | active | aggressive |
|--------|---------|---------|--------|------------|
| subfinder | passive sources | slow | default | `-all` sources |
| livehosts | https+http | https only | https+http | fast timeouts |
| nmap | ❌ skip | `-T2` slow | `-T4 -F` | `-p- -sV` full |
| ffuf | ❌ skip | ❌ skip | 50 threads | 100 threads |
| whatweb | `-a1` | `-a1` | `-a1` | `-a3` |
| wafw00f | ❌ skip | slow | normal | normal |
| subjack | ❌ skip | 5 threads | 20 threads | 50 threads |
| js_secrets | ❌ skip | critical only | crit+high | crit+high+med |
| cors | ❌ skip | 1 origin | 3 origins | 5 origins |
| nuclei | ❌ skip | crit+high | all | all+cves |
| cve_lookup | 3 techs | 5 techs | 10 techs | 20 techs |

---

## 🧠 Intelligence Layer

BugzBunny is not just a tool wrapper — it has a custom intelligence layer:

### Risk Correlation Engine
```
Findings from 16 modules → Normalized Schema → Risk Engine → Attack Chains

Risk Score Formula:
  base  = avg(severity_weight × confidence)
  mods  = no_waf(+2.0) | has_secret(+3.0) | cors_creds(+3.5)
          known_cve(+2.5) | waf_present(-2.0)
  score = clamp(base + mods, 0.0, 10.0)
```

### Attack Chain Detection
```
Port → Technology → CVE → No WAF = EXPLOITABLE PATH

AttackPath {
  steps:       ["open_port:443", "tech:nginx", "cve:CVE-2021-44224", "no_waf"]
  severity:    "critical"
  impact:      "Unprotected host with known RCE vulnerability"
  exploitable: true
}
```

### JS Secret Detection Engine
```
Pattern Match → Shannon Entropy Check → False Positive Filter → Confidence Score
entropy < 2.0  →  rejected (placeholder)
entropy > 4.0  →  confidence boosted
13 pattern types: AWS, GitHub, Stripe, JWT, Slack, SendGrid, Private Keys...
```

### Structured Telemetry
```json
{"ts": "2026-03-20T12:01:38", "scan_id": "3b0d606f",
 "module": "portscan", "level": "METRIC",
 "event": "module_complete",
 "data": {"duration_ms": 1240, "findings_count": 5}}
```

---

## 🚀 Installation

### Prerequisites
```bash
sudo apt install subfinder nmap ffuf whatweb wafw00f subjack nuclei -y
nuclei -update-templates
```

### Local Setup
```bash
git clone https://github.com/JOYDALAL7/BugzBunny.git
cd BugzBunny
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Docker Setup
```bash
docker-compose up -d
```

---

## 🔧 Usage

### CLI
```bash
# Activate venv
source venv/bin/activate

# Default active scan
python main.py scan --target hackerone.com

# With scan mode
python main.py scan --target hackerone.com --mode stealth
python main.py scan --target hackerone.com --mode aggressive

# Custom output directory
python main.py scan --target hackerone.com --output /tmp/results
```

### REST API
```bash
# Start API server
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Start a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "hackerone.com"}'

# Check scan status
curl http://localhost:8000/scans

# View Swagger UI
open http://localhost:8000/docs
```

---

## ⚡ Async Pipeline
```
Phase 1    →  Subdomain Enumeration (subfinder)
Phase 2    →  Live Host Detection (curl)
Phase 3    →  ┌──────────────────────────────────────┐
               │ Port Scanning    (nmap)               │
               │ Directory Fuzzing (ffuf)              │
               │ Tech Fingerprint  (whatweb)           │  ← Parallel
               │ WAF Detection     (wafw00f)           │
               │ Subdomain Takeover (subjack)          │
               │ JS Secrets        (custom engine)     │
               │ CORS Check        (custom)            │
               └──────────────────────────────────────┘
Phase 4    →  ┌──────────────────────────────────────┐
               │ Nuclei Vuln Scan                      │  ← Parallel
               │ CVE Lookup (NVD API)                  │
               └──────────────────────────────────────┘
Phase 4.5  →  Risk Correlation + Attack Chain Engine
Phase 5    →  Database + Diff + HTML + PDF Reports
```

---

## 📁 Output Structure
```
reports/
└── target.com/
    ├── target.com_report.html    ← Dark-themed HTML report
    ├── target.com_report.pdf     ← Professional A4 PDF report
    ├── bugzbunny.db              ← SQLite database (10 tables)
    ├── diff_report.json          ← Changes since last scan
    ├── previous_scan.json        ← Baseline for diff
    ├── logs/
    │   └── <scan_id>.log         ← Structured JSON telemetry
    ├── raw/
    │   ├── subdomains.json
    │   ├── livehosts.json
    │   ├── ports.json
    │   ├── fingerprint.json
    │   ├── waf.json
    │   ├── takeover.json
    │   ├── vulnerabilities.json
    │   ├── cves.json
    │   ├── js_secrets.json
    │   ├── cors.json
    │   ├── risk_chains.json       ← Attack chains + exploitable paths
    │   └── fuzzing/
    │       └── fuzzing_summary.json
    └── temp/
```

---

## 🌐 REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Tool info |
| POST | `/scan` | Start a new scan |
| GET | `/scans` | List all scans |
| GET | `/scan/{id}` | Get scan status |
| GET | `/scan/{id}/report` | Get HTML report |
| DELETE | `/scan/{id}` | Delete scan |

---

## 🐳 Docker
```bash
# Build image
docker build -t bugzbunny .

# Run with docker-compose
docker-compose up -d

# API available at
http://localhost:8001/docs
```

---

## 🗄️ Database Schema
```
Scan       → id, target, started_at, finished_at, status
Finding    → id, scan_id, module, type, title, description, data
Target     → id, domain, first_seen, last_seen
Host       → id, scan_id, target_id, url, ip, status_code
Port       → id, host_id, number, protocol, service
Technology → id, host_id, name, version, confidence
WAFResult  → id, host_id, detected, waf_name
Secret     → id, host_id, secret_type, match, severity
CORSResult → id, host_id, origin, acao, credentials
RiskChain  → id, scan_id, host_id, risk_score, title
```

---

## ⚠️ Legal Disclaimer

> BugzBunny is intended for **authorized security testing only**.
> The author is not responsible for any misuse or damage caused by this tool.
> Always obtain proper written permission before testing any target.
> Only test targets listed on HackerOne, Bugcrowd or Intigriti programs.

---

## 👨‍💻 Author

**Joy Dalal** — [@JOYDALAL7](https://github.com/JOYDALAL7)

---

## 📄 License

MIT License

---

<div align="center">
Made with ❤️ by Joy Dalal | Hop. Hunt. Hack. 🐰
</div>
