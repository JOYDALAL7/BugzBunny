<div align="center">

# 🐰 BugzBunny

### Hop. Hunt. Hack.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)
![FastAPI](https://img.shields.io/badge/FastAPI-REST_API-009688?style=for-the-badge&logo=fastapi)
![Nuclei](https://img.shields.io/badge/Nuclei-Enabled-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-orange?style=for-the-badge)

**BugzBunny is a modular, async offensive security automation framework built for bug bounty hunters and penetration testers. It automates the entire recon-to-report pipeline with 16+ security modules, REST API, Docker support, async parallel scanning, and beautiful HTML reports.**

</div>

---

## ✨ Features

| Module | Tool | Description |
|--------|------|-------------|
| 🔍 Subdomain Enumeration | `subfinder` | Discover subdomains passively |
| 🌐 Live Host Detection | `curl` | Filter alive hosts |
| 🔌 Port Scanning | `nmap` | Detect open ports & services |
| 📁 Directory Fuzzing | `ffuf` | Brute force hidden paths |
| 🧬 Tech Fingerprinting | `whatweb` | Identify tech stack |
| 🛡️ WAF Detection | `wafw00f` | Detect web application firewalls |
| 🎯 Subdomain Takeover | `subjack` | Find takeover vulnerabilities |
| ⚠️ Vulnerability Scanning | `nuclei` | Detect CVEs & misconfigs |
| 🔎 CVE Lookup | `NVD API` | Map services to known CVEs |
| 🔐 JS Secrets | `custom` | Extract API keys & tokens from JS files |
| 🌍 CORS Check | `custom` | Detect CORS misconfigurations |
| 📊 HTML Reporting | `jinja2` | Beautiful dark-themed reports |
| 🗄️ Database Storage | `SQLite` | Persist scan history |
| 🔄 Diff Reports | `custom` | Track new findings between scans |
| ⚡ Async Scanning | `asyncio` | Parallel module execution (10x faster) |
| 🌐 REST API | `FastAPI` | Programmatic scan control + Swagger UI |
| 🐳 Docker | `docker` | Containerized deployment |

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
# Basic scan
python main.py scan --target hackerone.com

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
Phase 1  →  Subdomain Enumeration (subfinder)
Phase 2  →  Live Host Detection (curl)
Phase 3  →  ┌─────────────────────────────────┐
             │ Port Scanning    (nmap)          │
             │ Directory Fuzzing (ffuf)         │
             │ Tech Fingerprint (whatweb)       │  ← Parallel
             │ WAF Detection    (wafw00f)       │
             │ Subdomain Takeover (subjack)     │
             │ JS Secrets       (custom)        │
             │ CORS Check       (custom)        │
             └─────────────────────────────────┘
Phase 4  →  ┌─────────────────────────────────┐
             │ Nuclei Vuln Scan                 │  ← Parallel
             │ CVE Lookup (NVD API)             │
             └─────────────────────────────────┘
Phase 5  →  Database Storage (SQLite)
Phase 6  →  Diff Report (new findings)
Phase 7  →  HTML Report Generation
```

---

## 📁 Output Structure
```
reports/
└── target.com/
    ├── target.com_report.html    ← HTML report
    ├── bugzbunny.db              ← SQLite database
    ├── diff_report.json          ← Changes since last scan
    ├── previous_scan.json        ← Baseline for diff
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
    │   └── fuzzing/
    │       ├── fuzzing_summary.json
    │       └── ffuf_*.json
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
Scan    → id, target, started_at, finished_at, status
Finding → id, scan_id, module, type, title, description, data
```

---

## 📸 Report Preview

> Dark-themed HTML report with stats dashboard, subdomains, open ports,
> WAF info, vulnerabilities, CVEs, JS secrets and CORS issues.

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

This project is licensed under the MIT License.

---

<div align="center">
</div>
