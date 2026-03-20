<div align="center">

# 🐰 BugzBunny

### Hop. Hunt. Hack.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.1.0-orange?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?style=for-the-badge&logo=fastapi)

*Transforms raw scan data into prioritized, exploitable attack paths using correlation and risk scoring.*

</div>

---

## 📸 Screenshots

### Tool Banner
![Banner](assets/banner.png)

### CLI Execution
![CLI](assets/cli.png)

### Attack Chain Detection (Core Feature)
![Attack Chain](assets/attack_chain.png)

### HTML Report (Dashboard)
![Report](assets/report.png)

### Structured Telemetry Logs
![Logs](assets/logs.png)

---

## Overview

Most recon tools dump raw output. BugzBunny **correlates findings** across modules, scores risk using a CVSS-inspired formula, and surfaces exploitable attack paths with step-by-step chains.

**What makes it different:**
- Adaptive scan modes — every module adjusts behavior based on context
- Custom risk engine that combines port + tech + CVE + WAF into a single exploitability score
- Shannon entropy-based secret detection with false positive filtering
- Structured JSON telemetry with per-module performance metrics
- Normalized relational schema across 10 tables — not a JSON blob

*This shifts the workflow from manual triage → automated security decision-making.*

---

## Example Output

**Raw findings (what other tools give you):**
```
port 443 open
nginx/1.18 detected
CVE-2021-44224 found
no WAF detected
```

**BugzBunny attack chain (what you get):**
```
🔥 api.target.com  |  Risk: 9.2 (CRITICAL)  |  EXPLOITABLE

  Chain:  open_port:443 → tech:nginx/1.18 → cve:CVE-2021-44224 → no_waf
  Impact: Unprotected nginx host with known RCE vulnerability, no WAF
  Action: Immediate patching required
```

---

## Key Capabilities

- **Attack Chain Detection** — connects port → tech → CVE → WAF into exploitable paths
- **CVSS-Style Risk Scoring** — severity × confidence + exploitability modifiers, clamped 0–10
- **Adaptive Scan Modes** — 11 modules adjust rate limits, templates, and coverage per mode
- **Entropy-Based Secret Detection** — 13 pattern types, Shannon entropy validation, false positive filter
- **Normalized Schema** — 10-table SQLite with proper foreign keys, queryable across modules
- **Structured Telemetry** — every module emits JSON logs with duration, findings count, scan ID

---

## Features

| Module | Tool | Description |
|--------|------|-------------|
| 🔍 Subdomain Enumeration | `subfinder` | Passive + active subdomain discovery |
| 🌐 Live Host Detection | `curl` | HTTP/HTTPS host probing |
| 🔌 Port Scanning | `nmap` | Open port and service detection |
| 📁 Directory Fuzzing | `ffuf` | Path brute-forcing with wordlists |
| 🧬 Tech Fingerprinting | `whatweb` | Tech stack identification |
| 🛡️ WAF Detection | `wafw00f` | WAF presence and provider detection |
| 🎯 Subdomain Takeover | `subjack` | Dangling DNS detection |
| ⚠️ Vulnerability Scanning | `nuclei` | Template-based CVE detection |
| 🔎 CVE Lookup | `NVD API` | Service-to-CVE mapping |
| 🔐 JS Secret Detection | `custom` | Entropy-scored API key extraction |
| 🌍 CORS Check | `custom` | Origin reflection and credential leaks |
| 🎲 Risk Engine | `custom` | Attack chain scoring and prioritization |
| 📋 Structured Logging | `custom` | JSON telemetry with correlation IDs |
| 📄 Reports | `jinja2 + weasyprint` | HTML + professional A4 PDF |
| 🌐 REST API | `FastAPI` | Programmatic scan control |
| 🐳 Docker | `docker-compose` | Containerized deployment |

---

## Scan Modes

Every module adapts its behavior — rate limits, templates, and coverage — based on the selected mode.
```bash
python main.py scan --target example.com --mode passive      # recon only, no active scanning
python main.py scan --target example.com --mode stealth      # slow, low-noise
python main.py scan --target example.com --mode active       # full scan, balanced (default)
python main.py scan --target example.com --mode aggressive   # maximum coverage
```

| Module | passive | stealth | active | aggressive |
|--------|:-------:|:-------:|:------:|:----------:|
| nmap | ❌ | `-T2` | `-T4 -F` | `-p- -sV` |
| ffuf | ❌ | ❌ | 50 threads | 100 threads |
| nuclei | ❌ | crit+high | all templates | all + CVEs |
| js_secrets | ❌ | critical | crit+high | crit+high+med |
| cors | ❌ | 1 origin | 3 origins | 5 origins |
| subjack | ❌ | 5 threads | 20 threads | 50 threads |

---

## Intelligence Layer

### Risk Scoring
```
base_score  = avg(severity_weight × confidence)
modifiers   = no_waf(+2.0) | known_cve(+2.5) | has_secret(+3.0) | cors_creds(+3.5)
              waf_present(-2.0) | low_confidence(-1.0)
final_score = clamp(base + modifiers, 0.0, 10.0)
```

### Exploitability Rule
```
exploitable = has_open_port AND (has_cve OR has_secret OR has_cors) AND no_waf
```

### JS Secret Detection
```
match → entropy check → false positive filter → confidence score
entropy < 2.0  →  rejected
entropy > 4.0  →  confidence boosted
```

### Telemetry Sample
```json
{
  "ts": "2026-03-20T12:01:38",
  "scan_id": "3b0d606f",
  "module": "parallel_recon",
  "level": "METRIC",
  "event": "module_complete",
  "data": {"duration_ms": 69953, "findings_count": 30}
}
```

---

## Installation

**Prerequisites**
```bash
sudo apt install subfinder nmap ffuf whatweb wafw00f subjack nuclei -y
nuclei -update-templates
```

**Local Setup**
```bash
git clone https://github.com/JOYDALAL7/BugzBunny.git
cd BugzBunny
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Docker**
```bash
docker-compose up -d
# API at http://localhost:8001/docs
```

---

## Usage
```bash
source venv/bin/activate

# Default scan
python main.py scan --target hackerone.com

# With mode
python main.py scan --target hackerone.com --mode stealth

# Custom output
python main.py scan --target hackerone.com --output /tmp/results
```

---

## REST API
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Start a scan |
| GET | `/scans` | List all scans |
| GET | `/scan/{id}` | Scan status |
| GET | `/scan/{id}/report` | HTML report |
| DELETE | `/scan/{id}` | Delete scan |

Swagger UI: `http://localhost:8000/docs`

---

## Pipeline
```
Phase 1    →  Subdomain Enumeration
Phase 2    →  Live Host Detection
Phase 3    →  Port Scan + Fuzzing + Fingerprint + WAF + Takeover + JS Secrets + CORS  ← parallel
Phase 4    →  Nuclei + CVE Lookup  ← parallel
Phase 4.5  →  Risk Correlation + Attack Chain Engine
Phase 5    →  Database + Diff + HTML + PDF
```

---

## Output
```
reports/target.com/
├── target.com_report.html      ← dark-themed HTML report
├── target.com_report.pdf       ← A4 PDF report
├── bugzbunny.db                ← normalized SQLite (10 tables)
├── diff_report.json            ← delta from previous scan
├── logs/<scan_id>.log          ← structured JSON telemetry
└── raw/
    ├── subdomains.json
    ├── ports.json
    ├── vulnerabilities.json
    ├── cves.json
    ├── js_secrets.json
    ├── cors.json
    ├── risk_chains.json        ← attack chains + exploitable paths
    └── fuzzing/
```

---

## Database Schema
```
Scan · Finding · Target · Host · Port
Technology · WAFResult · Secret · CORSResult · RiskChain
```

10 normalized tables with foreign key relationships — queryable across modules.

---

## Legal Disclaimer

> For **authorized security testing only**.
> Always obtain written permission before scanning any target.
> Only test targets listed on HackerOne, Bugcrowd, or Intigriti.

---

<div align="center">

**Joy Dalal** — [@JOYDALAL7](https://github.com/JOYDALAL7)

*Hop. Hunt. Hack. 🐰*

</div>
