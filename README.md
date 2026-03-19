<div align="center">

# 🐰 BugzBunny

### Hop. Hunt. Hack.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)
![FastAPI](https://img.shields.io/badge/FastAPI-REST_API-009688?style=for-the-badge&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**BugzBunny is a modular, scalable offensive security automation framework built for bug bounty hunters and penetration testers. It automates the entire recon-to-report pipeline with 12+ security modules, a REST API, Docker support, and beautiful HTML reports.**

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
| 📊 HTML Reporting | `jinja2` | Beautiful dark-themed reports |
| 🗄️ Database Storage | `SQLite` | Persist scan history |
| 🌐 REST API | `FastAPI` | Programmatic scan control |

---

## 🚀 Installation

### Prerequisites
```bash
sudo apt install subfinder nmap ffuf whatweb wafw00f subjack nuclei -y
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

## 📁 Output Structure
```
reports/
└── target.com/
    ├── target.com_report.html    ← Beautiful HTML report
    ├── bugzbunny.db              ← SQLite database
    ├── raw/
    │   ├── subdomains.json
    │   ├── livehosts.json
    │   ├── ports.json
    │   ├── fingerprint.json
    │   ├── waf.json
    │   ├── takeover.json
    │   ├── vulnerabilities.json
    │   ├── cves.json
    │   └── fuzzing/
    │       └── fuzzing_summary.json
    └── temp/
```

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

## 📸 Report Preview

> Dark-themed HTML report with stats, subdomains, ports, WAF info, vulnerabilities and CVEs.

---

## ⚠️ Legal Disclaimer

> BugzBunny is intended for **authorized security testing only**.  
> The author is not responsible for any misuse or damage caused by this tool.  
> Always obtain proper written permission before testing any target.

---

## 👨‍💻 Author

**Joy Dalal** — [@JOYDALAL7](https://github.com/JOYDALAL7)

---

## 📄 License

This project is licensed under the MIT License.

---

<div align="center">
Made with ❤️ by BugzBunny | Hop. Hunt. Hack. 🐰
</div>
