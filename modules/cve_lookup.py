import requests
import json
import time
import re
from rich.console import Console

console = Console()

NVD_API             = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VALID_TECH_PATTERN  = re.compile(r'^[a-zA-Z][a-zA-Z0-9\-\_\.]+$')

BLACKLIST = {
    "http", "https", "www", "unknown", "frame", "title", "script",
    "via-proxy", "redirectlocation", "poweredby", "country", "us",
    "eu", "uk", "permanently", "found", "not", "error", "none",
    "content-language", "httponly", "open-graph-protocol", "html5",
    "see", "meta", "tag", "manager", "analytics", "strict",
    "transport", "security", "cdn-cgi", "cgi", "cookie", "header",
    "redirect", "location", "charset", "encoding", "viewport",
    "robots", "sitemap", "favicon", "icon", "apple", "google",
    "x-frame-options", "x-xss-protection", "x-ua-compatible",
    "x-powered-by", "x-content-type", "x-forwarded",
    "content-security", "content-type", "content-length",
    "cache-control", "access-control", "metagenerator",
    "meta-refresh-redirect", "httpserver", "amazon-cloudfront",
    "google-analytics", "google-tag-manager", "open-graph",
    "twitter-cards", "schema-org", "json-ld", "microdata"
}

COMMON_TLDS = [".com", ".org", ".net", ".io", ".gov", ".edu", ".co", ".hackerone"]

KNOWN_TECHS = {
    "nginx", "apache", "iis", "tomcat", "wordpress", "drupal", "joomla",
    "jquery", "react", "angular", "vue", "laravel", "django", "rails",
    "php", "python", "ruby", "java", "nodejs", "express", "flask",
    "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
    "cloudflare", "fastly", "akamai", "varnish", "squid",
    "openssl", "openssh", "proftpd", "vsftpd", "sendmail",
    "bootstrap", "webpack", "typescript", "graphql", "next",
    "jenkins", "gitlab", "jira", "confluence", "struts",
    "spring", "log4j", "jackson", "lodash", "moment",
    "axios", "express", "koa", "hapi", "fastify",
    "sqlite", "mariadb", "cassandra", "memcached",
    "rabbitmq", "kafka", "haproxy", "traefik"
}

# ── Mode-based config ──────────────────────────────────
MODE_CONFIG = {
    "passive":    {"max_techs": 3,  "results_per_page": 3, "sleep": 2.0},
    "stealth":    {"max_techs": 5,  "results_per_page": 3, "sleep": 2.0},
    "active":     {"max_techs": 10, "results_per_page": 5, "sleep": 1.0},
    "aggressive": {"max_techs": 20, "results_per_page": 10, "sleep": 0.5},
}

def is_valid_tech(name: str) -> bool:
    """Filter out garbage technology names"""
    name_lower = name.strip().lower()
    if not name_lower or len(name_lower) < 3:
        return False
    if name_lower in BLACKLIST:
        return False
    if "-" in name_lower and name_lower not in KNOWN_TECHS:
        return False
    if not VALID_TECH_PATTERN.match(name_lower):
        return False
    if len(name_lower) > 30:
        return False
    if "." in name_lower and any(tld in name_lower for tld in COMMON_TLDS):
        return False
    if re.search(r'\.\d+', name_lower):
        return False
    if name_lower not in KNOWN_TECHS:
        return False
    return True

def lookup_cve(service: str, results_per_page: int = 5) -> list:
    """Lookup CVEs for a given service/technology"""
    try:
        response = requests.get(
            NVD_API,
            params={
                "keywordSearch":  service,
                "resultsPerPage": results_per_page,
                "startIndex":     0
            },
            timeout=10
        )
        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cve      = item.get("cve", {})
            cve_id   = cve.get("id", "N/A")
            desc     = cve.get("descriptions", [{}])[0].get("value", "N/A")
            metrics  = cve.get("metrics", {})
            score    = "N/A"
            severity = "N/A"

            if "cvssMetricV31" in metrics:
                score    = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in metrics:
                score    = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]

            cves.append({
                "id":          cve_id,
                "score":       score,
                "severity":    severity,
                "description": desc[:200]
            })

        return cves

    except Exception as e:
        console.print(f"[red]  [-] CVE lookup failed for {service}: {e}[/]")
        return []

def run_cve_lookup(tech_results: dict, port_results: dict, target: str,
                   raw_dir: str, mode: str = "active") -> dict:
    """Run CVE lookup — mode aware"""

    cfg = MODE_CONFIG.get(mode, MODE_CONFIG["active"])
    console.print(f"[cyan][*] Running CVE lookup [{mode}]...[/]")

    all_cves     = {}
    technologies = set()

    # Collect techs from fingerprint results
    for host, techs in tech_results.items():
        for tech in techs:
            name    = tech.get("name", "").strip()
            version = tech.get("version", "").strip()
            if is_valid_tech(name):
                if version and re.match(r'^\d[\d\.]+$', version):
                    technologies.add(f"{name} {version}")
                else:
                    technologies.add(name)

    # Collect services from port scan
    for host, ports in port_results.items():
        for port in ports:
            service = port.get("service", "").strip()
            if is_valid_tech(service):
                technologies.add(service)

    # Limit by mode
    tech_list = list(technologies)[:cfg["max_techs"]]

    for tech in tech_list:
        console.print(f"[cyan][*] Looking up CVEs for: {tech}[/]")
        cves = lookup_cve(tech, cfg["results_per_page"])

        if cves:
            all_cves[tech] = cves
            console.print(f"[yellow]  [!] {tech} → {len(cves)} CVEs found[/]")

        time.sleep(cfg["sleep"])

    # Save to raw dir
    out_file = f"{raw_dir}/cves.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "cves": all_cves}, f, indent=2)

    total = sum(len(v) for v in all_cves.values())
    console.print(f"[green]  ✓ CVE lookup complete → {total} CVEs found → {out_file}[/]")
    return all_cves
