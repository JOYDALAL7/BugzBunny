import requests
import json
import urllib3
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Test origins to check CORS
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://bugzbunny.io",
]

def check_cors(url: str) -> dict:
    """Check CORS misconfiguration on a URL"""
    results = []

    for origin in TEST_ORIGINS:
        try:
            response = requests.get(
                url,
                headers={
                    "Origin": origin,
                    "User-Agent": "Mozilla/5.0"
                },
                timeout=10,
                verify=False,
                allow_redirects=True
            )

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            # Check for vulnerabilities
            vulnerable = False
            issue = ""

            if acao == "*":
                vulnerable = True
                issue = "Wildcard ACAO header (*)"
            elif acao == origin:
                vulnerable = True
                issue = f"Origin reflected: {origin}"
                if acac.lower() == "true":
                    issue += " + Credentials allowed (CRITICAL!)"
            elif acao == "null" and origin == "null":
                vulnerable = True
                issue = "Null origin accepted"

            if vulnerable:
                results.append({
                    "url":         url,
                    "origin":      origin,
                    "acao":        acao,
                    "credentials": acac,
                    "issue":       issue,
                    "severity":    "critical" if "CRITICAL" in issue else "high"
                })

        except Exception:
            pass

    return results

def run_cors(live_hosts: list, target: str, raw_dir: str) -> dict:
    """Run CORS misconfiguration checks on all live hosts"""

    if not live_hosts:
        console.print("[red][-] No live hosts to check CORS[/]")
        return {}

    all_results = {}
    total_vulns = 0

    for host in live_hosts:
        url = host.split()[0]
        console.print(f"[cyan][*] Checking CORS on {url}[/]")

        findings = check_cors(url)

        if findings:
            all_results[url] = findings
            total_vulns += len(findings)
            for f in findings:
                severity_color = "bold red" if f["severity"] == "critical" else "yellow"
                console.print(f"[{severity_color}]  [!] {f['issue']}[/]")
        else:
            console.print(f"[green]  [+] {url} → No CORS issues[/]")

    # Save results
    out_file = f"{raw_dir}/cors.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "cors": all_results}, f, indent=2)

    if total_vulns > 0:
        console.print(f"[bold red][!] Found {total_vulns} CORS issues → {out_file}[/]")
    else:
        console.print(f"[green][+] CORS check complete → No issues found[/]")

    return all_results
