import requests
import json
import urllib3
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ── Test origins per mode ──────────────────────
ORIGINS_PASSIVE  = []  # no active probing
ORIGINS_STEALTH  = ["https://evil.com"]
ORIGINS_ACTIVE   = ["https://evil.com", "https://attacker.com", "null"]
ORIGINS_AGGRESSIVE = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://bugzbunny.io",
    "https://trusted.com",
]

def check_cors(url: str, origins: list, timeout: int = 10) -> list:
    """Check CORS misconfiguration on a URL"""
    results = []

    for origin in origins:
        try:
            response = requests.get(
                url,
                headers={
                    "Origin":     origin,
                    "User-Agent": "Mozilla/5.0"
                },
                timeout=timeout,
                verify=False,
                allow_redirects=True
            )

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            vulnerable = False
            issue      = ""

            if acao == "*":
                vulnerable = True
                issue      = "Wildcard ACAO header (*)"
            elif acao == origin:
                vulnerable = True
                issue      = f"Origin reflected: {origin}"
                if acac.lower() == "true":
                    issue += " + Credentials allowed (CRITICAL)"
            elif acao == "null" and origin == "null":
                vulnerable = True
                issue      = "Null origin accepted"

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

def run_cors(live_hosts: list, target: str, raw_dir: str,
             mode: str = "active") -> dict:
    """Run CORS misconfiguration checks — mode aware"""

    if not live_hosts:
        console.print("[red][-] No live hosts to check CORS[/]")
        return {}

    # Passive — skip active probing
    if mode == "passive":
        console.print("[dim]  › CORS check skipped in passive mode[/]")
        return {}

    # Select origins + timeout based on mode
    if mode == "stealth":
        origins = ORIGINS_STEALTH
        timeout = 15
    elif mode == "aggressive":
        origins = ORIGINS_AGGRESSIVE
        timeout = 10
    else:  # active
        origins = ORIGINS_ACTIVE
        timeout = 10

    all_results = {}
    total_vulns = 0

    for host in live_hosts:
        url = host.split()[0]
        console.print(f"[cyan][*] Checking CORS on {url} [{mode}]...[/]")

        findings = check_cors(url, origins, timeout)

        if findings:
            all_results[url] = findings
            total_vulns += len(findings)
            for f in findings:
                color = "bold red" if f["severity"] == "critical" else "yellow"
                console.print(f"  [{color}][!] {f['issue']}[/]")
        else:
            console.print(f"[green]  ✓ {url} → No CORS issues[/]")

    # Save results
    out_file = f"{raw_dir}/cors.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "cors": all_results}, f, indent=2)

    if total_vulns > 0:
        console.print(f"[bold red]  [!] Found {total_vulns} CORS issues → {out_file}[/]")
    else:
        console.print(f"[green]  ✓ CORS check complete → No issues found[/]")

    return all_results
