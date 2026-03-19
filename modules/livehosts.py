import subprocess
import json
from rich.console import Console

console = Console()

def check_host_alive(url: str) -> bool:
    """Check if host is alive using curl"""
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--connect-timeout", "10", "-L", url],
            capture_output=True,
            text=True,
            timeout=15
        )
        code = result.stdout.strip()
        return code.isdigit() and int(code) > 0
    except Exception:
        return False

def run_httpx(subdomains: list, target: str, raw_dir: str, temp_dir: str) -> list:
    """Check which hosts are alive using curl fallback"""

    if not subdomains:
        console.print("[red][-] No subdomains to check[/]")
        return []

    live_hosts = []

    with console.status("[cyan]Detecting live hosts...[/]"):
        for subdomain in subdomains:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{subdomain}"
                if check_host_alive(url):
                    result = subprocess.run(
                        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                         "--connect-timeout", "10", "-L", url],
                        capture_output=True, text=True, timeout=15
                    )
                    code = result.stdout.strip()
                    live_hosts.append(f"{url} [{code}]")
                    break

    # Save to raw dir
    out_file = f"{raw_dir}/livehosts.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "live_hosts": live_hosts}, f, indent=2)

    console.print(f"[green][+] Found {len(live_hosts)} live hosts → {out_file}[/]")
    return live_hosts
