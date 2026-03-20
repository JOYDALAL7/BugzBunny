import subprocess
import json
from rich.console import Console

console = Console()

def check_host_alive(url: str, connect_timeout: str = "10",
                     timeout: int = 15) -> bool:
    """Check if host is alive using curl"""
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--connect-timeout", connect_timeout, "-L", url],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        code = result.stdout.strip()
        return code.isdigit() and int(code) > 0
    except Exception:
        return False

def run_httpx(subdomains: list, target: str, raw_dir: str, temp_dir: str,
              mode: str = "active") -> list:
    """Check which hosts are alive — mode aware"""

    if not subdomains:
        console.print("[red][-] No subdomains to check[/]")
        return []

    # ── Mode-based config ─────────────────────
    if mode == "stealth":
        connect_timeout = "15"
        curl_timeout    = 20
        # Only check https in stealth — less noise
        schemes = ["https"]
    elif mode == "aggressive":
        connect_timeout = "5"
        curl_timeout    = 10
        schemes         = ["https", "http"]
    else:  # active / passive
        connect_timeout = "10"
        curl_timeout    = 15
        schemes         = ["https", "http"]

    console.print(f"[cyan][*] Detecting live hosts ({len(subdomains)} to check) [{mode}]...[/]")

    live_hosts = []

    for subdomain in subdomains:
        for scheme in schemes:
            url = f"{scheme}://{subdomain}"
            if check_host_alive(url, connect_timeout, curl_timeout):
                try:
                    result = subprocess.run(
                        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                         "--connect-timeout", connect_timeout, "-L", url],
                        capture_output=True,
                        text=True,
                        timeout=curl_timeout
                    )
                    code = result.stdout.strip()
                    live_hosts.append(f"{url} [{code}]")
                    console.print(f"[green]  ✓ {url} [{code}][/]")
                except Exception:
                    pass
                break  # skip http if https works

    # Save to raw dir
    out_file = f"{raw_dir}/livehosts.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "live_hosts": live_hosts}, f, indent=2)

    console.print(f"[green]  ✓ Found {len(live_hosts)} live hosts → {out_file}[/]")
    return live_hosts
