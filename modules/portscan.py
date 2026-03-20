import subprocess
import json
import re
from rich.console import Console

console = Console()

def parse_nmap_output(output: str) -> dict:
    """Parse nmap stdout into structured dict"""
    results = {}
    current_host = None
    for line in output.splitlines():
        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            current_host = host_match.group(1).strip()
            results[current_host] = []
        port_match = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if port_match and current_host:
            results[current_host].append({
                "port":    int(port_match.group(1)),
                "service": port_match.group(2)
            })
    return results

def run_nmap(live_hosts: list, target: str, raw_dir: str,
             mode: str = "active") -> dict:
    """Run nmap on live hosts — mode aware"""

    if not live_hosts:
        console.print("[red][-] No live hosts to scan[/]")
        return {}

    # Extract clean hostnames
    clean_hosts = []
    for h in live_hosts:
        host = h.split()[0]
        host = host.replace("https://", "").replace("http://", "")
        clean_hosts.append(host)

    # ── Mode-based nmap flags ─────────────────
    if mode == "stealth":
        # Slow, low noise — SYN scan, slow timing
        flags   = ["-sS", "-T2", "--open", "-F", "-Pn"]
        timeout = 600
        console.print("[cyan][*] Running port scan [stealth]...[/]")

    elif mode == "aggressive":
        # Full port range, version detection, OS detection
        flags   = ["-T4", "--open", "-p-", "-sV", "--version-intensity", "5"]
        timeout = 600
        console.print("[cyan][*] Running port scan [aggressive]...[/]")

    elif mode == "passive":
        # Passive mode — skip nmap entirely
        console.print("[dim]  › Port scan skipped in passive mode[/]")
        return {}

    else:  # active (default)
        # Fast scan, top ports
        flags   = ["-T4", "--open", "-F"]
        timeout = 300
        console.print("[cyan][*] Running port scan [active]...[/]")

    try:
        result = subprocess.run(
            ["nmap"] + flags + clean_hosts,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        console.print("[yellow][~] Port scan timed out[/]")
        return {}
    except FileNotFoundError:
        console.print("[red][-] nmap not found[/]")
        return {}

    parsed = parse_nmap_output(result.stdout)

    # Save to raw dir
    out_file = f"{raw_dir}/ports.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "port_scan": parsed}, f, indent=2)

    total_ports = sum(len(v) for v in parsed.values())
    console.print(f"[green]  ✓ Found {total_ports} open ports → {out_file}[/]")
    return parsed
