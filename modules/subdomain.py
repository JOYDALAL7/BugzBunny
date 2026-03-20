import subprocess
import json
from rich.console import Console

console = Console()

def run_subfinder(target: str, raw_dir: str, temp_dir: str,
                  mode: str = "active") -> list:
    """Run subdomain enumeration — mode aware"""

    console.print(f"[cyan][*] Subdomain enumeration on {target} [{mode}]...[/]")

    # ── Mode-based config ─────────────────────
    if mode == "passive":
        # Passive only — no active DNS bruteforce
        cmd = [
            "subfinder", "-d", target,
            "-silent",
            "-timeout", "10",
            "-max-time", "30",
            "-sources", "passive"   # passive sources only
        ]
        timeout = 35

    elif mode == "stealth":
        # Slower, fewer sources
        cmd = [
            "subfinder", "-d", target,
            "-silent",
            "-timeout", "15",
            "-max-time", "45",
        ]
        timeout = 50

    elif mode == "aggressive":
        # All sources, longer timeout
        cmd = [
            "subfinder", "-d", target,
            "-silent",
            "-timeout", "30",
            "-max-time", "120",
            "-all",               # all sources
        ]
        timeout = 130

    else:  # active (default)
        cmd = [
            "subfinder", "-d", target,
            "-silent",
            "-timeout", "10",
            "-max-time", "30",
        ]
        timeout = 35

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        subdomains = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]
    except subprocess.TimeoutExpired:
        console.print("[yellow][~] Subfinder timed out[/]")
        subdomains = []
    except FileNotFoundError:
        console.print("[red][-] subfinder not found[/]")
        subdomains = []

    # Save to raw dir
    out_file = f"{raw_dir}/subdomains.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "subdomains": subdomains}, f, indent=2)

    console.print(f"[green]  ✓ Found {len(subdomains)} subdomains → {out_file}[/]")
    return subdomains
