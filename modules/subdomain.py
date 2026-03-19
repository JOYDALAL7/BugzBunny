import subprocess
import json
from rich.console import Console

console = Console()

def run_subfinder(target: str, raw_dir: str, temp_dir: str) -> list:
    """Run subfinder and return list of subdomains"""
    console.print(f"[bold cyan][*] Running subdomain enumeration on {target}[/]")

    try:
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent", "-timeout", "10", "-max-time", "30"],
            capture_output=True,
            text=True,
            timeout=35
        )
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except subprocess.TimeoutExpired:
        console.print("[yellow][~] Subfinder timed out, continuing...[/]")
        subdomains = []

    # Save to raw dir
    out_file = f"{raw_dir}/subdomains.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "subdomains": subdomains}, f, indent=2)

    console.print(f"[green][+] Found {len(subdomains)} subdomains → {out_file}[/]")
    return subdomains
