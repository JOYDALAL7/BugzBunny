import subprocess
import json
from rich.console import Console

console = Console()

def run_subjack(subdomains: list, target: str, raw_dir: str, temp_dir: str,
                mode: str = "active") -> dict:
    """Check for subdomain takeover — mode aware"""

    if not subdomains:
        console.print("[red][-] No subdomains to check[/]")
        return {}

    # Passive — skip active probing
    if mode == "passive":
        console.print("[dim]  › Takeover check skipped in passive mode[/]")
        return {}

    # Mode-based config
    if mode == "stealth":
        threads = "5"
        timeout = "60"
        proc_timeout = 300
    elif mode == "aggressive":
        threads = "50"
        timeout = "20"
        proc_timeout = 300
    else:  # active (default)
        threads = "20"
        timeout = "30"
        proc_timeout = 180

    console.print(f"[cyan][*] Checking subdomain takeovers [{mode}]...[/]")

    # Write subdomains to temp file
    tmp_file = f"{temp_dir}/subs.txt"
    with open(tmp_file, "w") as f:
        f.write("\n".join(subdomains))

    raw_out = f"{temp_dir}/takeover_raw.txt"

    try:
        subprocess.run(
            [
                "subjack",
                "-w",       tmp_file,
                "-t",       threads,
                "-timeout", timeout,
                "-o",       raw_out,
                "-ssl"
            ],
            capture_output=True,
            text=True,
            timeout=proc_timeout
        )
    except subprocess.TimeoutExpired:
        console.print("[yellow][~] Takeover check timed out[/]")
    except FileNotFoundError:
        console.print("[red][-] subjack not found — skipping[/]")
        return {}

    # Parse results
    vulnerable = []
    try:
        with open(raw_out) as f:
            for line in f:
                line = line.strip()
                if (line
                    and not line.startswith("{")
                    and not line.startswith("\"")
                    and "not vulnerable" not in line.lower()
                    and "vulnerable" in line.lower()):
                    vulnerable.append(line)
    except Exception:
        pass

    results = {
        "vulnerable":     vulnerable,
        "total_checked":  len(subdomains),
        "mode":           mode
    }

    # Save to raw dir
    out_file = f"{raw_dir}/takeover.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "takeover": results}, f, indent=2)

    if vulnerable:
        console.print(f"[bold red]  [!] {len(vulnerable)} VULNERABLE subdomains![/]")
        for v in vulnerable:
            console.print(f"  [red]→ {v}[/]")
    else:
        console.print(f"[green]  ✓ No takeover vulnerabilities found[/]")

    console.print(f"[green]  ✓ Takeover check complete → {out_file}[/]")
    return results
