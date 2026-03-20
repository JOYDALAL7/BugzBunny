import subprocess
import json
import re
from rich.console import Console

console = Console()

def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def run_wafw00f(live_hosts: list, target: str, raw_dir: str,
                mode: str = "active") -> dict:
    """Detect WAF on live hosts — mode aware"""

    if not live_hosts:
        console.print("[red][-] No live hosts to check[/]")
        return {}

    # Passive — skip active WAF probing
    if mode == "passive":
        console.print("[dim]  › WAF detection skipped in passive mode[/]")
        return {}

    # Mode-based timeout
    timeout = 15 if mode == "stealth" else 30

    all_results = {}

    for host in live_hosts:
        url = host.split()[0]
        console.print(f"[cyan][*] Detecting WAF on {url} [{mode}]...[/]")

        try:
            result = subprocess.run(
                ["wafw00f", url],
                capture_output=True,
                text=True,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            console.print(f"[yellow][~] WAF detection timed out for {url}[/]")
            all_results[url] = "Timeout"
            continue
        except Exception as e:
            console.print(f"[red][-] WAF detection failed for {url}: {e}[/]")
            all_results[url] = "Error"
            continue

        # Clean ANSI codes
        clean_output = strip_ansi(result.stdout)

        # Parse output
        waf_detected = "No WAF"
        for line in clean_output.splitlines():
            line_lower = line.lower()
            if "is behind" in line_lower:
                match = re.search(r'is behind (.+)', line, re.IGNORECASE)
                if match:
                    waf_detected = match.group(1).strip()
            elif "no waf" in line_lower:
                waf_detected = "No WAF detected"

        all_results[url] = waf_detected

        if "No WAF" in waf_detected:
            console.print(f"[red]  [*] {url} → {waf_detected}[/]")
        else:
            console.print(f"[yellow]  [*] {url} → WAF: {waf_detected}[/]")

    # Save to raw dir
    out_file = f"{raw_dir}/waf.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "waf": all_results}, f, indent=2)

    console.print(f"[green]  ✓ WAF detection complete → {out_file}[/]")
    return all_results
