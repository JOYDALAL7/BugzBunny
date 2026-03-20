import subprocess
import json
import re
from rich.console import Console

console = Console()

def run_whatweb(live_hosts: list, target: str, raw_dir: str,
                mode: str = "active") -> dict:
    """Fingerprint technologies on live hosts — mode aware"""

    if not live_hosts:
        console.print("[red][-] No live hosts to fingerprint[/]")
        return {}

    # Mode-based aggression level
    # -a 1 = stealthy, -a 3 = aggressive
    if mode == "passive":
        aggression = "1"
        timeout    = 15
    elif mode == "stealth":
        aggression = "1"
        timeout    = 20
    elif mode == "aggressive":
        aggression = "3"
        timeout    = 30
    else:  # active
        aggression = "1"
        timeout    = 30

    all_results = {}

    for host in live_hosts:
        url = host.split()[0]
        console.print(f"[cyan][*] Fingerprinting {url} [{mode}]...[/]")

        try:
            result = subprocess.run(
                [
                    "whatweb",
                    "--color=never",
                    "--log-brief=/dev/stdout",
                    "-a", aggression,
                    url
                ],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            line = result.stdout.strip()

        except subprocess.TimeoutExpired:
            console.print(f"[yellow][~] Timed out: {url}, skipping...[/]")
            all_results[url] = []
            continue
        except Exception as e:
            console.print(f"[red][-] Failed: {url} → {e}[/]")
            all_results[url] = []
            continue

        # Parse technologies
        technologies = []
        if line:
            pattern = r'([A-Za-z][\w\-\.]+)(?:\[([^\]]*)\])?'
            techs   = re.findall(pattern, line)
            for name, version in techs:
                if name.lower() not in ["http", "https", "www"]:
                    technologies.append({
                        "name":    name,
                        "version": version if version else "unknown"
                    })

        all_results[url] = technologies
        console.print(f"[green]  ✓ {url} → {len(technologies)} technologies detected[/]")

    # Save to raw dir
    out_file = f"{raw_dir}/fingerprint.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "fingerprint": all_results}, f, indent=2)

    console.print(f"[green]  ✓ Fingerprinting complete → {out_file}[/]")
    return all_results
