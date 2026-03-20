import subprocess
import json
import re
from rich.console import Console

console = Console()

def run_whatweb(live_hosts: list, target: str, raw_dir: str) -> dict:
    """Fingerprint technologies on live hosts"""

    if not live_hosts:
        console.print("[red][-] No live hosts to fingerprint[/]")
        return {}

    all_results = {}

    for host in live_hosts:
        url = host.split()[0]
        console.print(f"[cyan][*] Fingerprinting {url}[/]")

        try:
            result = subprocess.run(
                [
                    "whatweb",
                    "--color=never",
                    "--log-brief=/dev/stdout",
                    "-a", "1",
                    url
                ],
                capture_output=True,
                text=True,
                timeout=30
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
            techs = re.findall(pattern, line)
            for name, version in techs:
                if name.lower() not in ["http", "https", "www"]:
                    technologies.append({
                        "name": name,
                        "version": version if version else "unknown"
                    })

        all_results[url] = technologies
        console.print(f"[green][+] {url} → {len(technologies)} technologies detected[/]")

    # Save to raw dir
    out_file = f"{raw_dir}/fingerprint.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "fingerprint": all_results}, f, indent=2)

    console.print(f"[green][+] Fingerprinting complete → {out_file}[/]")
    return all_results
