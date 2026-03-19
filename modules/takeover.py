import subprocess
import json
from rich.console import Console

console = Console()

def run_subjack(subdomains: list, target: str, raw_dir: str, temp_dir: str) -> dict:
    """Check for subdomain takeover vulnerabilities using subjack"""

    if not subdomains:
        console.print("[red][-] No subdomains to check[/]")
        return {}

    # Temp files go in temp_dir
    tmp_file = f"{temp_dir}/subs.txt"
    with open(tmp_file, "w") as f:
        f.write("\n".join(subdomains))

    raw_out = f"{temp_dir}/takeover_raw.txt"

    with console.status("[cyan]Checking for subdomain takeovers...[/]"):
        result = subprocess.run(
            [
                "subjack",
                "-w", tmp_file,
                "-t", "20",
                "-timeout", "30",
                "-o", raw_out,
                "-ssl"
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

    # Parse only raw text output
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
        "vulnerable": vulnerable,
        "total_checked": len(subdomains)
    }

    # Save structured JSON to raw dir
    out_file = f"{raw_dir}/takeover.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "takeover": results}, f, indent=2)

    if vulnerable:
        console.print(f"[bold red][!] {len(vulnerable)} VULNERABLE subdomains found![/]")
        for v in vulnerable:
            console.print(f"[red]  → {v}[/]")
    else:
        console.print(f"[green][+] No takeover vulnerabilities found[/]")

    console.print(f"[green][+] Takeover check complete → {out_file}[/]")
    return results
