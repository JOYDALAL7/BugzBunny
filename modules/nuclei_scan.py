import subprocess
import json
from rich.console import Console

console = Console()

def run_nuclei(live_hosts: list, target: str, raw_dir: str, temp_dir: str) -> dict:
    """Run nuclei vulnerability scanner on live hosts"""

    if not live_hosts:
        console.print("[red][-] No live hosts to scan[/]")
        return {}

    # Temp files go in temp_dir
    tmp_file = f"{temp_dir}/hosts.txt"
    clean_hosts = [h.split()[0] for h in live_hosts]
    with open(tmp_file, "w") as f:
        f.write("\n".join(clean_hosts))

    nuclei_raw = f"{temp_dir}/nuclei_raw.json"

    with console.status("[cyan]Running nuclei vulnerability scan...[/]"):
        try:
            result = subprocess.run(
                [
                    "nuclei",
                    "-l", tmp_file,
                    "-severity", "critical,high,medium",
                    "-o", nuclei_raw,
                    "-je",
                    "-silent",
                    "-rate-limit", "50",
                    "-timeout", "5",
                    "-retries", "0",
                    "-max-host-error", "3",
                    "-tags", "exposures,misconfiguration,cve,xss,sqli,lfi",
                    "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                ],
                capture_output=True,
                text=True,
                timeout=180
            )
        except subprocess.TimeoutExpired:
            console.print("[yellow][~] Nuclei timed out, continuing...[/]")

    # Parse results
    findings = []
    try:
        with open(nuclei_raw) as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
    except Exception:
        pass

    # Organize by severity
    summary = {
        "critical": [],
        "high": [],
        "medium": []
    }

    for f in findings:
        sev = f.get("info", {}).get("severity", "medium").lower()
        if sev in summary:
            summary[sev].append({
                "name": f.get("info", {}).get("name"),
                "host": f.get("host"),
                "matched": f.get("matched-at"),
                "tags": f.get("info", {}).get("tags", [])
            })

    # Save structured results
    structured_file = f"{raw_dir}/vulnerabilities.json"
    with open(structured_file, "w") as f:
        json.dump({
            "target": target,
            "total": len(findings),
            "vulnerabilities": summary
        }, f, indent=2)

    # Display summary
    console.print(f"[bold red][!] Critical: {len(summary['critical'])}[/]")
    console.print(f"[bold yellow][!] High:     {len(summary['high'])}[/]")
    console.print(f"[bold blue][!] Medium:   {len(summary['medium'])}[/]")
    console.print(f"[green][+] Nuclei scan complete → {structured_file}[/]")
    return summary
