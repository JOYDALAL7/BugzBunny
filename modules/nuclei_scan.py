import subprocess
import json
import os
from rich.console import Console

console = Console()

def run_nuclei(live_hosts: list, target: str, raw_dir: str, temp_dir: str,
               mode: str = "active") -> dict:
    """Run nuclei vulnerability scanner on live hosts"""

    if not live_hosts:
        console.print("[red][-] No live hosts to scan[/]")
        return {}

    tmp_file   = f"{temp_dir}/hosts.txt"
    clean_hosts = [h.split()[0] for h in live_hosts]
    with open(tmp_file, "w") as f:
        f.write("\n".join(clean_hosts))

    nuclei_raw = f"{temp_dir}/nuclei_raw.json"

    # ── Mode-based config ─────────────────────
    if mode == "stealth":
        rate_limit = "5"
        timeout    = "15"
        severity   = "critical,high"
        templates  = ["-t", "http/technologies/", "-t", "http/exposures/"]
    elif mode == "aggressive":
        rate_limit = "50"
        timeout    = "8"
        severity   = "critical,high,medium,low,info"
        templates  = [
            "-t", "http/technologies/",
            "-t", "http/exposures/",
            "-t", "http/misconfiguration/",
            "-t", "http/vulnerabilities/",
            "-t", "http/cves/",
        ]
    else:  # active (default)
        rate_limit = "20"
        timeout    = "10"
        severity   = "critical,high,medium,low"
        templates  = [
            "-t", "http/technologies/",
            "-t", "http/exposures/",
            "-t", "http/misconfiguration/",
            "-t", "http/vulnerabilities/",
        ]

    console.print(f"[cyan][*] Running nuclei [{mode} mode]...[/]")

    cmd = [
        "nuclei",
        "-l",        tmp_file,
        "-severity", severity,
        "-o",        nuclei_raw,
        "-je",
        "-silent",
        "-rl",       rate_limit,
        "-timeout",  timeout,
        "-retries",  "1",
        "-max-host-error", "5",
        "-duc",
        "-nm",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ] + templates

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 min max
        )
    except subprocess.TimeoutExpired:
        console.print("[yellow][~] Nuclei timed out, parsing partial results...[/]")
    except FileNotFoundError:
        console.print("[red][-] Nuclei not found — skipping[/]")
        return {}

    # ── Parse results ─────────────────────────
    findings = []
    try:
        with open(nuclei_raw) as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
    except Exception:
        pass

    # ── Organize by severity ──────────────────
    summary = {
        "critical": [],
        "high":     [],
        "medium":   [],
        "low":      []
    }

    for f in findings:
        sev = f.get("info", {}).get("severity", "low").lower()
        if sev in summary:
            summary[sev].append({
                "name":     f.get("info", {}).get("name"),
                "host":     f.get("host"),
                "matched":  f.get("matched-at"),
                "tags":     f.get("info", {}).get("tags", []),
                "severity": sev
            })

    # ── Save results ──────────────────────────
    structured_file = f"{raw_dir}/vulnerabilities.json"
    with open(structured_file, "w") as f:
        json.dump({
            "target":          target,
            "mode":            mode,
            "total":           len(findings),
            "vulnerabilities": summary
        }, f, indent=2)

    # ── Display summary ───────────────────────
    total = len(findings)
    if total > 0:
        console.print(f"[bold red]  [!] Critical : {len(summary['critical'])}[/]")
        console.print(f"[bold yellow]  [!] High     : {len(summary['high'])}[/]")
        console.print(f"[bold blue]  [!] Medium   : {len(summary['medium'])}[/]")
        console.print(f"[bold green]  [!] Low      : {len(summary['low'])}[/]")
    else:
        console.print("[dim]  → No vulnerabilities found[/]")

    console.print(f"[green]  ✓ Nuclei complete → {structured_file}[/]")
    return summary
