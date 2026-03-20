import click
import os
import asyncio
import json
from rich.console import Console
from rich.rule import Rule
from core.banner import show_banner
from core.async_runner import run_async, run_parallel
from core.normalizer import Normalizer
from core.risk_engine import RiskEngine
from modules.subdomain import run_subfinder
from modules.livehosts import run_httpx
from modules.portscan import run_nmap
from modules.fuzzer import run_ffuf
from modules.fingerprint import run_whatweb
from modules.waf import run_wafw00f
from modules.takeover import run_subjack
from modules.nuclei_scan import run_nuclei
from modules.cve_lookup import run_cve_lookup
from modules.js_secrets import run_js_secrets
from modules.cors import run_cors
from core.reporter import generate_report
from core.database import init_db, create_scan, save_finding, complete_scan
from core.diff import generate_diff
from core.pdf_export import export_pdf

console = Console()

def phase(number: str, title: str):
    """Print clean phase header with spacing"""
    console.print()
    console.print()
    console.print(f"  [bold red]━━━ Phase {number} :[/] [bold white]{title}[/]")
    console.print(f"  [dim]{'─' * 50}[/]")
    console.print()

@click.group()
def cli():
    """BugzBunny - Hop. Hunt. Hack."""
    show_banner()

@cli.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--output', '-o', default='reports', help='Output directory')
def scan(target, output):
    """Run full recon pipeline on a target"""
    asyncio.run(_scan(target, output))

async def _scan(target, output):
    """Async scan pipeline"""

    # Folder structure
    output_dir = os.path.join(output, target)
    raw_dir    = os.path.join(output_dir, "raw")
    temp_dir   = os.path.join(output_dir, "temp")
    fuzz_dir   = os.path.join(raw_dir, "fuzzing")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(raw_dir,    exist_ok=True)
    os.makedirs(temp_dir,   exist_ok=True)
    os.makedirs(fuzz_dir,   exist_ok=True)

    # Scan header
    console.print()
    console.print(Rule(style="red"))
    console.print(f"  [bold white]Target  [/]: [cyan]{target}[/]")
    console.print(f"  [bold white]Output  [/]: [cyan]{output_dir}[/]")
    db_path = init_db(output_dir)
    scan_record = create_scan(target)
    console.print(f"  [bold white]Database[/]: [cyan]{db_path}[/]")
    console.print(Rule(style="red"))

    # ──────────────────────────────────────────
    # Phase 1: Subdomain Enumeration
    # ──────────────────────────────────────────
    phase("1", "Subdomain Enumeration")

    subdomains = await run_async(run_subfinder, target, raw_dir, temp_dir)
    if not subdomains:
        console.print("[yellow]  → No subdomains found, using target directly[/]")
        subdomains = [target]
    for sub in subdomains:
        save_finding(scan_record, "subdomain", "info", sub, data={"subdomain": sub})

    # ──────────────────────────────────────────
    # Phase 2: Live Host Detection
    # ──────────────────────────────────────────
    phase("2", "Live Host Detection")

    live_hosts = await run_async(run_httpx, subdomains, target, raw_dir, temp_dir)
    if not live_hosts:
        console.print("[yellow]  → No live hosts found, using target directly[/]")
        live_hosts = [f"http://{target}"]
    for host in live_hosts:
        save_finding(scan_record, "livehosts", "info", host, data={"url": host})

    # ──────────────────────────────────────────
    # Phase 3: Parallel Recon
    # ──────────────────────────────────────────
    phase("3", "Parallel Recon")
    console.print("[dim]  Modules: Port Scan | Fuzzing | Fingerprint | WAF | Takeover | JS Secrets | CORS[/]")
    console.print()

    results = await run_parallel([
        run_async(run_nmap,       live_hosts, target, raw_dir),
        run_async(run_ffuf,       live_hosts, target, fuzz_dir),
        run_async(run_whatweb,    live_hosts, target, raw_dir),
        run_async(run_wafw00f,    live_hosts, target, raw_dir),
        run_async(run_subjack,    subdomains, target, raw_dir, temp_dir),
        run_async(run_js_secrets, live_hosts, target, raw_dir),
        run_async(run_cors,       live_hosts, target, raw_dir),
    ])

    port_results     = results[0] if not isinstance(results[0], Exception) else {}
    fuzz_results     = results[1] if not isinstance(results[1], Exception) else {}
    tech_results     = results[2] if not isinstance(results[2], Exception) else {}
    waf_results      = results[3] if not isinstance(results[3], Exception) else {}
    takeover_results = results[4] if not isinstance(results[4], Exception) else {}
    js_results       = results[5] if not isinstance(results[5], Exception) else {}
    cors_results     = results[6] if not isinstance(results[6], Exception) else {}

    # Save port findings
    for host, ports in port_results.items():
        for port in ports:
            save_finding(scan_record, "portscan", "info",
                f"{host}:{port['port']}/{port['service']}",
                data={"host": host, "port": port["port"], "service": port["service"]})

    # Save JS secret findings
    for host, secrets in js_results.items():
        for secret in secrets:
            save_finding(scan_record, "js_secrets", "high",
                secret.get("type", "unknown"),
                description=secret.get("match", ""),
                data=secret)

    # Save CORS findings
    for host, findings in cors_results.items():
        for finding in findings:
            save_finding(scan_record, "cors", finding.get("severity", "high"),
                finding.get("issue", "CORS Misconfiguration"),
                description=finding.get("acao", ""),
                data=finding)

    # ──────────────────────────────────────────
    # Phase 4: Vulnerability Scanning
    # ──────────────────────────────────────────
    phase("4", "Vulnerability Scanning")
    console.print("[dim]  Modules: Nuclei Scan | CVE Lookup[/]")
    console.print()

    vuln_cve = await run_parallel([
        run_async(run_nuclei,     live_hosts, target, raw_dir, temp_dir),
        run_async(run_cve_lookup, tech_results, port_results, target, raw_dir),
    ])

    vuln_results = vuln_cve[0] if not isinstance(vuln_cve[0], Exception) else {}
    cve_results  = vuln_cve[1] if not isinstance(vuln_cve[1], Exception) else {}

    # Save vuln findings
    for sev, vulns in vuln_results.items():
        for v in vulns:
            save_finding(scan_record, "nuclei", sev,
                v.get("name", "unknown"),
                description=v.get("matched", ""),
                data=v)

    # Save CVE findings
    for tech, cves in cve_results.items():
        for cve in cves:
            save_finding(scan_record, "cve", cve.get("severity", "info").lower(),
                cve.get("id", "unknown"),
                description=cve.get("description", ""),
                data=cve)

    # ──────────────────────────────────────────
    # Phase 4.5: Risk Correlation Engine
    # ──────────────────────────────────────────
    phase("4.5", "Risk Correlation & Scoring")

    normalizer   = Normalizer()
    all_findings = normalizer.normalize_all(
        port_results = port_results,
        vuln_results = vuln_results,
        cve_results  = cve_results,
        js_results   = js_results,
        cors_results = cors_results,
        waf_results  = waf_results
    )

    risk_chains = RiskEngine(all_findings).run()

    console.print(f"  [dim]Analyzed {len(all_findings)} findings across {len(risk_chains)} hosts[/]")
    console.print()

    for chain in risk_chains[:3]:
        if chain.risk_score >= 7.0:
            color = "bold red"
        elif chain.risk_score >= 5.0:
            color = "yellow"
        else:
            color = "green"
        console.print(f"  [{color}]► {chain.host}[/]")
        console.print(f"    Score : {chain.risk_score}")
        console.print(f"    Risk  : {chain.recommendation}")
        console.print(f"    Flags : {', '.join(chain.modifiers_applied)}")
        console.print()

    # Save risk chains
    risk_file = f"{raw_dir}/risk_chains.json"
    with open(risk_file, "w") as f:
        json.dump([{
            "host":              c.host,
            "risk_score":        c.risk_score,
            "modifiers_applied": c.modifiers_applied,
            "recommendation":    c.recommendation,
            "finding_count":     len(c.findings)
        } for c in risk_chains], f, indent=2)
    console.print(f"  [green]→ Risk chains saved → {risk_file}[/]")

    # ──────────────────────────────────────────
    # Phase 5: Save & Report
    # ──────────────────────────────────────────
    phase("5", "Saving Results & Generating Reports")

    complete_scan(scan_record)
    console.print("  [green]✓ Scan saved to database[/]")

    generate_diff(target, output_dir)
    console.print("  [green]✓ Diff report generated[/]")

    generate_report(target, output_dir, subdomains, live_hosts,
                    port_results, waf_results, vuln_results, cve_results,
                    risk_chains)
    console.print("  [green]✓ HTML report generated[/]")

    export_pdf(target, output_dir)
    console.print("  [green]✓ PDF report generated[/]")

    # Final summary
    console.print()
    console.print(Rule(style="red"))
    console.print()
    console.print("  [bold red]SCAN COMPLETE 🐰[/]")
    console.print()
    console.print(f"  [bold white]Target     [/]: [cyan]{target}[/]")
    console.print(f"  [bold white]Subdomains [/]: [cyan]{len(subdomains)}[/]")
    console.print(f"  [bold white]Live Hosts [/]: [cyan]{len(live_hosts)}[/]")
    console.print(f"  [bold white]Open Ports [/]: [cyan]{sum(len(v) for v in port_results.values())}[/]")
    console.print(f"  [bold white]JS Secrets [/]: [cyan]{sum(len(v) for v in js_results.values())}[/]")
    console.print(f"  [bold white]CORS Issues[/]: [cyan]{sum(len(v) for v in cors_results.values())}[/]")
    console.print(f"  [bold white]Vulns Found[/]: [cyan]{sum(len(v) for v in vuln_results.values())}[/]")
    console.print(f"  [bold white]CVEs Found [/]: [cyan]{sum(len(v) for v in cve_results.values())}[/]")
    console.print(f"  [bold white]Risk Score [/]: [cyan]{risk_chains[0].risk_score if risk_chains else 0.0}[/]")
    console.print(f"  [bold white]Report     [/]: [cyan]{output_dir}/{target}_report.html[/]")
    console.print()
    console.print(Rule(style="red"))

if __name__ == '__main__':
    cli()
