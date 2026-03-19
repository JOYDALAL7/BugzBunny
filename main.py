import click
import os
import asyncio
from rich.console import Console
from core.banner import show_banner
from core.async_runner import run_async, run_parallel
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

console = Console()

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

    # Organized folder structure
    output_dir = os.path.join(output, target)
    raw_dir    = os.path.join(output_dir, "raw")
    temp_dir   = os.path.join(output_dir, "temp")
    fuzz_dir   = os.path.join(raw_dir, "fuzzing")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(raw_dir,    exist_ok=True)
    os.makedirs(temp_dir,   exist_ok=True)
    os.makedirs(fuzz_dir,   exist_ok=True)

    console.print(f"[bold green][*] Target:[/] {target}")
    console.print(f"[bold green][*] Output:[/] {output_dir}")

    # Initialize Database
    db_path = init_db(output_dir)
    scan_record = create_scan(target)
    console.print(f"[bold green][*] Database:[/] {db_path}")

    # Phase 2: Subdomains (must run first)
    subdomains = await run_async(run_subfinder, target, raw_dir, temp_dir)
    if not subdomains:
        console.print(f"[yellow][~] No subdomains found, using target directly[/]")
        subdomains = [target]
    for sub in subdomains:
        save_finding(scan_record, "subdomain", "info", sub, data={"subdomain": sub})

    # Phase 3: Live Hosts (must run after subdomains)
    live_hosts = await run_async(run_httpx, subdomains, target, raw_dir, temp_dir)
    if not live_hosts:
        console.print(f"[yellow][~] Using target as live host directly[/]")
        live_hosts = [f"http://{target}"]
    for host in live_hosts:
        save_finding(scan_record, "livehosts", "info", host, data={"url": host})

    # Phase 4-8: Run in parallel
    console.print(f"[bold cyan][*] Running parallel scans...[/]")
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

    # Phase 9-10: Run in parallel
    console.print(f"[bold cyan][*] Running vulnerability scans...[/]")
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

    # Complete scan
    complete_scan(scan_record)
    console.print(f"[bold green][+] Scan saved to database![/]")

    # Phase 19: Diff Report
    diff_results = generate_diff(target, output_dir)

    # Phase 11: Generate HTML Report
    generate_report(target, output_dir, subdomains, live_hosts,
                    port_results, waf_results, vuln_results, cve_results)

if __name__ == '__main__':
    cli()
