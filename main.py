import click
import os
from rich.console import Console
from core.banner import show_banner
from modules.subdomain import run_subfinder
from modules.livehosts import run_httpx
from modules.portscan import run_nmap
from modules.fuzzer import run_ffuf
from modules.fingerprint import run_whatweb
from modules.waf import run_wafw00f
from modules.takeover import run_subjack
from modules.nuclei_scan import run_nuclei
from modules.cve_lookup import run_cve_lookup
from core.reporter import generate_report
from core.database import init_db, create_scan, save_finding, complete_scan

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

    # Phase 2: Subdomains
    subdomains = run_subfinder(target, raw_dir, temp_dir)
    if not subdomains:
        console.print(f"[yellow][~] No subdomains found, using target directly[/]")
        subdomains = [target]
    for sub in subdomains:
        save_finding(scan_record, "subdomain", "info", sub, data={"subdomain": sub})

    # Phase 3: Live Hosts
    live_hosts = run_httpx(subdomains, target, raw_dir, temp_dir)
    if not live_hosts:
        console.print(f"[yellow][~] Using target as live host directly[/]")
        live_hosts = [f"http://{target}"]
    for host in live_hosts:
        save_finding(scan_record, "livehosts", "info", host, data={"url": host})

    # Phase 4: Port Scanning
    port_results = run_nmap(live_hosts, target, raw_dir)
    for host, ports in port_results.items():
        for port in ports:
            save_finding(scan_record, "portscan", "info",
                f"{host}:{port['port']}/{port['service']}",
                data={"host": host, "port": port["port"], "service": port["service"]})

    # Phase 5: Directory Fuzzing
    fuzz_results = run_ffuf(live_hosts, target, fuzz_dir)

    # Phase 6: Technology Fingerprinting
    tech_results = run_whatweb(live_hosts, target, raw_dir)

    # Phase 7: WAF Detection
    waf_results = run_wafw00f(live_hosts, target, raw_dir)

    # Phase 8: Subdomain Takeover
    takeover_results = run_subjack(subdomains, target, raw_dir, temp_dir)

    # Phase 9: Nuclei Vulnerability Scan
    vuln_results = run_nuclei(live_hosts, target, raw_dir, temp_dir)
    for sev, vulns in vuln_results.items():
        for v in vulns:
            save_finding(scan_record, "nuclei", sev,
                v.get("name", "unknown"),
                description=v.get("matched", ""),
                data=v)

    # Phase 10: CVE Lookup
    cve_results = run_cve_lookup(tech_results, port_results, target, raw_dir)
    for tech, cves in cve_results.items():
        for cve in cves:
            save_finding(scan_record, "cve", cve.get("severity", "info").lower(),
                cve.get("id", "unknown"),
                description=cve.get("description", ""),
                data=cve)

    # Complete scan record
    complete_scan(scan_record)
    console.print(f"[bold green][+] Scan saved to database![/]")

    # Phase 11: Generate HTML Report
    generate_report(target, output_dir, subdomains, live_hosts,
                    port_results, waf_results, vuln_results, cve_results)

if __name__ == '__main__':
    cli()
