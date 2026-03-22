import click
import os
import asyncio
import json
import time
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from core.banner import show_banner
from core.async_runner import run_async, run_parallel
from core.normalizer import Normalizer
from core.risk_engine import RiskEngine
from core.logger import create_logger
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

SCAN_MODES = {
    "passive": {
        "description":  "Subdomain + live hosts + fingerprint only",
        "run_ports":    False,
        "run_fuzz":     False,
        "run_nuclei":   False,
        "run_takeover": False,
    },
    "stealth": {
        "description":  "Low-noise scan. No fuzzing.",
        "run_ports":    True,
        "run_fuzz":     False,
        "run_nuclei":   True,
        "run_takeover": True,
    },
    "active": {
        "description":  "Full scan. All modules.",
        "run_ports":    True,
        "run_fuzz":     True,
        "run_nuclei":   True,
        "run_takeover": True,
    },
    "aggressive": {
        "description":  "Maximum coverage. High rate limits.",
        "run_ports":    True,
        "run_fuzz":     True,
        "run_nuclei":   True,
        "run_takeover": True,
    },
}

def phase(number: str, title: str):
    console.print()
    console.print()
    console.print(f"  [bold red]━━━[/bold red]  [bold white]Phase {number}[/bold white]  [dim]·[/dim]  [white]{title}[/white]")
    console.print(f"  [dim]{'─' * 52}[/dim]")
    console.print()

def info(msg: str):
    console.print(f"  [dim]›[/dim]  {msg}")

def success(msg: str):
    console.print(f"  [green]✓[/green]  {msg}")

def warn(msg: str):
    console.print(f"  [yellow]⚠[/yellow]  {msg}")

def divider():
    console.print(f"  [dim]{'─' * 52}[/dim]")

def blank():
    console.print()

@click.group()
def cli():
    """
    \b
    BugzBunny — Async Security Intelligence Platform
    Hop. Hunt. Hack. 🐰
    \b
    USAGE:
      python main.py scan --target <domain>
      python main.py scan --target <domain> --mode <mode>
    \b
    EXAMPLES:
      python main.py scan --target hackerone.com
      python main.py scan --target testphp.vulnweb.com --mode active
      python main.py scan --target bugcrowd.com --mode stealth
    \b
    SCAN MODES:
      passive     Subdomain + live hosts + fingerprint only (no active scanning)
      stealth     Low-noise scan — ports, nuclei, takeover. No fuzzing.
      active      Full scan — all 16+ modules (default)
      aggressive  Maximum coverage — all modules, high rate limits
    \b
    PIPELINE:
      Phase 1    →  Subdomain Enumeration
      Phase 2    →  Live Host Detection
      Phase 3    →  Parallel Recon (nmap, ffuf, whatweb, wafw00f, subjack, js_secrets, cors)
      Phase 4    →  Vulnerability Scanning (nuclei + CVE lookup)
      Phase 4.5  →  Risk Correlation + Attack Chain Engine
      Phase 5    →  Reports (HTML + PDF + Diff + Database)
    \b
    OUTPUT:
      reports/<target>/
        ├── <target>_report.html    HTML report with attack chains
        ├── <target>_report.pdf     Professional A4 PDF
        ├── bugzbunny.db            SQLite database (10 tables)
        ├── diff_report.json        Changes since last scan
        ├── logs/<scan_id>.log      Structured JSON telemetry
        └── raw/
            ├── risk_chains.json    Attack chains + exploitable paths
            ├── vulnerabilities.json
            ├── cves.json
            └── ...
    """
    show_banner()

@cli.command()
@click.option('--target', '-t', required=True,
              help='Target domain to scan  (e.g. hackerone.com)')
@click.option('--output', '-o', default='reports',
              help='Output directory       (default: reports)')
@click.option('--mode',   '-m',
              default='active',
              type=click.Choice(['passive', 'stealth', 'active', 'aggressive'],
                                case_sensitive=False),
              help='Scan mode              (default: active)')
def scan(target, output, mode):
    """
    \b
    Run full recon + intelligence pipeline on a target.
    \b
    SCAN MODES:
      passive     No active scanning. Subdomain + live hosts + fingerprint only.
      stealth     Low-noise. Ports + nuclei + takeover. No fuzzing.
      active      Full scan. All 16+ modules. Balanced speed. (default)
      aggressive  Maximum coverage. All modules. High rate limits.
    \b
    EXAMPLES:
      python main.py scan --target hackerone.com
      python main.py scan --target hackerone.com --mode stealth
      python main.py scan --target hackerone.com --output /tmp/results
    \b
    MODULES (active mode):
      subfinder   nmap      ffuf      whatweb   wafw00f
      subjack     nuclei    nvd-api   js-secrets  cors
    \b
    INTELLIGENCE:
      Risk Engine   CVSS-style scoring 0-10 per host
      Attack Chains Step-by-step exploitation paths
      Exploitable   Hosts with port + CVE/secret/CORS + score >= 4.0
    """
    asyncio.run(_scan(target, output, mode))

async def _scan(target, output, mode="active"):
    cfg = SCAN_MODES[mode]

    output_dir = os.path.join(output, target)
    raw_dir    = os.path.join(output_dir, "raw")
    temp_dir   = os.path.join(output_dir, "temp")
    fuzz_dir   = os.path.join(raw_dir, "fuzzing")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(raw_dir,    exist_ok=True)
    os.makedirs(temp_dir,   exist_ok=True)
    os.makedirs(fuzz_dir,   exist_ok=True)

    logger      = create_logger(target, output_dir)
    db_path     = init_db(output_dir)
    scan_record = create_scan(target)

    blank()
    console.print(Rule(characters="─", style="red"))
    blank()
    console.print(f"  [bold white]Target  [/bold white]  [cyan]{target}[/cyan]")
    console.print(f"  [bold white]Output  [/bold white]  [dim]{output_dir}[/dim]")
    console.print(f"  [bold white]Mode    [/bold white]  [yellow]{mode.upper()}[/yellow]  [dim]·  {cfg['description']}[/dim]")
    blank()
    console.print(Rule(characters="─", style="red"))

    logger.info("scanner", "pipeline_started", {"output_dir": output_dir, "mode": mode})

    # ── Phase 1 ────────────────────────────────────────
    phase("1", "Subdomain Enumeration")
    t0 = time.time()
    subdomains = await run_async(run_subfinder, target, raw_dir, temp_dir)
    if not subdomains:
        warn("No subdomains found — using target directly")
        subdomains = [target]
    else:
        success(f"Found [cyan]{len(subdomains)}[/cyan] subdomains")
    for sub in subdomains:
        save_finding(scan_record, "subdomain", "info", sub, data={"subdomain": sub})
    logger.metric("subdomain", (time.time() - t0) * 1000, len(subdomains))

    # ── Phase 2 ────────────────────────────────────────
    phase("2", "Live Host Detection")
    t0 = time.time()
    live_hosts = await run_async(run_httpx, subdomains, target, raw_dir, temp_dir)
    if not live_hosts:
        warn("No live hosts found — using target directly")
        live_hosts = [f"http://{target}"]
        logger.warning("livehosts", "no_hosts_found", {"fallback": f"http://{target}"})
    else:
        success(f"Found [cyan]{len(live_hosts)}[/cyan] live hosts")
    for host in live_hosts:
        save_finding(scan_record, "livehosts", "info", host, data={"url": host})
    logger.metric("livehosts", (time.time() - t0) * 1000, len(live_hosts))

    # ── Phase 3 ────────────────────────────────────────
    phase("3", "Parallel Recon")
    active_mods = ["whatweb", "wafw00f", "js_secrets", "cors"]
    if cfg["run_ports"]:    active_mods.append("nmap")
    if cfg["run_fuzz"]:     active_mods.append("ffuf")
    if cfg["run_takeover"]: active_mods.append("subjack")
    info(f"Modules  →  {' · '.join(active_mods)}")
    blank()

    t0 = time.time()
    parallel_tasks = [
        run_async(run_whatweb,    live_hosts, target, raw_dir),
        run_async(run_wafw00f,    live_hosts, target, raw_dir),
        run_async(run_js_secrets, live_hosts, target, raw_dir),
        run_async(run_cors,       live_hosts, target, raw_dir),
    ]
    if cfg["run_ports"]:
        parallel_tasks.append(run_async(run_nmap, live_hosts, target, raw_dir))
    if cfg["run_fuzz"]:
        parallel_tasks.append(run_async(run_ffuf, live_hosts, target, fuzz_dir))
    if cfg["run_takeover"]:
        parallel_tasks.append(run_async(run_subjack, subdomains, target, raw_dir, temp_dir))

    results = await run_parallel(parallel_tasks)

    tech_results     = results[0] if not isinstance(results[0], Exception) else {}
    waf_results      = results[1] if not isinstance(results[1], Exception) else {}
    js_results       = results[2] if not isinstance(results[2], Exception) else {}
    cors_results     = results[3] if not isinstance(results[3], Exception) else {}

    idx              = 4
    port_results     = {}
    fuzz_results     = {}
    takeover_results = {}

    if cfg["run_ports"]:
        port_results = results[idx] if not isinstance(results[idx], Exception) else {}
        idx += 1
    if cfg["run_fuzz"]:
        fuzz_results = results[idx] if not isinstance(results[idx], Exception) else {}
        idx += 1
    if cfg["run_takeover"]:
        takeover_results = results[idx] if not isinstance(results[idx], Exception) else {}

    logger.metric("parallel_recon", (time.time() - t0) * 1000,
                  sum(len(v) for v in port_results.values()))

    blank()
    divider()
    blank()
    success(f"Open Ports   →  [cyan]{sum(len(v) for v in port_results.values())}[/cyan]  open")
    success(f"JS Secrets   →  [cyan]{sum(len(v) for v in js_results.values())}[/cyan]  detected")
    success(f"CORS Issues  →  [cyan]{sum(len(v) for v in cors_results.values())}[/cyan]  found")
    blank()

    for host, ports in port_results.items():
        for port in ports:
            save_finding(scan_record, "portscan", "info",
                f"{host}:{port['port']}/{port['service']}",
                data={"host": host, "port": port["port"], "service": port["service"]})
    for host, secrets in js_results.items():
        for secret in secrets:
            save_finding(scan_record, "js_secrets", "high",
                secret.get("type", "unknown"),
                description=secret.get("match", ""),
                data=secret)
    for host, findings in cors_results.items():
        for f in findings:
            save_finding(scan_record, "cors", f.get("severity", "high"),
                f.get("issue", "CORS Misconfiguration"),
                description=f.get("acao", ""),
                data=f)

    # ── Phase 4 ────────────────────────────────────────
    phase("4", "Vulnerability Scanning")
    vuln_results = {}
    cve_results  = {}
    total_vulns  = 0
    total_cves   = 0

    if cfg["run_nuclei"]:
        info("Modules  →  nuclei · cve_lookup")
        blank()
        t0       = time.time()
        vuln_cve = await run_parallel([
            run_async(run_nuclei,     live_hosts, target, raw_dir, temp_dir),
            run_async(run_cve_lookup, tech_results, port_results, target, raw_dir),
        ])
        vuln_results = vuln_cve[0] if not isinstance(vuln_cve[0], Exception) else {}
        cve_results  = vuln_cve[1] if not isinstance(vuln_cve[1], Exception) else {}
        total_vulns  = sum(len(v) for v in vuln_results.values())
        total_cves   = sum(len(v) for v in cve_results.values())
        logger.metric("vuln_scan", (time.time() - t0) * 1000, total_vulns)
        logger.info("cve_lookup", "lookup_complete", {"cves_found": total_cves})
        blank()
        divider()
        blank()
        vuln_color = "red"    if total_vulns > 0 else "dim"
        cve_color  = "yellow" if total_cves  > 0 else "dim"
        success(f"Vulns Found  →  [{vuln_color}]{total_vulns}[/{vuln_color}]  nuclei")
        success(f"CVEs Found   →  [{cve_color}]{total_cves}[/{cve_color}]  mapped")
        blank()
        for sev, vulns in vuln_results.items():
            for v in vulns:
                save_finding(scan_record, "nuclei", sev,
                    v.get("name", "unknown"),
                    description=v.get("matched", ""),
                    data=v)
        for tech, cves in cve_results.items():
            for cve in cves:
                save_finding(scan_record, "cve", cve.get("severity", "info").lower(),
                    cve.get("id", "unknown"),
                    description=cve.get("description", ""),
                    data=cve)
    else:
        warn(f"Skipped in [{mode}] mode")
        blank()

    # ── Phase 4.5 ──────────────────────────────────────
    phase("4.5", "Risk Correlation & Attack Chains")
    t0 = time.time()

    normalizer   = Normalizer()
    all_findings = normalizer.normalize_all(
        port_results = port_results,
        vuln_results = vuln_results,
        cve_results  = cve_results,
        js_results   = js_results,
        cors_results = cors_results,
        waf_results  = waf_results,
        live_hosts   = live_hosts
    )

    risk_chains, attack_paths = RiskEngine(all_findings).run()

    logger.metric("risk_engine", (time.time() - t0) * 1000, len(risk_chains))
    logger.info("risk_engine", "scoring_complete", {
        "total_findings": len(all_findings),
        "chains":         len(risk_chains),
        "top_score":      risk_chains[0].risk_score if risk_chains else 0.0
    })

    info(f"Analyzed [bold]{len(all_findings)}[/bold] findings across [bold]{len(risk_chains)}[/bold] hosts")
    blank()

    console.print(f"  [bold white]Top Risk Hosts[/bold white]")
    blank()
    for chain in risk_chains[:3]:
        if chain.risk_score >= 7.0:
            color = "bold red"
            icon  = "🔴"
        elif chain.risk_score >= 5.0:
            color = "yellow"
            icon  = "🟡"
        else:
            color = "dim white"
            icon  = "🟢"
        console.print(f"  {icon}  [{color}]{chain.host}[/]")
        console.print(f"     [dim]Score   {chain.risk_score}  ·  {', '.join(chain.modifiers_applied)}[/dim]")
        console.print(f"     [dim]{chain.recommendation}[/dim]")
        blank()

    exploitable = [p for p in attack_paths if p.exploitable]
    divider()
    blank()

    if exploitable:
        console.print(f"  [bold red]⚠  {len(exploitable)} EXPLOITABLE PATH(S) DETECTED[/bold red]")
        blank()
        for p in exploitable[:3]:
            # Truncate chain display to 6 steps max
            display_steps = p.steps[:6]
            suffix = f" → (+{len(p.steps) - 6} more)" if len(p.steps) > 6 else ""
            console.print(f"  [red]▶  {p.host}[/red]")
            console.print(f"     [dim]Chain   {' → '.join(display_steps)}{suffix}[/dim]")
            console.print(f"     [dim]Impact  {p.impact}[/dim]")
            console.print(f"     [dim]Score   {p.risk_score}[/dim]")
            blank()
    else:
        info("No directly exploitable paths found")
        blank()

    risk_file = f"{raw_dir}/risk_chains.json"
    with open(risk_file, "w") as f:
        json.dump({
            "chains": [{
                "host":              c.host,
                "risk_score":        c.risk_score,
                "modifiers_applied": c.modifiers_applied,
                "recommendation":    c.recommendation,
                "finding_count":     len(c.findings)
            } for c in risk_chains],
            "attack_paths": [{
                "chain_id":    p.chain_id,
                "host":        p.host,
                "steps":       p.steps,
                "severity":    p.severity,
                "impact":      p.impact,
                "risk_score":  p.risk_score,
                "exploitable": p.exploitable
            } for p in attack_paths]
        }, f, indent=2)
    success(f"Risk chains saved  →  {risk_file}")

    # ── Phase 5 ────────────────────────────────────────
    phase("5", "Saving Results & Generating Reports")

    complete_scan(scan_record)
    success("Scan saved to database")

    generate_diff(target, output_dir)
    success("Diff report generated")

    generate_report(target, output_dir, subdomains, live_hosts,
                    port_results, waf_results, vuln_results, cve_results,
                    risk_chains)
    success("HTML report generated")

    export_pdf(target, output_dir)
    success("PDF report generated")

    logger.info("scanner", "pipeline_complete", {
        "mode":        mode,
        "subdomains":  len(subdomains),
        "live_hosts":  len(live_hosts),
        "total_vulns": total_vulns,
        "total_cves":  total_cves,
        "top_risk":    risk_chains[0].risk_score if risk_chains else 0.0
    })

    blank()
    console.print(Rule(characters="─", style="red"))
    blank()
    console.print("  [bold red]SCAN COMPLETE[/bold red]  [dim]🐰  BugzBunny v2.1.0[/dim]")
    blank()
    divider()
    blank()

    table = Table(
        show_header = False,
        box         = None,
        padding     = (0, 2),
        show_edge   = False,
        show_footer = False,
    )
    table.add_column(style="dim",       width=14, justify="left")
    table.add_column(style="bold cyan", width=36, justify="left")
    table.add_column(style="dim",       width=12, justify="left")

    table.add_row("Target",      target,                                                  "")
    table.add_row("Mode",        mode.upper(),                                            cfg["description"])
    table.add_row("─" * 12,      "",                                                      "")
    table.add_row("Subdomains",  str(len(subdomains)),                                    "discovered")
    table.add_row("Live Hosts",  str(len(live_hosts)),                                    "responding")
    table.add_row("Open Ports",  str(sum(len(v) for v in port_results.values())),         "exposed")
    table.add_row("JS Secrets",  str(sum(len(v) for v in js_results.values())),           "detected")
    table.add_row("CORS Issues", str(sum(len(v) for v in cors_results.values())),         "found")
    table.add_row("Vulns Found", str(total_vulns),                                        "nuclei")
    table.add_row("CVEs Found",  str(total_cves),                                         "mapped")
    table.add_row("Risk Score",  str(risk_chains[0].risk_score if risk_chains else 0.0),  "/ 10.0")
    table.add_row("Exploitable", str(len(exploitable)),                                   "paths")
    table.add_row("─" * 12,      "",                                                      "")
    table.add_row("Report",      f"{output_dir}/{target}_report.html",                    "")
    table.add_row("Log",         logger.log_file,                                         "")

    console.print(table)
    blank()
    console.print(Rule(characters="─", style="red"))
    blank()

if __name__ == '__main__':
    cli()
