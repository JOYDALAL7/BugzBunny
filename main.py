import click
import os
import asyncio
import json
import time
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich.panel import Panel
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

# ── Scan Mode Configs ──────────────────────────────────
SCAN_MODES = {
    "passive": {
        "description":  "Subdomain + live hosts + fingerprint only. No active scanning.",
        "run_ports":    False,
        "run_fuzz":     False,
        "run_nuclei":   False,
        "run_takeover": False,
    },
    "stealth": {
        "description":  "Low-noise scan. Slow rate limits, no fuzzing.",
        "run_ports":    True,
        "run_fuzz":     False,
        "run_nuclei":   True,
        "run_takeover": True,
    },
    "active": {
        "description":  "Full scan. All modules. Balanced speed.",
        "run_ports":    True,
        "run_fuzz":     True,
        "run_nuclei":   True,
        "run_takeover": True,
    },
    "aggressive": {
        "description":  "Maximum coverage. All modules. High rate limits.",
        "run_ports":    True,
        "run_fuzz":     True,
        "run_nuclei":   True,
        "run_takeover": True,
    },
}

def phase(number: str, title: str):
    console.print()
    console.print()
    console.print(f"  [bold red]PHASE {number}[/bold red]")
    console.print(f"  [bold white]{title}[/bold white]")
    console.print(f"  [dim]{'─' * 40}[/dim]")
    console.print()

def info(msg: str):
    console.print(f"  [dim]›[/dim] {msg}")

def success(msg: str):
    console.print(f"  [bold green]✓[/bold green]  {msg}")

def warning(msg: str):
    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")

def finding(msg: str):
    console.print(f"  [bold red]![/bold red]  {msg}")

@click.group()
def cli():
    """BugzBunny - Hop. Hunt. Hack."""
    show_banner()

@cli.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--output', '-o', default='reports', help='Output directory')
@click.option('--mode',   '-m',
              default='active',
              type=click.Choice(['passive', 'stealth', 'active', 'aggressive'],
                                case_sensitive=False),
              help='Scan mode: passive | stealth | active | aggressive')
def scan(target, output, mode):
    """Run full recon pipeline on a target"""
    asyncio.run(_scan(target, output, mode))

async def _scan(target, output, mode="active"):
    """Async scan pipeline"""

    cfg = SCAN_MODES[mode]

    # Folder structure
    output_dir = os.path.join(output, target)
    raw_dir    = os.path.join(output_dir, "raw")
    temp_dir   = os.path.join(output_dir, "temp")
    fuzz_dir   = os.path.join(raw_dir, "fuzzing")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(raw_dir,    exist_ok=True)
    os.makedirs(temp_dir,   exist_ok=True)
    os.makedirs(fuzz_dir,   exist_ok=True)

    logger = create_logger(target, output_dir)

    # Scan header
    console.print()
    console.print(Rule(characters="─", style="red"))
    console.print()
    console.print(f"  [bold white]Target  [/bold white]  [dim]→[/dim]  [bold cyan]{target}[/bold cyan]")
    db_path     = init_db(output_dir)
    scan_record = create_scan(target)
    console.print(f"  [bold white]Output  [/bold white]  [dim]→[/dim]  [dim]{output_dir}[/dim]")
    console.print(f"  [bold white]Database[/bold white]  [dim]→[/dim]  [dim]{db_path}[/dim]")
    console.print(f"  [bold white]Mode    [/bold white]  [dim]→[/dim]  [bold yellow]{mode.upper()}[/bold yellow]  [dim]{cfg['description']}[/dim]")
    console.print()
    console.print(Rule(characters="─", style="red"))

    logger.info("scanner", "pipeline_started", {"output_dir": output_dir, "mode": mode})

    # ──────────────────────────────────────────
    # Phase 1: Subdomain Enumeration
    # ──────────────────────────────────────────
    phase("1", "Subdomain Enumeration")
    t0 = time.time()

    subdomains = await run_async(run_subfinder, target, raw_dir, temp_dir, mode)
    if not subdomains:
        warning("No subdomains found — using target directly")
        subdomains = [target]
    else:
        success(f"Found [bold cyan]{len(subdomains)}[/bold cyan] subdomains")

    for sub in subdomains:
        save_finding(scan_record, "subdomain", "info", sub, data={"subdomain": sub})

    logger.metric("subdomain", (time.time() - t0) * 1000, len(subdomains))

    # ──────────────────────────────────────────
    # Phase 2: Live Host Detection
    # ──────────────────────────────────────────
    phase("2", "Live Host Detection")
    t0 = time.time()

    live_hosts = await run_async(run_httpx, subdomains, target, raw_dir, temp_dir)
    if not live_hosts:
        warning("No live hosts found — using target directly")
        live_hosts = [f"http://{target}"]
        logger.warning("livehosts", "no_hosts_found", {"fallback": f"http://{target}"})
    else:
        success(f"Found [bold cyan]{len(live_hosts)}[/bold cyan] live hosts")

    for host in live_hosts:
        save_finding(scan_record, "livehosts", "info", host, data={"url": host})

    logger.metric("livehosts", (time.time() - t0) * 1000, len(live_hosts))

    # ──────────────────────────────────────────
    # Phase 3: Parallel Recon
    # ──────────────────────────────────────────
    phase("3", "Parallel Recon")

    active_modules = ["whatweb", "wafw00f", "js_secrets", "cors"]
    if cfg["run_ports"]:    active_modules.append("nmap")
    if cfg["run_fuzz"]:     active_modules.append("ffuf")
    if cfg["run_takeover"]: active_modules.append("subjack")

    info(f"Modules: {' · '.join(active_modules)}")
    console.print()

    t0 = time.time()

    # Build parallel tasks — pass mode to ALL modules
    parallel_tasks = []

    if cfg["run_ports"]:
        parallel_tasks.append(run_async(run_nmap, live_hosts, target, raw_dir, mode))

    parallel_tasks += [
        run_async(run_whatweb,    live_hosts, target, raw_dir,  mode),
        run_async(run_wafw00f,    live_hosts, target, raw_dir,  mode),
        run_async(run_js_secrets, live_hosts, target, raw_dir,  mode),
        run_async(run_cors,       live_hosts, target, raw_dir,  mode),
    ]

    if cfg["run_fuzz"]:
        parallel_tasks.append(run_async(run_ffuf, live_hosts, target, fuzz_dir, mode))
    if cfg["run_takeover"]:
        parallel_tasks.append(run_async(run_subjack, subdomains, target, raw_dir, temp_dir, mode))

    results = await run_parallel(parallel_tasks)

    # ── Parse results ─────────────────────────
    idx          = 0
    port_results = {}
    fuzz_results = {}
    takeover_results = {}

    if cfg["run_ports"]:
        port_results = results[idx] if not isinstance(results[idx], Exception) else {}
        idx += 1

    tech_results  = results[idx]     if not isinstance(results[idx],     Exception) else {}
    waf_results   = results[idx + 1] if not isinstance(results[idx + 1], Exception) else {}
    js_results    = results[idx + 2] if not isinstance(results[idx + 2], Exception) else {}
    cors_results  = results[idx + 3] if not isinstance(results[idx + 3], Exception) else {}
    idx += 4

    if cfg["run_fuzz"]:
        fuzz_results = results[idx] if not isinstance(results[idx], Exception) else {}
        idx += 1
    if cfg["run_takeover"]:
        takeover_results = results[idx] if not isinstance(results[idx], Exception) else {}

    logger.metric("parallel_recon", (time.time() - t0) * 1000,
                  sum(len(v) for v in port_results.values()))

    console.print()
    console.print(f"  [dim]{'─' * 40}[/dim]")
    console.print()
    success(f"Ports       [bold cyan]{sum(len(v) for v in port_results.values())}[/bold cyan]  open")
    success(f"JS Secrets  [bold cyan]{sum(len(v) for v in js_results.values())}[/bold cyan]  detected")
    success(f"CORS Issues [bold cyan]{sum(len(v) for v in cors_results.values())}[/bold cyan]  found")
    console.print()

    # Save findings
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

    # ──────────────────────────────────────────
    # Phase 4: Vulnerability Scanning
    # ──────────────────────────────────────────
    phase("4", "Vulnerability Scanning")

    vuln_results = {}
    cve_results  = {}
    total_vulns  = 0
    total_cves   = 0

    if cfg["run_nuclei"]:
        info(f"Modules: nuclei [{mode}] · cve_lookup")
        console.print()

        t0 = time.time()
        vuln_cve = await run_parallel([
            run_async(run_nuclei,     live_hosts, target, raw_dir, temp_dir, mode),
            run_async(run_cve_lookup, tech_results, port_results, target, raw_dir),
        ])

        vuln_results = vuln_cve[0] if not isinstance(vuln_cve[0], Exception) else {}
        cve_results  = vuln_cve[1] if not isinstance(vuln_cve[1], Exception) else {}
        total_vulns  = sum(len(v) for v in vuln_results.values())
        total_cves   = sum(len(v) for v in cve_results.values())

        logger.metric("vuln_scan", (time.time() - t0) * 1000, total_vulns)
        logger.info("cve_lookup", "lookup_complete", {"cves_found": total_cves})

        console.print()
        console.print(f"  [dim]{'─' * 40}[/dim]")
        console.print()
        success(f"Vulns Found  [bold {'red' if total_vulns > 0 else 'dim'}]{total_vulns}[/]")
        success(f"CVEs Found   [bold {'yellow' if total_cves > 0 else 'dim'}]{total_cves}[/]")
        console.print()

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
        info(f"Vulnerability scanning skipped in {mode} mode")
        console.print()

    # ──────────────────────────────────────────
    # Phase 4.5: Risk Correlation Engine
    # ──────────────────────────────────────────
    phase("4.5", "Risk Correlation & Attack Chains")
    t0 = time.time()

    normalizer   = Normalizer()
    all_findings = normalizer.normalize_all(
        port_results = port_results,
        vuln_results = vuln_results,
        cve_results  = cve_results,
        js_results   = js_results,
        cors_results = cors_results,
        waf_results  = waf_results
    )

    risk_chains, attack_paths = RiskEngine(all_findings).run()

    logger.metric("risk_engine", (time.time() - t0) * 1000, len(risk_chains))
    logger.info("risk_engine", "scoring_complete", {
        "total_findings": len(all_findings),
        "chains":         len(risk_chains),
        "top_score":      risk_chains[0].risk_score if risk_chains else 0.0
    })

    info(f"Analyzed [bold]{len(all_findings)}[/bold] findings across [bold]{len(risk_chains)}[/bold] hosts")
    console.print()

    # Top risk chains
    console.print(f"  [bold white]Top Risk Hosts:[/bold white]")
    console.print()
    for chain in risk_chains[:3]:
        if chain.risk_score >= 7.0:
            color = "bold red"
            icon  = "🔴"
        elif chain.risk_score >= 5.0:
            color = "yellow"
            icon  = "🟡"
        else:
            color = "dim green"
            icon  = "🟢"
        console.print(f"  {icon}  [{color}]{chain.host}[/]")
        console.print(f"      [dim]Score : {chain.risk_score}   Flags : {', '.join(chain.modifiers_applied)}[/dim]")
        console.print(f"      [dim]{chain.recommendation}[/dim]")
        console.print()

    # Exploitable paths
    exploitable = [p for p in attack_paths if p.exploitable]
    console.print()
    console.print(f"  [dim]{'─' * 40}[/dim]")
    console.print()

    if exploitable:
        console.print(f"  [bold red]⚠   {len(exploitable)} EXPLOITABLE PATH(S) DETECTED[/bold red]")
        console.print()
        for p in exploitable[:3]:
            console.print(f"  [bold red]  ►  {p.host}[/bold red]")
            console.print(f"      [dim]Chain :[/dim]  {' → '.join(p.steps)}")
            console.print(f"      [dim]Impact:[/dim]  {p.impact}")
            console.print(f"      [dim]Score :[/dim]  {p.risk_score}")
            console.print()
    else:
        info("No directly exploitable paths found")

    # Save risk chains + attack paths
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
    success(f"Risk chains + attack paths saved → {risk_file}")

    # ──────────────────────────────────────────
    # Phase 5: Save & Report
    # ──────────────────────────────────────────
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

    # ── Final Summary ──────────────────────────
    console.print()
    console.print(Rule(characters="─", style="red"))
    console.print()
    console.print("  [bold red]SCAN COMPLETE  🐰[/bold red]")
    console.print()

    summary = Table.grid(padding=(0, 3))
    summary.add_column(style="bold white", justify="right")
    summary.add_column(style="bold cyan",  justify="left")
    summary.add_column(style="dim",        justify="left")

    summary.add_row("Target",      target,                                            "")
    summary.add_row("Mode",        mode.upper(),                                      "")
    summary.add_row("Subdomains",  str(len(subdomains)),                              "discovered")
    summary.add_row("Live Hosts",  str(len(live_hosts)),                              "responding")
    summary.add_row("Open Ports",  str(sum(len(v) for v in port_results.values())),   "exposed")
    summary.add_row("JS Secrets",  str(sum(len(v) for v in js_results.values())),     "detected")
    summary.add_row("CORS Issues", str(sum(len(v) for v in cors_results.values())),   "found")
    summary.add_row("Vulns Found", str(total_vulns),                                  "nuclei")
    summary.add_row("CVEs Found",  str(total_cves),                                   "mapped")
    summary.add_row("Risk Score",  str(risk_chains[0].risk_score if risk_chains else 0.0), "/ 10.0")
    summary.add_row("Exploitable", str(len(exploitable)),                             "paths")
    summary.add_row("Log File",    logger.log_file,                                   "")
    summary.add_row("Report",      f"{output_dir}/{target}_report.html",              "")

    console.print(summary, justify="center")
    console.print()
    console.print(Rule(characters="─", style="red"))
    console.print()

if __name__ == '__main__':
    cli()
