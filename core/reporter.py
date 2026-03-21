import json
import os
from datetime import datetime
from jinja2 import Template
from rich.console import Console

console = Console()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>BugzBunny Report — {{ target }}</title>
    <style>
        @page {
            margin: 1.5cm 2cm;
            size: A4;
            @bottom-right {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 8px; color: #666;
            }
            @bottom-left {
                content: "BugzBunny v2.1.0  ·  Confidential";
                font-size: 8px; color: #666;
            }
        }

        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --red:    #e94560;
            --dark:   #0f0f1a;
            --navy:   #1a1a2e;
            --navy2:  #16213e;
            --text:   #1a1a1a;
            --muted:  #666;
            --light:  #f7f7f7;
            --border: #e8e8e8;
        }

        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #fff;
            color: var(--text);
            font-size: 11px;
            line-height: 1.5;
        }

        /* ── Cover Header ─────────────────────────────── */
        .cover {
            background: var(--dark);
            padding: 40px 50px 30px;
            border-bottom: 3px solid var(--red);
            margin-bottom: 0;
        }
        .cover-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        .cover-logo {
            font-size: 28px;
            font-weight: 900;
            color: var(--red);
            letter-spacing: -0.5px;
        }
        .cover-logo span { color: #fff; }
        .cover-tagline {
            font-size: 10px;
            color: #666;
            margin-top: 3px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        .cover-badge {
            background: var(--red);
            color: #fff;
            font-size: 9px;
            font-weight: bold;
            padding: 4px 10px;
            border-radius: 2px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        .cover-target {
            margin-top: 24px;
            padding-top: 20px;
            border-top: 1px solid #2a2a3e;
        }
        .cover-target .label {
            font-size: 9px;
            color: #555;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }
        .cover-target .value {
            font-size: 20px;
            color: #fff;
            font-weight: 700;
            margin-top: 4px;
        }
        .cover-meta {
            display: flex;
            gap: 30px;
            margin-top: 16px;
        }
        .cover-meta-item .label {
            font-size: 9px;
            color: #555;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .cover-meta-item .value {
            font-size: 11px;
            color: #aaa;
            margin-top: 2px;
        }

        /* ── Stats Bar ────────────────────────────────── */
        .stats-bar {
            display: flex;
            background: var(--navy);
            border-bottom: 2px solid var(--red);
            margin-bottom: 24px;
        }
        .stat-item {
            flex: 1;
            padding: 16px 20px;
            border-right: 1px solid #2a2a3e;
            text-align: center;
        }
        .stat-item:last-child { border-right: none; }
        .stat-item .num {
            font-size: 26px;
            font-weight: 800;
            color: var(--red);
            line-height: 1;
        }
        .stat-item .num.safe  { color: #22c55e; }
        .stat-item .num.warn  { color: #f59e0b; }
        .stat-item .num.danger{ color: var(--red); }
        .stat-item .lbl {
            font-size: 8px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }

        /* ── Body wrapper ─────────────────────────────── */
        .body { padding: 0 50px; }

        /* ── Section ──────────────────────────────────── */
        .section {
            margin-bottom: 28px;
            page-break-inside: avoid;
        }
        .section-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 2px solid var(--red);
        }
        .section-header .icon {
            width: 26px; height: 26px;
            background: var(--red);
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 13px;
            flex-shrink: 0;
        }
        .section-header h2 {
            font-size: 13px;
            font-weight: 700;
            color: var(--navy);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .section-header .count {
            margin-left: auto;
            background: var(--light);
            border: 1px solid var(--border);
            font-size: 9px;
            color: var(--muted);
            padding: 2px 8px;
            border-radius: 10px;
        }

        /* ── Summary Box ──────────────────────────────── */
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1px;
            background: var(--border);
            border: 1px solid var(--border);
            border-radius: 4px;
            overflow: hidden;
            font-size: 10px;
        }
        .summary-row {
            display: flex;
            background: #fff;
            padding: 7px 12px;
        }
        .summary-row .key {
            color: var(--muted);
            width: 140px;
            flex-shrink: 0;
        }
        .summary-row .val {
            font-weight: 600;
            color: var(--text);
        }

        /* ── Risk Cards ───────────────────────────────── */
        .risk-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
        }
        .risk-card {
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
        }
        .risk-card-header {
            padding: 8px 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .risk-card-header.critical { background: #1a0000; border-bottom: 2px solid #cc0000; }
        .risk-card-header.high     { background: #1a0d00; border-bottom: 2px solid #cc6600; }
        .risk-card-header.medium   { background: #1a1a00; border-bottom: 2px solid #997700; }
        .risk-card-header.low      { background: #001a00; border-bottom: 2px solid #006600; }
        .risk-card-header .host {
            font-size: 10px;
            font-weight: 700;
            color: #fff;
            word-break: break-all;
        }
        .risk-card-header .score {
            font-size: 18px;
            font-weight: 800;
            flex-shrink: 0;
            margin-left: 8px;
        }
        .risk-card-header.critical .score { color: #ff4444; }
        .risk-card-header.high     .score { color: #ff8800; }
        .risk-card-header.medium   .score { color: #ffcc00; }
        .risk-card-header.low      .score { color: #44cc44; }
        .risk-card-body {
            padding: 8px 12px;
            background: #fafafa;
        }
        .risk-card-body .rec {
            font-size: 9px;
            color: var(--muted);
            margin-bottom: 4px;
        }
        .risk-card-body .mods {
            display: flex;
            flex-wrap: wrap;
            gap: 3px;
        }
        .mod-tag {
            font-size: 8px;
            background: var(--navy);
            color: #aaa;
            padding: 1px 5px;
            border-radius: 2px;
        }

        /* ── Tables ───────────────────────────────────── */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 10px;
            table-layout: fixed;
        }
        thead tr {
            background: var(--navy);
        }
        thead th {
            color: var(--red);
            padding: 9px 12px;
            text-align: left;
            font-size: 9px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 700;
        }
        tbody tr:nth-child(even) { background: var(--light); }
        tbody tr:hover           { background: #f0f0ff; }
        tbody td {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
            word-wrap: break-word;
            overflow-wrap: break-word;
            vertical-align: top;
        }
        .empty-row td {
            text-align: center;
            color: #bbb;
            padding: 20px;
            font-style: italic;
        }

        /* ── Badges ───────────────────────────────────── */
        .badge {
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 8px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-block;
        }
        .critical { background: #ffe0e0; color: #cc0000; border: 1px solid #ffaaaa; }
        .high     { background: #fff0e0; color: #cc5500; border: 1px solid #ffcc99; }
        .medium   { background: #fffbe0; color: #886600; border: 1px solid #ffee99; }
        .low      { background: #e8ffe8; color: #006600; border: 1px solid #99dd99; }
        .info     { background: #e0f0ff; color: #0055cc; border: 1px solid #99ccff; }

        /* ── WAF tag ──────────────────────────────────── */
        .waf-yes {
            color: #cc5500;
            font-weight: bold;
            font-size: 9px;
        }
        .waf-no {
            color: #006600;
            font-size: 9px;
        }

        /* ── Footer ───────────────────────────────────── */
        .footer {
            margin-top: 30px;
            padding: 14px 50px;
            background: var(--navy);
            border-top: 2px solid var(--red);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .footer .left {
            font-size: 9px;
            color: #555;
        }
        .footer .right {
            font-size: 9px;
            color: #444;
        }

        .page-break { page-break-before: always; }
    </style>
</head>
<body>

<!-- ── Cover ─────────────────────────────────────────── -->
<div class="cover">
    <div class="cover-top">
        <div>
            <div class="cover-logo">🐰 BugzBunny<span> Report</span></div>
            <div class="cover-tagline">Security Intelligence Platform</div>
        </div>
        <div class="cover-badge">Confidential</div>
    </div>
    <div class="cover-target">
        <div class="label">Target</div>
        <div class="value">{{ target }}</div>
    </div>
    <div class="cover-meta">
        <div class="cover-meta-item">
            <div class="label">Generated</div>
            <div class="value">{{ timestamp }}</div>
        </div>
        <div class="cover-meta-item">
            <div class="label">Tool</div>
            <div class="value">BugzBunny v2.1.0</div>
        </div>
        <div class="cover-meta-item">
            <div class="label">Classification</div>
            <div class="value">For authorized use only</div>
        </div>
    </div>
</div>

<!-- ── Stats Bar ──────────────────────────────────────── -->
<div class="stats-bar">
    <div class="stat-item">
        <div class="num">{{ subdomains|length }}</div>
        <div class="lbl">Subdomains</div>
    </div>
    <div class="stat-item">
        <div class="num">{{ live_hosts|length }}</div>
        <div class="lbl">Live Hosts</div>
    </div>
    <div class="stat-item">
        <div class="num">{{ total_ports }}</div>
        <div class="lbl">Open Ports</div>
    </div>
    <div class="stat-item">
        <div class="num {% if total_vulns > 0 %}danger{% else %}safe{% endif %}">{{ total_vulns }}</div>
        <div class="lbl">Vulns</div>
    </div>
    <div class="stat-item">
        <div class="num {% if total_cves > 0 %}warn{% else %}safe{% endif %}">{{ total_cves }}</div>
        <div class="lbl">CVEs</div>
    </div>
    <div class="stat-item">
        <div class="num {% if top_risk_score >= 7 %}danger{% elif top_risk_score >= 5 %}warn{% else %}safe{% endif %}">{{ top_risk_score }}</div>
        <div class="lbl">Risk Score</div>
    </div>
</div>

<div class="body">

<!-- ── Executive Summary ──────────────────────────────── -->
<div class="section">
    <div class="section-header">
        <div class="icon">📋</div>
        <h2>Executive Summary</h2>
    </div>
    <div class="summary-grid">
        <div class="summary-row"><span class="key">Target</span><span class="val">{{ target }}</span></div>
        <div class="summary-row"><span class="key">Scan Date</span><span class="val">{{ timestamp }}</span></div>
        <div class="summary-row"><span class="key">Subdomains Discovered</span><span class="val">{{ subdomains|length }}</span></div>
        <div class="summary-row"><span class="key">Live Hosts</span><span class="val">{{ live_hosts|length }}</span></div>
        <div class="summary-row"><span class="key">Open Ports</span><span class="val">{{ total_ports }}</span></div>
        <div class="summary-row"><span class="key">Vulnerabilities Found</span><span class="val">{{ total_vulns }}</span></div>
        <div class="summary-row"><span class="key">CVEs Identified</span><span class="val">{{ total_cves }}</span></div>
        <div class="summary-row"><span class="key">Highest Risk Score</span><span class="val">{{ top_risk_score }} / 10.0</span></div>
    </div>
</div>

<!-- ── Attack Chains ──────────────────────────────────── -->
{% if risk_chains %}
<div class="section">
    <div class="section-header">
        <div class="icon">🎯</div>
        <h2>Prioritized Attack Chains</h2>
        <span class="count">{{ risk_chains|length }} hosts analyzed</span>
    </div>
    <div class="risk-grid">
        {% for chain in risk_chains %}
        {% set sev = 'critical' if chain.risk_score >= 9 else 'high' if chain.risk_score >= 7 else 'medium' if chain.risk_score >= 5 else 'low' %}
        <div class="risk-card">
            <div class="risk-card-header {{ sev }}">
                <div class="host">{{ chain.host }}</div>
                <div class="score">{{ chain.risk_score }}</div>
            </div>
            <div class="risk-card-body">
                <div class="rec">{{ chain.recommendation }}</div>
                <div class="mods">
                    {% for mod in chain.modifiers_applied %}
                    <span class="mod-tag">{{ mod }}</span>
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
</div>
{% endif %}

<!-- ── Subdomains ─────────────────────────────────────── -->
<div class="section">
    <div class="section-header">
        <div class="icon">📡</div>
        <h2>Subdomain Enumeration</h2>
        <span class="count">{{ subdomains|length }} found</span>
    </div>
    <table>
        <thead><tr><th style="width:100%">Subdomain</th></tr></thead>
        <tbody>
        {% for sub in subdomains %}
        <tr><td>{{ sub }}</td></tr>
        {% endfor %}
        </tbody>
    </table>
</div>

<!-- ── Live Hosts ─────────────────────────────────────── -->
<div class="section">
    <div class="section-header">
        <div class="icon">🌐</div>
        <h2>Live Hosts</h2>
        <span class="count">{{ live_hosts|length }} responding</span>
    </div>
    <table>
        <colgroup>
            <col style="width:55%">
            <col style="width:15%">
            <col style="width:30%">
        </colgroup>
        <thead>
            <tr><th>URL</th><th>Status</th><th>WAF</th></tr>
        </thead>
        <tbody>
        {% for host in live_hosts %}
        {% set url = host.split()[0] %}
        {% set status = host.split()[1] if host.split()|length > 1 else 'N/A' %}
        {% set waf_val = waf.get(url, 'Not Detected') %}
        <tr>
            <td>{{ url }}</td>
            <td>{{ status }}</td>
            <td>
                {% if 'No WAF' in waf_val or 'Not Detected' in waf_val %}
                <span class="waf-no">✓ None</span>
                {% else %}
                <span class="waf-yes">⚠ {{ waf_val }}</span>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
</div>

<!-- ── Open Ports ─────────────────────────────────────── -->
<div class="section">
    <div class="section-header">
        <div class="icon">🔌</div>
        <h2>Open Ports</h2>
        <span class="count">{{ total_ports }} exposed</span>
    </div>
    <table>
        <colgroup>
            <col style="width:55%">
            <col style="width:15%">
            <col style="width:30%">
        </colgroup>
        <thead>
            <tr><th>Host</th><th>Port</th><th>Service</th></tr>
        </thead>
        <tbody>
        {% for host, ports in port_scan.items() %}
            {% for port in ports %}
            <tr>
                <td>{{ host }}</td>
                <td><strong>{{ port.port }}</strong></td>
                <td>{{ port.service }}</td>
            </tr>
            {% endfor %}
        {% endfor %}
        {% if total_ports == 0 %}
        <tr class="empty-row"><td colspan="3">No open ports found</td></tr>
        {% endif %}
        </tbody>
    </table>
</div>

<!-- ── Vulnerabilities ────────────────────────────────── -->
<div class="section page-break">
    <div class="section-header">
        <div class="icon">⚠️</div>
        <h2>Vulnerabilities</h2>
        <span class="count">{{ total_vulns }} found</span>
    </div>
    <table>
        <colgroup>
            <col style="width:11%">
            <col style="width:27%">
            <col style="width:32%">
            <col style="width:30%">
        </colgroup>
        <thead>
            <tr><th>Severity</th><th>Name</th><th>Host</th><th>Matched At</th></tr>
        </thead>
        <tbody>
        {% for sev in ['critical', 'high', 'medium', 'low'] %}
            {% for vuln in vulnerabilities.get(sev, []) %}
            <tr>
                <td><span class="badge {{ sev }}">{{ sev }}</span></td>
                <td>{{ vuln.name }}</td>
                <td>{{ vuln.host }}</td>
                <td>{{ vuln.matched }}</td>
            </tr>
            {% endfor %}
        {% endfor %}
        {% if total_vulns == 0 %}
        <tr class="empty-row"><td colspan="4">No vulnerabilities detected</td></tr>
        {% endif %}
        </tbody>
    </table>
</div>

<!-- ── CVE Findings ───────────────────────────────────── -->
<div class="section">
    <div class="section-header">
        <div class="icon">🔍</div>
        <h2>CVE Findings</h2>
        <span class="count">{{ total_cves }} mapped</span>
    </div>
    <table>
        <colgroup>
            <col style="width:13%">
            <col style="width:16%">
            <col style="width:7%">
            <col style="width:10%">
            <col style="width:54%">
        </colgroup>
        <thead>
            <tr><th>Technology</th><th>CVE ID</th><th>Score</th><th>Severity</th><th>Description</th></tr>
        </thead>
        <tbody>
        {% for tech, cves in cve_data.items() %}
            {% for cve in cves %}
            <tr>
                <td>{{ tech }}</td>
                <td><strong>{{ cve.id }}</strong></td>
                <td>{{ cve.score }}</td>
                <td><span class="badge {{ cve.severity.lower() if cve.severity != 'N/A' else 'low' }}">{{ cve.severity }}</span></td>
                <td>{{ cve.description[:160] }}…</td>
            </tr>
            {% endfor %}
        {% endfor %}
        {% if total_cves == 0 %}
        <tr class="empty-row"><td colspan="5">No CVEs identified</td></tr>
        {% endif %}
        </tbody>
    </table>
</div>

</div><!-- end .body -->

<!-- ── Footer ─────────────────────────────────────────── -->
<div class="footer">
    <div class="left">Generated by BugzBunny v2.1.0  ·  Hop. Hunt. Hack.  ·  {{ timestamp }}</div>
    <div class="right">For authorized security testing only</div>
</div>

</body>
</html>
"""

def generate_report(target: str, output_dir: str, subdomains: list,
                    live_hosts: list, port_results: dict, waf_results: dict,
                    vuln_results: dict, cve_results: dict,
                    risk_chains: list = None) -> str:

    total_ports    = sum(len(v) for v in port_results.values())
    total_vulns    = sum(len(v) for v in vuln_results.values())
    total_cves     = sum(len(v) for v in cve_results.values())
    top_risk_score = round(risk_chains[0].risk_score, 2) if risk_chains else 0.0

    template = Template(HTML_TEMPLATE)
    html = template.render(
        target          = target,
        timestamp       = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        subdomains      = subdomains,
        live_hosts      = live_hosts,
        port_scan       = port_results,
        waf             = waf_results,
        vulnerabilities = vuln_results,
        cve_data        = cve_results,
        risk_chains     = risk_chains or [],
        total_ports     = total_ports,
        total_vulns     = total_vulns,
        total_cves      = total_cves,
        top_risk_score  = top_risk_score
    )

    report_file = f"{output_dir}/{target}_report.html"
    with open(report_file, "w") as f:
        f.write(html)

    console.print(f"[bold green][+] HTML Report generated → {report_file}[/]")
    return report_file
