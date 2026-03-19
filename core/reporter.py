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
    <title>BugzBunny Report - {{ target }}</title>
    <style>
        @page {
            margin: 2cm;
            size: A4;
            @bottom-center {
                content: "BugzBunny v2.0.0 | Hop. Hunt. Hack. | Page " counter(page);
                font-size: 9px;
                color: #999;
            }
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #ffffff; color: #1a1a1a; font-size: 11px; }

        /* ── Cover Header ── */
        .header {
            background: #1a1a2e;
            color: white;
            padding: 30px 40px;
            border-bottom: 4px solid #e94560;
            margin-bottom: 20px;
        }
        .header h1 { font-size: 24px; color: #e94560; margin-bottom: 5px; }
        .header .meta { color: #aaa; font-size: 11px; }
        .header .meta span { color: white; font-weight: bold; }

        /* ── Stats Row ── */
        .stats {
            display: flex;
            gap: 10px;
            margin: 0 0 20px 0;
            flex-wrap: wrap;
        }
        .stat-card {
            flex: 1;
            min-width: 80px;
            background: #f8f8f8;
            border-left: 4px solid #e94560;
            border-radius: 4px;
            padding: 12px 15px;
        }
        .stat-card .num { font-size: 22px; font-weight: bold; color: #e94560; }
        .stat-card .label { font-size: 9px; color: #666; margin-top: 2px; }

        /* ── Section ── */
        .section { margin-bottom: 20px; page-break-inside: avoid; }
        .section-title {
            font-size: 13px;
            font-weight: bold;
            color: #1a1a2e;
            border-bottom: 2px solid #e94560;
            padding-bottom: 5px;
            margin-bottom: 10px;
        }

        /* ── Tables ── */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 10px;
            table-layout: fixed;
        }
        th {
            background: #1a1a2e;
            color: #e94560;
            padding: 8px 10px;
            text-align: left;
            font-size: 10px;
        }
        td {
            padding: 7px 10px;
            border-bottom: 1px solid #eee;
            word-wrap: break-word;
            overflow-wrap: break-word;
            vertical-align: top;
        }
        tr:nth-child(even) { background: #f9f9f9; }

        /* ── Badges ── */
        .badge {
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 9px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .critical { background: #ffe0e0; color: #cc0000; border: 1px solid #cc0000; }
        .high     { background: #fff0e0; color: #cc6600; border: 1px solid #cc6600; }
        .medium   { background: #fffbe0; color: #997700; border: 1px solid #997700; }
        .low      { background: #e0ffe0; color: #006600; border: 1px solid #006600; }

        /* ── Summary Box ── */
        .summary-box {
            background: #f0f0f0;
            border-left: 4px solid #1a1a2e;
            padding: 10px 15px;
            margin-bottom: 20px;
            font-size: 10px;
        }
        .summary-box p { margin: 3px 0; }
        .summary-box strong { color: #1a1a2e; }

        /* ── Footer ── */
        .footer {
            text-align: center;
            padding: 15px;
            color: #999;
            border-top: 1px solid #ddd;
            margin-top: 20px;
            font-size: 9px;
        }

        .page-break { page-break-before: always; }
    </style>
</head>
<body>

    <!-- Header -->
    <div class="header">
        <h1>🐰 BugzBunny Security Report</h1>
        <div class="meta">
            Target: <span>{{ target }}</span> &nbsp;|&nbsp;
            Generated: <span>{{ timestamp }}</span> &nbsp;|&nbsp;
            Tool: <span>BugzBunny v2.0.0</span>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats">
        <div class="stat-card">
            <div class="num">{{ subdomains|length }}</div>
            <div class="label">Subdomains</div>
        </div>
        <div class="stat-card">
            <div class="num">{{ live_hosts|length }}</div>
            <div class="label">Live Hosts</div>
        </div>
        <div class="stat-card">
            <div class="num">{{ total_ports }}</div>
            <div class="label">Open Ports</div>
        </div>
        <div class="stat-card">
            <div class="num">{{ total_vulns }}</div>
            <div class="label">Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="num">{{ total_cves }}</div>
            <div class="label">CVEs Found</div>
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <div class="section-title">📋 Executive Summary</div>
        <div class="summary-box">
            <p><strong>Target:</strong> {{ target }}</p>
            <p><strong>Scan Date:</strong> {{ timestamp }}</p>
            <p><strong>Subdomains Discovered:</strong> {{ subdomains|length }}</p>
            <p><strong>Live Hosts:</strong> {{ live_hosts|length }}</p>
            <p><strong>Open Ports:</strong> {{ total_ports }}</p>
            <p><strong>Vulnerabilities Found:</strong> {{ total_vulns }}</p>
            <p><strong>CVEs Identified:</strong> {{ total_cves }}</p>
        </div>
    </div>

    <!-- Subdomains -->
    <div class="section">
        <div class="section-title">📡 Subdomain Enumeration</div>
        <table>
            <tr><th style="width:100%">Subdomain</th></tr>
            {% for sub in subdomains %}
            <tr><td>{{ sub }}</td></tr>
            {% endfor %}
        </table>
    </div>

    <!-- Live Hosts -->
    <div class="section">
        <div class="section-title">🌐 Live Hosts</div>
        <table>
            <colgroup>
                <col style="width:55%">
                <col style="width:15%">
                <col style="width:30%">
            </colgroup>
            <tr><th>URL</th><th>Status</th><th>WAF</th></tr>
            {% for host in live_hosts %}
            <tr>
                <td>{{ host.split()[0] }}</td>
                <td>{{ host.split()[1] if host.split()|length > 1 else 'N/A' }}</td>
                <td>{{ waf.get(host.split()[0], 'Not Detected') }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <!-- Port Scan -->
    <div class="section">
        <div class="section-title">🔌 Open Ports</div>
        <table>
            <colgroup>
                <col style="width:60%">
                <col style="width:15%">
                <col style="width:25%">
            </colgroup>
            <tr><th>Host</th><th>Port</th><th>Service</th></tr>
            {% for host, ports in port_scan.items() %}
                {% for port in ports %}
                <tr>
                    <td>{{ host }}</td>
                    <td>{{ port.port }}</td>
                    <td>{{ port.service }}</td>
                </tr>
                {% endfor %}
            {% endfor %}
        </table>
    </div>

    <!-- Vulnerabilities -->
    <div class="section page-break">
        <div class="section-title">⚠️ Vulnerabilities</div>
        <table>
            <colgroup>
                <col style="width:12%">
                <col style="width:28%">
                <col style="width:30%">
                <col style="width:30%">
            </colgroup>
            <tr><th>Severity</th><th>Name</th><th>Host</th><th>Matched At</th></tr>
            {% set has_vulns = false %}
            {% for sev in ['critical', 'high', 'medium', 'low'] %}
                {% for vuln in vulnerabilities.get(sev, []) %}
                {% set has_vulns = true %}
                <tr>
                    <td><span class="badge {{ sev }}">{{ sev }}</span></td>
                    <td>{{ vuln.name }}</td>
                    <td>{{ vuln.host }}</td>
                    <td>{{ vuln.matched }}</td>
                </tr>
                {% endfor %}
            {% endfor %}
            {% if total_vulns == 0 %}
            <tr><td colspan="4" style="text-align:center; color:#999; padding:15px;">No vulnerabilities found</td></tr>
            {% endif %}
        </table>
    </div>

    <!-- CVEs -->
    <div class="section">
        <div class="section-title">🔍 CVE Findings</div>
        <table>
            <colgroup>
                <col style="width:14%">
                <col style="width:17%">
                <col style="width:7%">
                <col style="width:10%">
                <col style="width:52%">
            </colgroup>
            <tr><th>Technology</th><th>CVE ID</th><th>Score</th><th>Severity</th><th>Description</th></tr>
            {% for tech, cves in cve_data.items() %}
                {% for cve in cves %}
                <tr>
                    <td>{{ tech }}</td>
                    <td>{{ cve.id }}</td>
                    <td>{{ cve.score }}</td>
                    <td><span class="badge {{ cve.severity.lower() if cve.severity != 'N/A' else 'low' }}">{{ cve.severity }}</span></td>
                    <td>{{ cve.description[:150] }}...</td>
                </tr>
                {% endfor %}
            {% endfor %}
            {% if total_cves == 0 %}
            <tr><td colspan="5" style="text-align:center; color:#999; padding:15px;">No CVEs found</td></tr>
            {% endif %}
        </table>
    </div>

    <div class="footer">
        Generated by BugzBunny v2.0.0 | Hop. Hunt. Hack. | For authorized testing only | {{ timestamp }}
    </div>

</body>
</html>
"""

def generate_report(target: str, output_dir: str, subdomains: list,
                    live_hosts: list, port_results: dict, waf_results: dict,
                    vuln_results: dict, cve_results: dict) -> str:

    total_ports = sum(len(v) for v in port_results.values())
    total_vulns = sum(len(v) for v in vuln_results.values())
    total_cves  = sum(len(v) for v in cve_results.values())

    template = Template(HTML_TEMPLATE)
    html = template.render(
        target=target,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        subdomains=subdomains,
        live_hosts=live_hosts,
        port_scan=port_results,
        waf=waf_results,
        vulnerabilities=vuln_results,
        cve_data=cve_results,
        total_ports=total_ports,
        total_vulns=total_vulns,
        total_cves=total_cves
    )

    report_file = f"{output_dir}/{target}_report.html"
    with open(report_file, "w") as f:
        f.write(html)

    console.print(f"[bold green][+] HTML Report generated → {report_file}[/]")
    return report_file
