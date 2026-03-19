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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugzBunny Report - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; }
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 40px; border-bottom: 2px solid #e94560; }
        .header h1 { color: #e94560; font-size: 2.5em; }
        .header p { color: #888; margin-top: 5px; }
        .stats { display: flex; gap: 20px; padding: 30px 40px; flex-wrap: wrap; }
        .stat-card { background: #1a1a2e; border-radius: 10px; padding: 20px 30px; flex: 1; min-width: 150px; border-left: 4px solid #e94560; }
        .stat-card h2 { font-size: 2em; color: #e94560; }
        .stat-card p { color: #888; font-size: 0.9em; }
        .section { padding: 20px 40px; margin-bottom: 10px; }
        .section h2 { color: #e94560; border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; background: #1a1a2e; border-radius: 8px; overflow: hidden; }
        th { background: #16213e; color: #e94560; padding: 12px 15px; text-align: left; }
        td { padding: 10px 15px; border-bottom: 1px solid #222; font-size: 0.9em; }
        tr:hover { background: #16213e; }
        .badge { padding: 3px 10px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }
        .critical { background: #ff000033; color: #ff4444; }
        .high { background: #ff660033; color: #ff6600; }
        .medium { background: #ffaa0033; color: #ffaa00; }
        .low { background: #00ff0033; color: #00cc00; }
        .safe { background: #00ff0033; color: #00cc00; }
        .danger { background: #ff000033; color: #ff4444; }
        .footer { text-align: center; padding: 30px; color: #444; border-top: 1px solid #222; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐰 BugzBunny Report</h1>
        <p>Target: <strong>{{ target }}</strong> | Generated: {{ timestamp }}</p>
    </div>

    <!-- Stats -->
    <div class="stats">
        <div class="stat-card">
            <h2>{{ subdomains|length }}</h2>
            <p>Subdomains Found</p>
        </div>
        <div class="stat-card">
            <h2>{{ live_hosts|length }}</h2>
            <p>Live Hosts</p>
        </div>
        <div class="stat-card">
            <h2>{{ total_ports }}</h2>
            <p>Open Ports</p>
        </div>
        <div class="stat-card">
            <h2>{{ total_vulns }}</h2>
            <p>Vulnerabilities</p>
        </div>
        <div class="stat-card">
            <h2>{{ total_cves }}</h2>
            <p>CVEs Found</p>
        </div>
    </div>

    <!-- Subdomains -->
    <div class="section">
        <h2>📡 Subdomains</h2>
        <table>
            <tr><th>Subdomain</th></tr>
            {% for sub in subdomains %}
            <tr><td>{{ sub }}</td></tr>
            {% endfor %}
        </table>
    </div>

    <!-- Live Hosts -->
    <div class="section">
        <h2>🌐 Live Hosts</h2>
        <table>
            <tr><th>URL</th><th>Status</th><th>WAF</th></tr>
            {% for host in live_hosts %}
            <tr>
                <td>{{ host.split()[0] }}</td>
                <td>{{ host.split()[1] if host.split()|length > 1 else 'N/A' }}</td>
                <td>{{ waf.get(host.split()[0], 'Unknown') }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <!-- Port Scan -->
    <div class="section">
        <h2>🔌 Open Ports</h2>
        <table>
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
    <div class="section">
        <h2>⚠️ Vulnerabilities</h2>
        <table>
            <tr><th>Severity</th><th>Name</th><th>Host</th><th>Matched At</th></tr>
            {% for sev in ['critical', 'high', 'medium'] %}
                {% for vuln in vulnerabilities.get(sev, []) %}
                <tr>
                    <td><span class="badge {{ sev }}">{{ sev.upper() }}</span></td>
                    <td>{{ vuln.name }}</td>
                    <td>{{ vuln.host }}</td>
                    <td>{{ vuln.matched }}</td>
                </tr>
                {% endfor %}
            {% endfor %}
        </table>
    </div>

    <!-- CVEs -->
    <div class="section">
        <h2>🔍 CVE Findings</h2>
        <table>
            <tr><th>Technology</th><th>CVE ID</th><th>Score</th><th>Severity</th><th>Description</th></tr>
            {% for tech, cves in cve_data.items() %}
                {% for cve in cves %}
                <tr>
                    <td>{{ tech }}</td>
                    <td>{{ cve.id }}</td>
                    <td>{{ cve.score }}</td>
                    <td><span class="badge {{ cve.severity.lower() if cve.severity != 'N/A' else 'low' }}">{{ cve.severity }}</span></td>
                    <td>{{ cve.description[:100] }}...</td>
                </tr>
                {% endfor %}
            {% endfor %}
        </table>
    </div>

    <div class="footer">
        <p>Generated by BugzBunny v2.0.0 | Hop. Hunt. Hack. | For authorized testing only</p>
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
