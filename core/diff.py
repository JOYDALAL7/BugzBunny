import json
import os
from datetime import datetime
from rich.console import Console

console = Console()

def load_json(filepath: str) -> dict:
    """Load JSON file safely"""
    try:
        with open(filepath) as f:
            return json.load(f)
    except Exception:
        return {}

def diff_lists(old: list, new: list) -> dict:
    """Compare two lists and return added/removed items"""
    old_set = set(str(i) for i in old)
    new_set = set(str(i) for i in new)
    return {
        "added":   list(new_set - old_set),
        "removed": list(old_set - new_set),
        "common":  list(old_set & new_set)
    }

def generate_diff(target: str, output_dir: str) -> dict:
    """Compare current scan with previous scan"""

    raw_dir   = os.path.join(output_dir, "raw")
    diff_file = os.path.join(output_dir, "diff_report.json")
    prev_file = os.path.join(output_dir, "previous_scan.json")

    # Load current scan data
    current = {
        "subdomains":      load_json(f"{raw_dir}/subdomains.json").get("subdomains", []),
        "live_hosts":      load_json(f"{raw_dir}/livehosts.json").get("live_hosts", []),
        "ports":           load_json(f"{raw_dir}/ports.json").get("port_scan", {}),
        "vulnerabilities": load_json(f"{raw_dir}/vulnerabilities.json").get("vulnerabilities", {}),
        "cves":            load_json(f"{raw_dir}/cves.json").get("cves", {}),
        "js_secrets":      load_json(f"{raw_dir}/js_secrets.json").get("secrets", {}),
        "cors":            load_json(f"{raw_dir}/cors.json").get("cors", {}),
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Load previous scan if exists
    previous = load_json(prev_file)

    diff = {}

    if not previous:
        console.print("[yellow][~] No previous scan found — this is the baseline scan[/]")
        diff = {"baseline": True, "timestamp": current["timestamp"]}
    else:
        console.print(f"[cyan][*] Comparing with previous scan from {previous.get('timestamp', 'unknown')}[/]")

        # Diff subdomains
        sub_diff = diff_lists(previous.get("subdomains", []), current["subdomains"])
        diff["subdomains"] = sub_diff
        if sub_diff["added"]:
            console.print(f"[bold red][!] {len(sub_diff['added'])} NEW subdomains found![/]")
            for s in sub_diff["added"]:
                console.print(f"[red]  → {s}[/]")
        if sub_diff["removed"]:
            console.print(f"[yellow][~] {len(sub_diff['removed'])} subdomains removed[/]")

        # Diff live hosts
        host_diff = diff_lists(previous.get("live_hosts", []), current["live_hosts"])
        diff["live_hosts"] = host_diff
        if host_diff["added"]:
            console.print(f"[bold red][!] {len(host_diff['added'])} NEW live hosts![/]")

        # Diff vulnerabilities
        prev_vulns = []
        curr_vulns = []
        for sev, vulns in previous.get("vulnerabilities", {}).items():
            for v in vulns:
                prev_vulns.append(f"{sev}:{v.get('name')}:{v.get('host')}")
        for sev, vulns in current["vulnerabilities"].items():
            for v in vulns:
                curr_vulns.append(f"{sev}:{v.get('name')}:{v.get('host')}")

        vuln_diff = diff_lists(prev_vulns, curr_vulns)
        diff["vulnerabilities"] = vuln_diff
        if vuln_diff["added"]:
            console.print(f"[bold red][!] {len(vuln_diff['added'])} NEW vulnerabilities![/]")
            for v in vuln_diff["added"]:
                console.print(f"[red]  → {v}[/]")

        # Diff JS secrets
        prev_secrets = sum(len(v) for v in previous.get("js_secrets", {}).values())
        curr_secrets = sum(len(v) for v in current["js_secrets"].values())
        diff["js_secrets"] = {
            "previous": prev_secrets,
            "current":  curr_secrets,
            "new":      max(0, curr_secrets - prev_secrets)
        }
        if diff["js_secrets"]["new"] > 0:
            console.print(f"[bold red][!] {diff['js_secrets']['new']} NEW JS secrets found![/]")

        # Diff CORS
        prev_cors = len(previous.get("cors", {}))
        curr_cors = len(current["cors"])
        diff["cors"] = {"previous": prev_cors, "current": curr_cors}
        if curr_cors > prev_cors:
            console.print(f"[bold red][!] {curr_cors - prev_cors} NEW CORS issues![/]")

        diff["timestamp"]      = current["timestamp"]
        diff["prev_timestamp"] = previous.get("timestamp", "unknown")

    # Save diff report
    with open(diff_file, "w") as f:
        json.dump({"target": target, "diff": diff}, f, indent=2)

    # Save current as previous for next scan
    with open(prev_file, "w") as f:
        json.dump(current, f, indent=2)

    console.print(f"[green][+] Diff report saved → {diff_file}[/]")
    return diff
