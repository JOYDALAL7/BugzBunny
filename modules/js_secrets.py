import json
import re
import requests
import urllib3
from rich.console import Console

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

PATTERNS = {
    "AWS Access Key":    r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":    r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
    "Google API Key":    r'AIza[0-9A-Za-z\-_]{35}',
    "Stripe Secret Key": r'sk_live_[0-9a-zA-Z]{24}',
    "Stripe Public Key": r'pk_live_[0-9a-zA-Z]{24}',
    "GitHub Token":      r'ghp_[0-9a-zA-Z]{36}',
    "JWT Token":         r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
    "Slack Token":       r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Twilio API Key":    r'SK[0-9a-fA-F]{32}',
    "SendGrid API Key":  r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    "Private Key":       r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
    "Password in URL":   r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@',
    "Basic Auth":        r'(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]{8,}',
}

def find_js_files(url: str) -> list:
    """Find JS files from a URL"""
    js_files = []
    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
            verify=False
        )
        pattern = r'src=["\']([^"\']*\.js[^"\']*)["\']'
        matches = re.findall(pattern, response.text)
        for match in matches:
            if match.startswith("http"):
                js_files.append(match)
            elif match.startswith("//"):
                js_files.append(f"https:{match}")
            elif match.startswith("/"):
                base = url.rstrip("/")
                js_files.append(f"{base}{match}")
    except Exception:
        pass
    return js_files[:20]

def scan_js_file(js_url: str) -> list:
    """Scan a JS file for secrets"""
    findings = []
    try:
        response = requests.get(
            js_url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
            verify=False
        )
        content = response.text
        for secret_type, pattern in PATTERNS.items():
            matches = re.findall(pattern, content)
            # Deduplicate matches per file
            seen = set()
            for match in matches:
                match_str = str(match)[:100]
                if match_str not in seen:
                    seen.add(match_str)
                    findings.append({
                        "type": secret_type,
                        "match": match_str,
                        "url": js_url
                    })
    except Exception:
        pass
    return findings

def run_js_secrets(live_hosts: list, target: str, raw_dir: str) -> dict:
    """Find secrets in JS files across all live hosts"""

    if not live_hosts:
        console.print("[red][-] No live hosts to scan for JS secrets[/]")
        return {}

    all_findings = {}
    total = 0

    for host in live_hosts:
        url = host.split()[0]
        console.print(f"[cyan][*] Scanning JS files on {url}[/]")

        js_files = find_js_files(url)
        console.print(f"[dim]    Found {len(js_files)} JS files[/]")

        host_findings = []
        seen_urls = set()

        for js_url in js_files:
            if js_url in seen_urls:
                continue
            seen_urls.add(js_url)

            secrets = scan_js_file(js_url)
            if secrets:
                host_findings.extend(secrets)
                # Show only first finding per JS file
                console.print(f"[bold red]  [!] {len(secrets)} secrets in {js_url}[/]")

        if host_findings:
            all_findings[url] = host_findings
            total += len(host_findings)

    # Save results
    out_file = f"{raw_dir}/js_secrets.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "secrets": all_findings}, f, indent=2)

    if total > 0:
        console.print(f"[bold red][!] Found {total} secrets → {out_file}[/]")
    else:
        console.print(f"[green][+] No secrets found in JS files[/]")

    return all_findings
