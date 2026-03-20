import json
import re
import math
import requests
import urllib3
from dataclasses import dataclass
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ── Categorized Pattern Library ────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key": {
        "pattern":    r'AKIA[0-9A-Z]{16}',
        "confidence": 0.95,
        "severity":   "critical"
    },
    "AWS Secret Key": {
        "pattern":    r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
        "confidence": 0.85,
        "severity":   "critical"
    },
    "Google API Key": {
        "pattern":    r'AIza[0-9A-Za-z\-_]{35}',
        "confidence": 0.95,
        "severity":   "high"
    },
    "Stripe Secret Key": {
        "pattern":    r'sk_live_[0-9a-zA-Z]{24}',
        "confidence": 0.98,
        "severity":   "critical"
    },
    "Stripe Public Key": {
        "pattern":    r'pk_live_[0-9a-zA-Z]{24}',
        "confidence": 0.90,
        "severity":   "medium"
    },
    "GitHub Token": {
        "pattern":    r'ghp_[0-9a-zA-Z]{36}',
        "confidence": 0.98,
        "severity":   "critical"
    },
    "JWT Token": {
        "pattern":    r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "confidence": 0.90,
        "severity":   "high"
    },
    "Slack Token": {
        "pattern":    r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        "confidence": 0.95,
        "severity":   "high"
    },
    "Twilio API Key": {
        "pattern":    r'SK[0-9a-fA-F]{32}',
        "confidence": 0.80,
        "severity":   "high"
    },
    "SendGrid API Key": {
        "pattern":    r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        "confidence": 0.98,
        "severity":   "high"
    },
    "Private Key": {
        "pattern":    r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
        "confidence": 1.00,
        "severity":   "critical"
    },
    "Password in URL": {
        "pattern":    r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@',
        "confidence": 0.75,
        "severity":   "high"
    },
    "Generic Secret": {
        "pattern":    r'(?i)(secret|api_key|apikey|token|password)[\'"\s]*[:=][\'"\s]*[0-9a-zA-Z\-_]{16,}',
        "confidence": 0.60,
        "severity":   "medium"
    },
}

# ── Severity filter per mode ───────────────────────────
MODE_SEVERITY_FILTER = {
    "passive":    [],                              # skip entirely
    "stealth":    ["critical"],                    # critical only
    "active":     ["critical", "high"],            # critical + high
    "aggressive": ["critical", "high", "medium"],  # all except low
}

# ── False Positive Indicators ──────────────────────────
FALSE_POSITIVE_PATTERNS = [
    "example", "test", "placeholder", "your_",
    "xxxxxxxx", "00000000", "changeme", "insert",
    "dummy", "sample", "fake", "mock", "replace",
    "aaaaaa", "123456", "abcdef", "none", "null"
]

@dataclass
class SecretFinding:
    secret_type: str
    match:       str
    url:         str
    severity:    str
    confidence:  float
    entropy:     float

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length  = len(text)
    for count in freq.values():
        prob     = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 3)

def is_false_positive(match: str) -> bool:
    match_lower = match.lower()
    for fp in FALSE_POSITIVE_PATTERNS:
        if fp in match_lower:
            return True
    if calculate_entropy(match) < 2.0:
        return True
    if len(match) < 8:
        return True
    return False

def find_js_files(url: str, limit: int = 20) -> list:
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
                js_files.append(f"{url.rstrip('/')}{match}")
    except Exception:
        pass
    return js_files[:limit]

def scan_js_file(js_url: str, severity_filter: list) -> list:
    """Scan a JS file for secrets — filters by severity"""
    findings = []
    seen     = set()

    try:
        response = requests.get(
            js_url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
            verify=False
        )
        content = response.text

        for secret_type, config in SECRET_PATTERNS.items():

            # Skip if severity not in mode filter
            if config["severity"] not in severity_filter:
                continue

            matches = re.findall(config["pattern"], content)
            for match in matches:
                match_str = str(match)[:150].strip()

                if match_str in seen:
                    continue
                if is_false_positive(match_str):
                    continue

                seen.add(match_str)
                entropy    = calculate_entropy(match_str)
                confidence = config["confidence"]

                if entropy > 4.0:
                    confidence = min(1.0, confidence + 0.05)
                elif entropy < 3.0:
                    confidence = max(0.0, confidence - 0.10)

                findings.append(SecretFinding(
                    secret_type = secret_type,
                    match       = match_str,
                    url         = js_url,
                    severity    = config["severity"],
                    confidence  = round(confidence, 2),
                    entropy     = entropy
                ))

    except Exception:
        pass

    return findings

def run_js_secrets(live_hosts: list, target: str, raw_dir: str,
                   mode: str = "active") -> dict:
    """Find secrets in JS files — mode aware"""

    if not live_hosts:
        console.print("[red][-] No live hosts to scan for JS secrets[/]")
        return {}

    # Passive — skip
    if mode == "passive":
        console.print("[dim]  › JS secrets skipped in passive mode[/]")
        return {}

    severity_filter = MODE_SEVERITY_FILTER.get(mode, ["critical", "high"])
    js_limit        = 10 if mode == "stealth" else 20

    all_findings = {}
    total        = 0

    for host in live_hosts:
        url = host.split()[0]
        console.print(f"[cyan][*] Scanning JS files on {url} [{mode}]...[/]")

        js_files      = find_js_files(url, limit=js_limit)
        console.print(f"[dim]    Found {len(js_files)} JS files[/]")

        host_findings = []
        seen_urls     = set()

        for js_url in js_files:
            if js_url in seen_urls:
                continue
            seen_urls.add(js_url)

            secrets = scan_js_file(js_url, severity_filter)
            for s in secrets:
                host_findings.append({
                    "type":       s.secret_type,
                    "match":      s.match,
                    "url":        s.url,
                    "severity":   s.severity,
                    "confidence": s.confidence,
                    "entropy":    s.entropy
                })
                console.print(
                    f"  [bold red][!] {s.secret_type}[/]  "
                    f"[dim]entropy={s.entropy}  confidence={s.confidence}[/]"
                )

        if host_findings:
            all_findings[url] = host_findings
            total += len(host_findings)

    # Save results
    out_file = f"{raw_dir}/js_secrets.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "secrets": all_findings}, f, indent=2)

    if total > 0:
        console.print(f"[bold red]  [!] Found {total} secrets → {out_file}[/]")
    else:
        console.print(f"[green]  ✓ No secrets found in JS files[/]")

    return all_findings
