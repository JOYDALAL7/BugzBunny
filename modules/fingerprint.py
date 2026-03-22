import subprocess
import json
import re
import requests
import urllib3
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ── Header-based tech signatures ──────────────────────
HEADER_SIGNATURES = {
    "Server": [
        (r"Apache/([\d\.]+)", "Apache"),
        (r"nginx/([\d\.]+)",  "nginx"),
        (r"Microsoft-IIS/([\d\.]+)", "IIS"),
        (r"LiteSpeed",        "LiteSpeed"),
        (r"cloudflare",       "Cloudflare"),
        (r"openresty",        "OpenResty"),
    ],
    "X-Powered-By": [
        (r"PHP/([\d\.]+)",    "PHP"),
        (r"ASP\.NET",         "ASP.NET"),
        (r"Express",          "Express"),
        (r"Django",           "Django"),
    ],
    "X-Generator": [
        (r"WordPress ([\d\.]+)", "WordPress"),
        (r"Drupal ([\d\.]+)",    "Drupal"),
        (r"Joomla",              "Joomla"),
    ],
    "Via": [
        (r"Varnish",  "Varnish"),
        (r"Squid",    "Squid"),
        (r"([\d\.]+) Fastly", "Fastly"),
    ],
}

BODY_SIGNATURES = [
    (r"wp-content/themes",         "WordPress",  None),
    (r"Drupal\.settings",          "Drupal",     None),
    (r"Joomla",                    "Joomla",     None),
    (r"laravel_session",           "Laravel",    None),
    (r"csrfmiddlewaretoken",       "Django",     None),
    (r"__NEXT_DATA__",             "Next.js",    None),
    (r"react-dom",                 "React",      None),
    (r"angular\.min\.js",          "Angular",    None),
    (r"vue\.min\.js",              "Vue.js",     None),
    (r"jquery-([\d\.]+)\.min\.js", "jQuery",     1),
    (r"bootstrap/([\d\.]+)/",      "Bootstrap",  1),
    (r"tomcat",                    "Tomcat",     None),
    (r"struts",                    "Struts",     None),
]

def fingerprint_from_headers(url: str) -> list:
    """Fallback fingerprinting from HTTP response headers and body"""
    techs = []
    seen  = set()

    try:
        r = requests.get(
            url,
            timeout=10,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        headers = dict(r.headers)
        body    = r.text[:50000]

        # Header matching
        for header_name, patterns in HEADER_SIGNATURES.items():
            header_val = headers.get(header_name, "")
            if not header_val:
                continue
            for pattern, tech_name in patterns:
                m = re.search(pattern, header_val, re.IGNORECASE)
                if m and tech_name not in seen:
                    seen.add(tech_name)
                    version = m.group(1) if m.lastindex else "unknown"
                    techs.append({"name": tech_name, "version": version})

        # Body matching
        for pattern, tech_name, group in BODY_SIGNATURES:
            m = re.search(pattern, body, re.IGNORECASE)
            if m and tech_name not in seen:
                seen.add(tech_name)
                version = m.group(group) if group and m.lastindex else "unknown"
                techs.append({"name": tech_name, "version": version})

    except Exception:
        pass

    return techs


def run_whatweb(live_hosts: list, target: str, raw_dir: str,
                mode: str = "active") -> dict:
    """Fingerprint technologies — whatweb + header fallback"""

    if not live_hosts:
        console.print("[red][-] No live hosts to fingerprint[/]")
        return {}

    if mode == "passive":
        aggression = "1"
        timeout    = 15
    elif mode == "stealth":
        aggression = "1"
        timeout    = 20
    elif mode == "aggressive":
        aggression = "3"
        timeout    = 30
    else:
        aggression = "1"
        timeout    = 30

    all_results = {}

    for host in live_hosts:
        url  = host.split()[0]
        console.print(f"[cyan][*] Fingerprinting {url} [{mode}]...[/]")

        technologies = []

        # ── Primary: whatweb ──────────────────────────
        try:
            result = subprocess.run(
                ["whatweb", "--color=never", "--log-brief=/dev/stdout",
                 "-a", aggression, url],
                capture_output=True, text=True, timeout=timeout
            )
            line = result.stdout.strip()

            if line:
                pattern = r'([A-Za-z][\w\-\.]+)(?:\[([^\]]*)\])?'
                techs   = re.findall(pattern, line)
                for name, version in techs:
                    if name.lower() not in ["http", "https", "www"]:
                        technologies.append({
                            "name":    name,
                            "version": version if version else "unknown"
                        })

        except subprocess.TimeoutExpired:
            console.print(f"[yellow][~] whatweb timed out for {url} — using fallback[/]")
        except Exception as e:
            console.print(f"[yellow][~] whatweb failed for {url} — using fallback[/]")

        # ── Fallback: header + body fingerprinting ────
        if not technologies:
            console.print(f"[dim]  › Running header fallback for {url}...[/]")
            fallback = fingerprint_from_headers(url)
            if fallback:
                technologies = fallback
                console.print(f"[green]  ✓ Fallback detected {len(fallback)} technologies[/]")
            else:
                console.print(f"[dim]  › No technologies detected via fallback[/]")

        all_results[url] = technologies
        console.print(f"[green]  ✓ {url} → {len(technologies)} technologies detected[/]")

    # Save
    out_file = f"{raw_dir}/fingerprint.json"
    with open(out_file, "w") as f:
        json.dump({"target": target, "mode": mode, "fingerprint": all_results}, f, indent=2)

    console.print(f"[green]  ✓ Fingerprinting complete → {out_file}[/]")
    return all_results
