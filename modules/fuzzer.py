import subprocess
import json
import os
from rich.console import Console

console = Console()

def run_ffuf(live_hosts: list, target: str, fuzz_dir: str,
             mode: str = "active") -> dict:
    """Run directory fuzzing on live hosts — mode aware"""

    if not live_hosts:
        console.print("[red][-] No live hosts to fuzz[/]")
        return {}

    # Passive mode — skip entirely
    if mode == "passive":
        console.print("[dim]  › Fuzzing skipped in passive mode[/]")
        return {}

    # Stealth mode — skip fuzzing (too noisy)
    if mode == "stealth":
        console.print("[dim]  › Fuzzing skipped in stealth mode[/]")
        return {}

    # ── Mode-based config ─────────────────────
    if mode == "aggressive":
        threads  = "100"
        timeout  = "10"
        wordlists = [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/wordlists/dirb/common.txt"
        ]
        proc_timeout = 300
    else:  # active (default)
        threads  = "50"
        timeout  = "10"
        wordlists = [
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/usr/share/wordlists/dirb/common.txt"
        ]
        proc_timeout = 180

    wordlist = next((w for w in wordlists if os.path.exists(w)),
                    "/usr/share/wordlists/dirb/common.txt")

    console.print(f"[dim]  › Wordlist: {wordlist}[/]")

    all_results = {}

    for host in live_hosts:
        url        = host.split()[0]
        clean_name = url.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")
        out_file   = f"{fuzz_dir}/ffuf_{clean_name}.json"

        console.print(f"[cyan][*] Fuzzing {url} [{mode}]...[/]")

        try:
            subprocess.run(
                [
                    "ffuf",
                    "-u",  f"{url}/FUZZ",
                    "-w",  wordlist,
                    "-o",  out_file,
                    "-of", "json",
                    "-t",  threads,
                    "-mc", "200,201,204,301,302,307,401,403,405",
                    "-timeout", timeout,
                    "-silent",
                    "-fc", "429,404",
                    "-fs", "0",
                    "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "-H", "Accept: text/html,application/xhtml+xml,*/*;q=0.8",
                ],
                capture_output=True,
                text=True,
                timeout=proc_timeout
            )
        except subprocess.TimeoutExpired:
            console.print(f"[yellow][~] Fuzzing timed out for {url}[/]")
            all_results[url] = []
            continue
        except Exception as e:
            console.print(f"[red][-] Fuzzing failed for {url}: {e}[/]")
            all_results[url] = []
            continue

        # Parse results
        try:
            with open(out_file) as f:
                data     = json.load(f)
            findings = [r["url"] for r in data.get("results", [])]
        except Exception:
            findings = []

        all_results[url] = findings

        if findings:
            console.print(f"[bold green]  ✓ {url} → {len(findings)} paths found![/]")
        else:
            console.print(f"[green]  ✓ {url} → 0 paths found[/]")

    # Save summary
    summary_file = f"{fuzz_dir}/fuzzing_summary.json"
    with open(summary_file, "w") as f:
        json.dump({"target": target, "mode": mode, "fuzzing": all_results}, f, indent=2)

    total = sum(len(v) for v in all_results.values())
    console.print(f"[green]  ✓ Fuzzing complete → {total} total paths → {summary_file}[/]")
    return all_results
