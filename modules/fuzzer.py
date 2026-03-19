import subprocess
import json
from rich.console import Console

console = Console()

def run_ffuf(live_hosts: list, target: str, fuzz_dir: str) -> dict:
    """Run directory fuzzing on live hosts"""

    if not live_hosts:
        console.print("[red][-] No live hosts to fuzz[/]")
        return {}

    wordlist = "/usr/share/wordlists/dirb/common.txt"
    all_results = {}

    for host in live_hosts:
        url = host.split()[0]
        console.print(f"[cyan][*] Fuzzing {url}[/]")

        clean_name = url.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")
        out_file = f"{fuzz_dir}/ffuf_{clean_name}.json"

        try:
            with console.status(f"[cyan]Fuzzing {url}...[/]"):
                result = subprocess.run(
                    [
                        "ffuf",
                        "-u", f"{url}/FUZZ",
                        "-w", wordlist,
                        "-o", out_file,
                        "-of", "json",
                        "-t", "40",
                        "-mc", "200,201,301,302,403",
                        "-timeout", "10",
                        "-silent",
                        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "-H", "X-Forwarded-For: 127.0.0.1"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
        except subprocess.TimeoutExpired:
            console.print(f"[yellow][~] Fuzzing timed out for {url}, skipping...[/]")
            all_results[url] = []
            continue
        except Exception as e:
            console.print(f"[red][-] Fuzzing failed for {url}: {e}[/]")
            all_results[url] = []
            continue

        try:
            with open(out_file) as f:
                data = json.load(f)
            findings = [r["url"] for r in data.get("results", [])]
        except Exception:
            findings = []

        all_results[url] = findings
        console.print(f"[green][+] {url} → {len(findings)} paths found[/]")

    # Save summary
    summary_file = f"{fuzz_dir}/fuzzing_summary.json"
    with open(summary_file, "w") as f:
        json.dump({"target": target, "fuzzing": all_results}, f, indent=2)

    console.print(f"[green][+] Fuzzing complete → {summary_file}[/]")
    return all_results
