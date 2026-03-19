import os
from rich.console import Console

console = Console()

def export_pdf(target: str, output_dir: str) -> str:
    """Convert HTML report to PDF using weasyprint"""

    html_file = f"{output_dir}/{target}_report.html"
    pdf_file  = f"{output_dir}/{target}_report.pdf"

    if not os.path.exists(html_file):
        console.print("[red][-] HTML report not found, skipping PDF export[/]")
        return ""

    # Try weasyprint
    try:
        from weasyprint import HTML
        console.print("[cyan][*] Generating PDF report...[/]")
        HTML(filename=html_file).write_pdf(pdf_file)
        console.print(f"[bold green][+] PDF Report generated → {pdf_file}[/]")
        return pdf_file
    except Exception as e:
        console.print(f"[yellow][~] Weasyprint failed: {e}[/]")

    # Fallback: wkhtmltopdf
    try:
        import subprocess
        result = subprocess.run(
            ["wkhtmltopdf", html_file, pdf_file],
            capture_output=True,
            text=True,
            timeout=60
        )
        if os.path.exists(pdf_file):
            console.print(f"[bold green][+] PDF Report generated → {pdf_file}[/]")
            return pdf_file
    except Exception as e:
        console.print(f"[yellow][~] wkhtmltopdf failed: {e}[/]")

    console.print("[yellow][~] PDF export skipped — no PDF generator available[/]")
    return ""
