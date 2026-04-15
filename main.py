"""
SentinelScan - Main Entry Point
=================================
The CLI (Command Line Interface) - what users actually run.

This file handles:
  - Parsing command-line arguments (argparse)
  - Beautiful terminal output using Rich
  - Triggering the scan and displaying results

Usage:
  python main.py https://example.com
  python main.py https://example.com --output report.json
  python main.py https://example.com --timeout 15
"""

import argparse
import sys
import io
import time

# Force UTF-8 output on Windows to prevent encoding errors
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich import box
from rich.style import Style

from scanner.core import SentinelCore, normalize_target, validate_target
from scanner.models import Severity, ScanReport, ModuleResult
from reporter.pdf_reporter import generate_pdf_report

# ─────────────────────────────────────────────────────────────────────────────
#  RICH CONSOLE SETUP
#  Rich uses a Console object for all output.
#  This is better than print() — supports colors, formatting, tables, panels.
# ─────────────────────────────────────────────────────────────────────────────
console = Console()

# Severity → Rich color mapping
SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim white",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[X]",
    Severity.HIGH:     "[!]",
    Severity.MEDIUM:   "[~]",
    Severity.LOW:      "[-]",
    Severity.INFO:     "[i]",
}


def print_banner():
    """Print the SentinelScan ASCII banner."""
    banner = """
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                    ███████╗ ██████╗ █████╗ ███╗   ██╗             
                    ██╔════╝██╔════╝██╔══██╗████╗  ██║             
                    ███████╗██║     ███████║██╔██╗ ██║             
                    ╚════██║██║     ██╔══██║██║╚██╗██║             
                    ███████║╚██████╗██║  ██║██║ ╚████║             
                    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝             
"""
    console.print(Panel(
        Text(banner, style="bold blue", justify="center"),
        subtitle="[dim]Web Security Vulnerability Scanner v1.0 — For Authorized Use Only[/dim]",
        border_style="blue",
        box=box.DOUBLE_EDGE,
    ))


def print_module_result(result: ModuleResult):
    """Print the results of a single scanner module."""
    # Module header
    has_findings = len(result.findings) > 0
    header_style = "bold red" if has_findings else "bold green"
    finding_count = f"[{len(result.findings)} {'issue' if len(result.findings) == 1 else 'issues'}]"

    console.print(f"\n  [bold white]▶ {result.module_name}[/bold white]  "
                  f"[{header_style}]{finding_count}[/{header_style}]")
    console.rule(style="dim blue")

    if result.error:
        console.print(f"  [bold red][ERR] Module Error:[/bold red] {result.error}")
        return

    # Print passed checks
    for check in result.passed:
        console.print(f"    [green][OK][/green] {check}")

    # Print findings
    for finding in result.findings:
        color = SEVERITY_COLORS[finding.severity]
        icon = SEVERITY_ICONS[finding.severity]
        cvss = f"CVSS {finding.cvss_score:.1f}"

        console.print(
            f"\n    {icon} [{color}][{finding.severity.value}] {finding.title}[/{color}]  "
            f"[dim]({cvss})[/dim]"
        )

        # Wrap description at 90 chars for readability
        desc_lines = finding.description.split("\n")
        for line in desc_lines:
            console.print(f"       [dim white]{line.strip()}[/dim white]")

        if finding.evidence:
            console.print(f"       [dim cyan]Evidence: {finding.evidence}[/dim cyan]")

        console.print(f"       [dim green]Fix: {finding.recommendation.split(chr(10))[0]}[/dim green]")


def print_summary_table(report: ScanReport):
    """Print the final summary dashboard."""
    console.print("\n")
    console.rule("[bold white]  SCAN SUMMARY  ", style="bold blue")

    # Overall risk badge
    risk = report.risk_rating()
    risk_colors = {
        "CRITICAL": "bold white on red",
        "HIGH":     "bold black on yellow",
        "MEDIUM":   "bold black on yellow3",
        "LOW":      "bold white on blue",
        "SECURE":   "bold white on green",
    }
    risk_style = risk_colors.get(risk, "white")

    console.print(f"\n  Target   : [bold cyan]{report.target}[/bold cyan]")
    console.print(f"  Scanned  : [dim]{report.scan_time}[/dim]")
    console.print(f"  Modules  : {', '.join(report.modules_run)}")
    console.print(f"  Risk     : [{risk_style}]  {risk}  [/{risk_style}]\n")

    # Findings breakdown table
    table = Table(
        title="Vulnerability Breakdown",
        box=box.ROUNDED,
        border_style="blue",
        show_header=True,
        header_style="bold white"
    )
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Count", justify="center", width=8)
    table.add_column("Action Required", style="dim")

    severity_data = [
        (Severity.CRITICAL, report.critical_count(), "[!!] Fix immediately - active threat risk",  "bold red"),
        (Severity.HIGH,     report.high_count(),     "[!] Fix within 7 days",                       "bold yellow"),
        (Severity.MEDIUM,   report.medium_count(),   "[~] Fix within 30 days",                      "yellow"),
        (Severity.LOW,      report.low_count(),      "[-] Fix when possible",                        "cyan"),
    ]

    for severity, count, action, color in severity_data:
        count_str = f"[{color}]{count}[/{color}]" if count > 0 else "[green]0[/green]"
        table.add_row(
            f"[{color}]{severity.value}[/{color}]",
            count_str,
            action if count > 0 else "[dim green]All clear[/dim green]"
        )

    table.add_section()
    table.add_row(
        "[bold white]TOTAL[/bold white]",
        f"[bold white]{report.total_findings()}[/bold white]",
        f"{len(report.results)} modules run"
    )

    console.print(table)


def parse_arguments() -> argparse.Namespace:
    """
    Set up and parse command-line arguments.
    
    argparse is Python's standard way to build CLIs.
    Every professional Python tool (pip, pytest, black) uses it.
    """
    parser = argparse.ArgumentParser(
        prog="sentinelscan",
        description=(
            "SentinelScan — Web Security Vulnerability Scanner\n"
            "Scans web applications for security misconfigurations.\n"
            "IMPORTANT: Only scan systems you own or have written permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py https://example.com\n"
            "  python main.py https://example.com --output reports/scan.json\n"
            "  python main.py https://example.com --timeout 15 --no-banner\n"
        )
    )

    parser.add_argument(
        "target",
        help="Target URL to scan (e.g., https://example.com)"
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save JSON report to this file (default: auto-generated filename)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        metavar="SECONDS",
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip the ASCII banner (useful for piping output)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show findings (no passed checks)"
    )
    parser.add_argument(
        "--no-intel",
        action="store_true",
        help="Skip threat intelligence lookup (Shodan + NVD) for faster offline scans"
    )
    parser.add_argument(
        "--pdf",
        metavar="FILE",
        help="Also generate a PDF report (e.g., --pdf report.pdf)"
    )

    return parser.parse_args()


def confirm_authorization(target: str) -> bool:
    """
    Ethical scanner design: always confirm authorization before scanning.
    
    Professional security tools (Burp Suite, Metasploit) all do this.
    It protects both the user and the target.
    """
    console.print(Panel(
        f"[bold yellow]*** AUTHORIZATION CONFIRMATION ***[/bold yellow]\n\n"
        f"You are about to scan: [bold cyan]{target}[/bold cyan]\n\n"
        f"[white]SentinelScan is for [bold green]authorized security testing only[/bold green].\n"
        f"Scanning systems without permission is illegal in most countries\n"
        f"and violates computer crime laws (e.g., India IT Act Section 66).[/white]",
        border_style="yellow",
        box=box.ROUNDED
    ))
    
    response = input("\n  Do you own this system or have written permission to scan it? (yes/no): ")
    return response.strip().lower() in ("yes", "y")


def main():
    """Main entry point for SentinelScan CLI."""
    args = parse_arguments()

    if not args.no_banner:
        print_banner()

    # Authorization check — this is what makes us an ethical scanner
    target = normalize_target(args.target)
    if not confirm_authorization(target):
        console.print("\n[bold red]Scan aborted.[/bold red] Only scan systems you are authorized to test.\n")
        sys.exit(0)

    console.print(f"\n[bold white]  Initializing scan...[/bold white]")
    console.print(f"  Target  : [bold cyan]{target}[/bold cyan]")
    console.print(f"  Timeout : {args.timeout}s per request")
    intel_status = "disabled (--no-intel)" if args.no_intel else "Shodan + NVD"
    console.print(f"  Modules : Headers, SSL, Dirs, SQLi, XSS, CORS | Intel: {intel_status}\n")

    # ── RUN THE SCAN ────────────────────────────────────────────────────────
    start_time = time.time()
    scanner = SentinelCore(
        timeout=args.timeout,
        include_threat_intel=not args.no_intel
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TimeElapsedColumn(),
        console=console,
        transient=True  # Progress bar disappears after completion
    ) as progress:
        task = progress.add_task("  Scanning...", total=None)
        report = scanner.scan(target)
        progress.update(task, completed=True)

    elapsed = time.time() - start_time

    # ── DISPLAY RESULTS ─────────────────────────────────────────────────────
    for module_result in report.results:
        if args.quiet:
            # In quiet mode, only show findings, not passed checks
            module_result.passed = []
        print_module_result(module_result)

    print_summary_table(report)

    # ── SAVE JSON REPORT ────────────────────────────────────────────────────
    # Auto-generate output filename if not specified
    if not args.output:
        hostname = target.replace("https://", "").replace("http://", "").rstrip("/")
        hostname = hostname.replace("/", "_").replace(":", "_")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        args.output = f"sentinelscan_{hostname}_{timestamp}.json"

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    saved_path = scanner.save_json_report(report, str(output_path))

    console.print(f"\n  [bold green][DONE][/bold green] JSON report saved: [cyan]{saved_path}[/cyan]")

    # PDF report (optional)
    if args.pdf:
        try:
            pdf_path = generate_pdf_report(report, args.pdf)
            console.print(f"  [bold green][DONE][/bold green] PDF report saved: [cyan]{pdf_path}[/cyan]")
        except Exception as e:
            console.print(f"  [yellow][WARN] PDF generation failed: {e}[/yellow]")

    console.print(f"  [dim]Scan completed in {elapsed:.1f}s[/dim]\n")

    # Exit with non-zero code if critical/high findings exist
    # (This makes SentinelScan usable in CI/CD pipelines — failing builds on bad security)
    if report.critical_count() > 0 or report.high_count() > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
