import os
import sys
import shlex
from typing import Optional, List, Dict, Any

from emla import __version__
from emla.models import ScanResult, Severity, FindingCategory
from emla.engine import EMLAEngine
from emla.reporter import JSONReporter

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.style import Style
    from rich.prompt import Prompt
    from rich import print as rprint
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

ASCII_BANNER = r"""
 ███████╗███╗   ███╗██╗      █████╗ 
 ██╔════╝████╗ ████║██║     ██╔══██╗
 █████╗  ██╔████╔██║██║     ███████║
 ██╔══╝  ██║╚██╔╝██║██║     ██╔══██╗
 ███████╗██║ ╚═╝ ██║███████╗██║  ██║
 ╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
"""

def print_banner(interactive: bool = False):
    """Prints the DriftSentry-style software banner."""
    if HAS_RICH:
        banner_text = Text()
        banner_text.append(ASCII_BANNER, style="bold cyan")
        banner_text.append("\n  🛡️  ERROR MESSAGE LINGUISTICS ANALYZER  |  ", style="bold white")
        banner_text.append(f"v{__version__} ", style="bold yellow")
        banner_text.append("[Kali Linux Certified]", style="bold magenta")
        
        sub_text = "\n\n" + ("Interactive Mode Active. Type 'help' for command list, 'exit' or 'q' to quit." if interactive else "Automated Security Analysis Engine")
        banner_text.append(sub_text, style="italic green" if interactive else "dim white")

        panel = Panel(
            banner_text,
            border_style="bright_blue",
            padding=(0, 2),
            expand=True
        )
        console.print(panel)
    else:
        print("=" * 65)
        print(ASCII_BANNER)
        print(f" EMLA v{__version__} - Error Message Linguistics Analyzer [Kali Certified]")
        if interactive:
            print(" Interactive Mode Active. Type 'help' for command list, 'exit' or 'q' to quit.")
        print("=" * 65)

def get_severity_color(severity_str: str) -> str:
    """Returns color code for severity level."""
    s = severity_str.upper()
    if s == "CRITICAL":
        return "bold red"
    elif s == "HIGH":
        return "red"
    elif s == "MEDIUM":
        return "yellow"
    elif s == "LOW":
        return "cyan"
    elif s == "INFO":
        return "blue"
    else:
        return "green"

def render_scan_config(target: str, single_url: bool, max_depth: int, max_pages: int, output_path: str):
    """Renders scan configuration box."""
    if HAS_RICH:
        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(style="bold yellow")
        grid.add_column(style="bold white")
        grid.add_column(style="bold yellow")
        grid.add_column(style="bold white")

        grid.add_row("🎯 Target URL:", target, "⚙️  Scan Mode:", "Single URL" if single_url else "Crawl Domain")
        grid.add_row("🔍 Max Depth:", str(max_depth), "📄 Max Pages:", str(max_pages))
        grid.add_row("💾 Report Path:", output_path, "⏱️  Timeout:", "5.0s")

        panel = Panel(
            grid,
            title="[bold cyan]🔍 Target & Scan Telemetry Config[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        )
        console.print(panel)
    else:
        print(f"[*] Target: {target} | Mode: {'Single URL' if single_url else 'Crawl Domain'}")
        print(f"[*] Max Depth: {max_depth} | Max Pages: {max_pages} | Output: {output_path}")

def render_scan_results(scan_result: ScanResult):
    """Displays rich software-style telemetry tables for scan results."""
    if not HAS_RICH:
        print(f"\nScan Complete for {scan_result.target_url}")
        print(f"Total Endpoints: {scan_result.total_endpoints} | Findings: {scan_result.total_findings} | Score: {scan_result.overall_score} ({scan_result.overall_severity_rating})")
        return

    # 1. Endpoints Table
    ep_table = Table(
        title="[bold cyan]📡 Discovered Services & Endpoint Vulnerability Telemetry[/bold cyan]",
        border_style="bright_blue",
        header_style="bold magenta",
        expand=True
    )
    ep_table.add_column("Method", style="bold cyan", width=8)
    ep_table.add_column("Endpoint URL", style="bold white")
    ep_table.add_column("Status", style="yellow", justify="center", width=8)
    ep_table.add_column("Score", style="bold red", justify="right", width=10)
    ep_table.add_column("Findings", style="bold white", justify="right", width=10)
    ep_table.add_column("Severity Breakdown", style="dim white")

    for ep in scan_result.endpoints_scanned:
        summary_str = ", ".join([f"{k}:{v}" for k, v in ep.summary.items()]) if ep.summary else "Clean (0)"
        score_color = get_severity_color(
            "CRITICAL" if ep.score > 75 else "HIGH" if ep.score > 40 else "MEDIUM" if ep.score > 15 else "LOW" if ep.score > 0 else "NONE"
        )
        ep_table.add_row(
            f"[{'green' if ep.method=='GET' else 'yellow'}]{ep.method}[/]",
            ep.url,
            str(ep.status_code),
            f"[{score_color}]{ep.score:.1f}[/]",
            str(len(ep.findings)),
            summary_str
        )

    console.print(ep_table)
    console.print()

    # 2. Detailed Findings Table if findings exist
    all_findings = []
    for ep in scan_result.endpoints_scanned:
        for f in ep.findings:
            all_findings.append((ep.url, f))

    if all_findings:
        f_table = Table(
            title="[bold red]🚨 Detected Sensitive Information Leakage Findings[/bold red]",
            border_style="red",
            header_style="bold yellow",
            expand=True
        )
        f_table.add_column("Severity", width=10)
        f_table.add_column("Category", style="cyan", width=18)
        f_table.add_column("Finding Title", style="bold white", width=30)
        f_table.add_column("Endpoint", style="dim white")
        f_table.add_column("Disclosed Snippet", style="italic gray")

        for url, f in all_findings:
            sev_color = get_severity_color(f.severity.value if hasattr(f.severity, 'value') else str(f.severity))
            cat_str = f.category.value if hasattr(f.category, 'value') else str(f.category)
            snippet_str = (f.snippet or f.detail)[:60].replace("\n", " ")
            f_table.add_row(
                f"[{sev_color}]{f.severity}[/]",
                cat_str,
                f.title,
                url,
                snippet_str
            )

        console.print(f_table)
        console.print()

    # 3. Overall Telemetry Summary Panel
    rating_color = get_severity_color(scan_result.overall_severity_rating)

    summary_grid = Table.grid(expand=True, padding=(0, 2))
    summary_grid.add_column(style="bold yellow")
    summary_grid.add_column(style="bold white")
    summary_grid.add_column(style="bold yellow")
    summary_grid.add_column(style="bold white")

    summary_grid.add_row("🎯 Target:", scan_result.target_url, "⏱️  Duration:", f"{scan_result.duration_seconds:.2f}s")
    summary_grid.add_row("📊 Total Endpoints:", str(scan_result.total_endpoints), "🚨 Total Findings:", f"[bold red]{scan_result.total_findings}[/bold red]")
    summary_grid.add_row("🔥 Overall Risk Score:", f"[{rating_color}]{scan_result.overall_score:.2f} / 100.0[/{rating_color}]", "🛡️  Severity Rating:", f"[{rating_color}]{scan_result.overall_severity_rating}[/{rating_color}]")

    summary_panel = Panel(
        summary_grid,
        title="[bold green]📊 Scan Telemetry & Risk Summary[/bold green]",
        border_style="green",
        padding=(1, 2)
    )
    console.print(summary_panel)

def run_interactive_shell(default_target: str = "http://127.0.0.1:8888"):
    """Launches DriftSentry-style interactive command prompt REPL."""
    os.system("clear" if os.name != "nt" else "cls")
    print_banner(interactive=True)

    current_target = default_target
    engine = EMLAEngine()

    while True:
        try:
            target_display = current_target or "no-target"
            prompt_str = f"[bold cyan]emla[/bold cyan] ([bold yellow]{target_display}[/bold yellow]) > "
            
            if HAS_RICH:
                user_input = console.input(prompt_str).strip()
            else:
                user_input = input(f"emla ({target_display}) > ").strip()

            if not user_input:
                continue

            parts = shlex.split(user_input)
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ["exit", "quit", "q"]:
                if HAS_RICH:
                    console.print("[bold yellow]Exiting EMLA Security Suite. Goodbye![/bold yellow]")
                else:
                    print("Exiting EMLA Security Suite. Goodbye!")
                break

            elif cmd == "clear":
                os.system("clear" if os.name != "nt" else "cls")
                print_banner(interactive=True)

            elif cmd == "help":
                show_help()

            elif cmd in ["target", "set"]:
                if args:
                    new_t = args[0] if len(args) == 1 else args[1] if args[0] in ["target", "url"] else args[0]
                    if not new_t.startswith("http://") and not new_t.startswith("https://"):
                        new_t = "http://" + new_t
                    current_target = new_t
                    if HAS_RICH:
                        console.print(f"[bold green][+] Target URL updated to:[bold green] {current_target}")
                    else:
                        print(f"[+] Target URL updated to: {current_target}")
                else:
                    if HAS_RICH:
                        console.print(f"[bold yellow][*] Current Target URL:[bold yellow] {current_target}")
                    else:
                        print(f"[*] Current Target URL: {current_target}")

            elif cmd == "scan":
                target_to_scan = args[0] if args else current_target
                if not target_to_scan or target_to_scan == "no-target":
                    if HAS_RICH:
                        console.print("[bold red][!] Error: No target URL specified. Set target with 'target <URL>' first.[bold red]")
                    else:
                        print("[!] Error: No target URL specified.")
                    continue

                if not target_to_scan.startswith("http://") and not target_to_scan.startswith("https://"):
                    target_to_scan = "http://" + target_to_scan

                single_url = "--single-url" in args
                output_file = "report.json"
                if "-o" in args:
                    idx = args.index("-o")
                    if idx + 1 < len(args):
                        output_file = args[idx + 1]

                render_scan_config(target_to_scan, single_url, 3, 50, output_file)

                if HAS_RICH:
                    console.print("\n[bold cyan][*] Executing Crawl & Error Provocation Scan...[/bold cyan]")
                else:
                    print("\n[*] Executing Crawl & Error Provocation Scan...")

                scan_result = engine.scan(
                    target_url=target_to_scan,
                    single_url=single_url,
                    max_depth=3,
                    max_pages=50,
                    verbose=False
                )

                reporter = JSONReporter()
                saved_path = reporter.save_report(scan_result, output_file)

                render_scan_results(scan_result)

                if HAS_RICH:
                    console.print(f"\n[bold green][+] Scan complete! Full JSON report saved to:[bold green] {saved_path}\n")
                else:
                    print(f"\n[+] Scan complete! Full JSON report saved to: {saved_path}\n")

            elif cmd == "report":
                report_file = args[0] if args else "report.json"
                if os.path.exists(report_file):
                    if HAS_RICH:
                        with open(report_file, "r") as f:
                            console.print_json(f.read())
                    else:
                        with open(report_file, "r") as f:
                            print(f.read())
                else:
                    if HAS_RICH:
                        console.print(f"[bold red][!] Report file '{report_file}' not found. Run a scan first![/bold red]")
                    else:
                        print(f"[!] Report file '{report_file}' not found.")

            else:
                if HAS_RICH:
                    console.print(f"[bold red][!] Unknown command '{cmd}'. Type 'help' for command list.[/bold red]")
                else:
                    print(f"[!] Unknown command '{cmd}'. Type 'help' for command list.")

        except (KeyboardInterrupt, EOFError):
            print("\nExiting EMLA.")
            break
        except Exception as e:
            if HAS_RICH:
                console.print(f"[bold red][!] Error: {str(e)}[/bold red]")
            else:
                print(f"[!] Error: {str(e)}")

def show_help():
    """Displays rich help menu table."""
    if HAS_RICH:
        table = Table(
            title="[bold cyan]🛠️  EMLA Interactive Command Reference[/bold cyan]",
            border_style="bright_blue",
            header_style="bold yellow",
            expand=True
        )
        table.add_column("Command", style="bold green", width=22)
        table.add_column("Arguments", style="bold white", width=25)
        table.add_column("Description", style="dim white")

        table.add_row("target <URL>", "http://target.com", "Set active target URL for interactive scans")
        table.add_row("scan [URL]", "[--single-url] [-o file]", "Execute vulnerability crawl & error leakage scan")
        table.add_row("report [path]", "[report.json]", "Display formatted JSON scan report content")
        table.add_row("clear", "-", "Clear terminal screen and redraw EMLA header panel")
        table.add_row("help", "-", "Show this interactive command menu")
        table.add_row("exit / q", "-", "Quit EMLA Security Suite")

        console.print(table)
    else:
        print("\n--- EMLA Interactive Help Menu ---")
        print("  target <URL>               : Set target URL")
        print("  scan [URL] [--single-url]  : Run vulnerability scan")
        print("  report [file]              : View JSON report")
        print("  clear                      : Clear screen")
        print("  help                       : Display help menu")
        print("  exit / q                   : Quit program\n")
