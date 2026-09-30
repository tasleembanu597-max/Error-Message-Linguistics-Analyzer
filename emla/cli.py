import argparse
import sys
from typing import List, Optional

from emla import __version__
from emla.engine import EMLAEngine
from emla.reporter import JSONReporter
from emla.ui import (
    print_banner,
    render_scan_config,
    render_scan_results,
    run_interactive_shell
)

def create_parser() -> argparse.ArgumentParser:
    """Constructs CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="emla",
        description="Error Message Linguistics Analyzer (EMLA) - Security Analysis & Risk Scoring Suite"
    )
    parser.add_argument(
        "-t", "--target", "--url",
        dest="target",
        type=str,
        default=None,
        help="Target URL to analyze (e.g. http://localhost:8080)"
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Launch interactive software shell mode"
    )
    parser.add_argument(
        "--single-url",
        action="store_true",
        help="Analyze single target URL only (skip web crawling)"
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="Maximum web crawling depth (default: 3)"
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum pages to crawl (default: 50)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="report.json",
        help="Output file path for JSON report (default: report.json)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output during scanning"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"EMLA v{__version__}"
    )
    return parser

def main(args: Optional[List[str]] = None) -> int:
    """Main entrypoint for CLI & Interactive Shell execution."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    # Launch interactive mode if explicitly requested OR if no target URL is provided
    if parsed_args.interactive or not parsed_args.target:
        run_interactive_shell(default_target=parsed_args.target or "http://127.0.0.1:8888")
        return 0

    # Direct CLI scan mode
    print_banner(interactive=False)
    render_scan_config(
        target=parsed_args.target,
        single_url=parsed_args.single_url,
        max_depth=parsed_args.max_depth,
        max_pages=parsed_args.max_pages,
        output_path=parsed_args.output
    )

    try:
        engine = EMLAEngine()
        scan_result = engine.scan(
            target_url=parsed_args.target,
            single_url=parsed_args.single_url,
            max_depth=parsed_args.max_depth,
            max_pages=parsed_args.max_pages,
            verbose=parsed_args.verbose
        )

        reporter = JSONReporter()
        saved_path = reporter.save_report(scan_result, parsed_args.output)

        render_scan_results(scan_result)

        print(f"[+] Full JSON report saved successfully to: {saved_path}\n")
        return 0

    except Exception as e:
        print(f"\n[!] Error during EMLA scan execution: {str(e)}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
