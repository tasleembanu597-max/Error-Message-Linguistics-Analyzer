import argparse
import sys
from typing import List, Optional
from emla import __version__
from emla.engine import EMLAEngine
from emla.reporter import JSONReporter

def create_parser() -> argparse.ArgumentParser:
    """Constructs CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="emla",
        description="Error Message Linguistics Analyzer (EMLA) - Security Analysis Tool"
    )
    parser.add_argument(
        "-t", "--target", "--url",
        dest="target",
        type=str,
        required=True,
        help="Target URL to analyze (e.g. http://localhost:8080)"
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

def print_banner():
    """Prints EMLA CLI header banner."""
    print("=" * 60)
    print(f" Error Message Linguistics Analyzer (EMLA) v{__version__}")
    print(" Security Analysis & Information Leakage Scoring Engine")
    print("=" * 60)

def main(args: Optional[List[str]] = None) -> int:
    """Main entrypoint for CLI execution."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    print_banner()
    print(f"[*] Target URL: {parsed_args.target}")
    print(f"[*] Mode: {'Single URL' if parsed_args.single_url else 'Crawl Target Domain'}")
    if not parsed_args.single_url:
        print(f"[*] Crawl Config: Max Depth={parsed_args.max_depth}, Max Pages={parsed_args.max_pages}")
    print(f"[*] Output Path: {parsed_args.output}")
    print("-" * 60)

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

        print("\n" + "=" * 60)
        print(" SCAN COMPLETE - SUMMARY RESULTS")
        print("=" * 60)
        print(f" Total Endpoints Scanned: {scan_result.total_endpoints}")
        print(f" Total Findings Count:   {scan_result.total_findings}")
        print(f" Overall Risk Score:     {scan_result.overall_score} / 100.0")
        print(f" Severity Rating:        {scan_result.overall_severity_rating}")
        print("-" * 60)
        print(" Severity Breakdown:")
        for sev, count in scan_result.severity_breakdown.items():
            if count > 0 or parsed_args.verbose:
                print(f"   - {sev:<10}: {count}")
        print("-" * 60)
        print(f"[+] Report saved successfully to: {saved_path}\n")

        return 0

    except Exception as e:
        print(f"\n[!] Error during EMLA scan execution: {str(e)}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
