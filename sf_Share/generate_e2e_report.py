import json
from tests.mock_server import MockServerThread
from emla.engine import EMLAEngine
from emla.reporter import JSONReporter

def run_e2e_verification():
    print("============================================================")
    print(" Starting EMLA End-to-End Verification Scan against Local Mock Server")
    print("============================================================")
    
    server = MockServerThread(port=8888)
    server.start()
    print("[*] Local Mock Server started at http://127.0.0.1:8888")

    try:
        engine = EMLAEngine()
        print("[*] Executing Crawl & Error Trigger Scan...")
        scan_result = engine.scan(
            target_url="http://127.0.0.1:8888",
            single_url=False,
            max_depth=3,
            max_pages=50,
            verbose=True
        )

        reporter = JSONReporter()
        report_path = reporter.save_report(scan_result, "report.json")
        print(f"[+] Full Scan Report successfully generated and saved to: {report_path}")

        print("\n" + "=" * 60)
        print(" SCAN SUMMARY RESULTS")
        print("=" * 60)
        print(f" Target URL:              {scan_result.target_url}")
        print(f" Total Endpoints Scanned: {scan_result.total_endpoints}")
        print(f" Total Findings Count:   {scan_result.total_findings}")
        print(f" Overall Risk Score:     {scan_result.overall_score} / 100.0")
        print(f" Overall Severity:       {scan_result.overall_severity_rating}")
        print("-" * 60)
        print(" Severity Breakdown:")
        for sev, count in scan_result.severity_breakdown.items():
            print(f"   - {sev:<10}: {count}")
        print("-" * 60)
        print(" Category Breakdown:")
        for cat, count in scan_result.category_breakdown.items():
            print(f"   - {cat:<20}: {count}")
        print("=" * 60)

    finally:
        server.stop()
        print("[*] Local Mock Server stopped cleanly.")

if __name__ == "__main__":
    run_e2e_verification()
