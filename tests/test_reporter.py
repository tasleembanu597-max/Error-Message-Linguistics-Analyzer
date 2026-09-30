import json
import pytest
from emla.models import ScanResult, EndpointResult, Finding, FindingCategory, Severity
from emla.reporter import JSONReporter

@pytest.fixture
def sample_scan_result():
    f1 = Finding(
        category=FindingCategory.STACK_TRACE,
        severity=Severity.CRITICAL,
        title="Python Stack Trace Disclosed",
        detail="Traceback detected",
        snippet="Traceback (most recent call last):"
    )
    f2 = Finding(
        category=FindingCategory.FILESYSTEM_PATH,
        severity=Severity.HIGH,
        title="UNIX System File Path Disclosed",
        detail="UNIX path detected",
        snippet="/var/www/app/main.py"
    )
    ep1 = EndpointResult(
        url="http://localhost:8080/about",
        status_code=500,
        findings=[f1, f2],
        score=45.5,
        summary={"CRITICAL": 1, "HIGH": 1},
        method="GET"
    )
    return ScanResult(
        target_url="http://localhost:8080",
        timestamp="2026-09-15T12:00:00Z",
        duration_seconds=1.23,
        single_url_mode=False,
        endpoints_scanned=[ep1],
        total_endpoints=1,
        total_findings=2,
        severity_breakdown={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        category_breakdown={"STACK_TRACE": 1, "FILESYSTEM_PATH": 1},
        overall_score=45.5,
        overall_severity_rating="MEDIUM",
        config={"max_depth": 3, "max_pages": 50}
    )

def test_json_reporter_dict_and_json(sample_scan_result):
    reporter = JSONReporter()
    report_dict = reporter.to_dict(sample_scan_result)

    assert "scan_metadata" in report_dict
    assert "summary" in report_dict
    assert "endpoints" in report_dict

    meta = report_dict["scan_metadata"]
    assert meta["target_url"] == "http://localhost:8080"
    assert meta["emla_version"] == "0.1.0"

    summary = report_dict["summary"]
    assert summary["overall_score"] == 45.5
    assert summary["overall_severity_rating"] == "MEDIUM"
    assert summary["total_endpoints_scanned"] == 1
    assert summary["total_findings_count"] == 2
    assert summary["severity_breakdown"]["CRITICAL"] == 1

    eps = report_dict["endpoints"]
    assert len(eps) == 1
    assert eps[0]["url"] == "http://localhost:8080/about"
    assert len(eps[0]["findings"]) == 2

    # Verify JSON string generation
    json_str = reporter.to_json(sample_scan_result)
    parsed = json.loads(json_str)
    assert parsed["summary"]["overall_score"] == 45.5

def test_json_reporter_save_report(sample_scan_result, tmp_path):
    reporter = JSONReporter()
    output_file = tmp_path / "subfolder" / "custom_report.json"

    saved_path = reporter.save_report(sample_scan_result, str(output_file))
    assert output_file.exists()
    assert saved_path == str(output_file.resolve())

    with open(output_file, "r", encoding="utf-8") as f:
        content = json.load(f)

    assert content["scan_metadata"]["target_url"] == "http://localhost:8080"
    assert content["summary"]["total_findings_count"] == 2
