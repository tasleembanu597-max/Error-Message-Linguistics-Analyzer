import os
import pytest
from tests.mock_server import MockServerThread
from emla.models import (
    ScanResult,
    EndpointResult,
    Finding,
    FindingCategory,
    Severity,
    ScanType,
    ScanIntensity,
    MultiScanResult
)
from emla.engine import EMLAEngine, parse_port_range
from emla.ui import save_scan_reports
from emla.reporter import (
    JSONReporter,
    HTMLReporter,
    MarkdownReporter,
    CSVReporter,
    XMLReporter,
    TextReporter
)

@pytest.fixture(scope="module")
def mock_server():
    server = MockServerThread(port=8894)
    server.start()
    yield server
    server.stop()

@pytest.fixture
def sample_single_result():
    f = Finding(
        category=FindingCategory.STACK_TRACE,
        severity=Severity.CRITICAL,
        title="Traceback Disclosed",
        detail="Traceback detected in response",
        snippet="Traceback (most recent call last):"
    )
    ep = EndpointResult(
        url="http://127.0.0.1:8894/error",
        status_code=500,
        findings=[f],
        score=75.0,
        summary={"CRITICAL": 1},
        method="GET"
    )
    return ScanResult(
        target_url="http://127.0.0.1:8894",
        timestamp="2026-10-10T12:00:00Z",
        duration_seconds=0.45,
        single_url_mode=False,
        endpoints_scanned=[ep],
        total_endpoints=1,
        total_findings=1,
        severity_breakdown={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        category_breakdown={"STACK_TRACE": 1},
        overall_score=75.0,
        overall_severity_rating="CRITICAL",
        config={"scan_type": "ACTIVE", "scan_intensity": "MEDIUM"}
    )

def test_parse_port_range_keywords():
    # Test 'all' and full range
    ports_all = parse_port_range("all")
    assert len(ports_all) == 65535
    assert ports_all[0] == 1
    assert ports_all[-1] == 65535

    ports_full = parse_port_range("1-65535")
    assert len(ports_full) == 65535

    # Test 'web', 'top', 'common'
    ports_web = parse_port_range("web")
    assert 80 in ports_web
    assert 443 in ports_web
    assert 8080 in ports_web
    assert 5173 in ports_web

    # Test custom range & list
    custom = parse_port_range("80, 443, 8000-8004, 8888")
    assert custom == [80, 443, 8000, 8001, 8002, 8003, 8004, 8888]

    # Test malformed parts handled cleanly
    fallback = parse_port_range("invalid, 80, 500-invalid, 443")
    assert fallback == [80, 443]

def test_save_scan_reports_all_formats_single(sample_single_result, tmp_path):
    base_file = str(tmp_path / "single_test_out")
    saved_files = save_scan_reports(sample_single_result, base_file, fmt="all")

    assert len(saved_files) == 6
    exts = [os.path.splitext(f)[1] for f in saved_files]
    assert set(exts) == {".json", ".html", ".md", ".csv", ".xml", ".txt"}

    for sf in saved_files:
        assert os.path.exists(sf)
        assert os.path.getsize(sf) > 0

def test_save_scan_reports_individual_formats(sample_single_result, tmp_path):
    for fmt, ext in [("json", ".json"), ("html", ".html"), ("markdown", ".md"), ("csv", ".csv"), ("xml", ".xml"), ("txt", ".txt")]:
        base_file = str(tmp_path / f"test_{fmt}")
        saved = save_scan_reports(sample_single_result, base_file, fmt=fmt)
        assert len(saved) == 1
        assert saved[0].endswith(ext)
        assert os.path.exists(saved[0])

def test_save_scan_reports_multi_target(mock_server, tmp_path):
    engine = EMLAEngine(trigger_timeout=2.0)
    multi_res = engine.scan_batch(
        target_urls=[mock_server.base_url],
        scan_type=ScanType.QUICK,
        intensity=ScanIntensity.LOW,
        max_workers=1
    )

    base_file = str(tmp_path / "multi_test_out")
    saved_files = save_scan_reports(multi_res, base_file, fmt="all")

    assert len(saved_files) == 6
    for sf in saved_files:
        assert os.path.exists(sf)
        assert os.path.getsize(sf) > 0

def test_scan_ports_discovery_and_scan(mock_server):
    engine = EMLAEngine(trigger_timeout=2.0)
    # Scan with specific port list containing the mock server port (8894)
    res = engine.scan_ports(
        target_host="127.0.0.1",
        ports=[8893, 8894, 8895],
        single_url=True,
        scan_type=ScanType.PASSIVE,
        intensity=ScanIntensity.LOW,
        verbose=True
    )

    assert isinstance(res, MultiScanResult)
    assert res.total_targets >= 1
    # Check that port 8894 was discovered and analyzed
    scanned_urls = [r.target_url for r in res.target_results]
    assert any("8894" in u for u in scanned_urls)

def test_all_scan_types(mock_server):
    engine = EMLAEngine(trigger_timeout=2.0)
    for st in [ScanType.PASSIVE, ScanType.ACTIVE, ScanType.AGGRESSIVE, ScanType.QUICK, ScanType.STANDARD, ScanType.DEEP]:
        res = engine.scan(
            target_url=f"{mock_server.base_url}/search",
            single_url=True,
            scan_type=st,
            intensity=ScanIntensity.LOW
        )
        assert res.config["scan_type"] == st.value
