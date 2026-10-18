import pytest
from tests.mock_server import MockServerThread
from emla.engine import EMLAEngine
from emla.models import ScanType, ScanIntensity, MultiScanResult
from emla.reporter import JSONReporter, HTMLReporter, MarkdownReporter, CSVReporter

@pytest.fixture(scope="module")
def mock_servers():
    server1 = MockServerThread(port=8890)
    server2 = MockServerThread(port=8891)
    server1.start()
    server2.start()
    yield [server1.base_url, server2.base_url]
    server1.stop()
    server2.stop()

def test_multi_target_batch_scan(mock_servers):
    engine = EMLAEngine(trigger_timeout=3.0)
    multi_res = engine.scan_batch(
        target_urls=mock_servers,
        scan_type=ScanType.QUICK,
        intensity=ScanIntensity.LOW,
        max_workers=2
    )

    assert isinstance(multi_res, MultiScanResult)
    assert multi_res.total_targets == 2
    assert len(multi_res.target_results) == 2
    assert multi_res.total_endpoints >= 2

def test_scan_types_and_intensities(mock_servers):
    engine = EMLAEngine(trigger_timeout=3.0)
    target = mock_servers[0]

    # Quick scan + Low intensity
    res_quick = engine.scan(target, scan_type=ScanType.QUICK, intensity=ScanIntensity.LOW)
    assert res_quick.config["scan_type"] == "QUICK"
    assert res_quick.config["scan_intensity"] == "LOW"

    # Deep scan + High intensity
    res_deep = engine.scan(target, scan_type=ScanType.DEEP, intensity=ScanIntensity.HIGH)
    assert res_deep.config["scan_type"] == "DEEP"
    assert res_deep.config["scan_intensity"] == "HIGH"

def test_markdown_and_csv_reporters(mock_servers):
    engine = EMLAEngine(trigger_timeout=3.0)
    res = engine.scan(mock_servers[0], scan_type=ScanType.STANDARD, intensity=ScanIntensity.MEDIUM)

    # Markdown report
    md_reporter = MarkdownReporter()
    md_str = md_reporter.to_markdown(res)
    assert "# 🛡️ EMLA Security Report" in md_str
    assert res.target_url in md_str

    # CSV report
    csv_reporter = CSVReporter()
    csv_str = csv_reporter.to_csv(res)
    assert "Target URL,Endpoint URL,HTTP Method" in csv_str
    assert res.target_url in csv_str

def test_multi_target_reporters(mock_servers):
    engine = EMLAEngine(trigger_timeout=3.0)
    multi_res = engine.scan_batch(mock_servers, scan_type=ScanType.QUICK, intensity=ScanIntensity.LOW)

    # Test JSON multi-target serialization
    json_reporter = JSONReporter()
    json_str = json_reporter.to_json(multi_res)
    assert "batch_metadata" in json_str
    assert "total_targets" in json_str

    # Test HTML multi-target reporting
    html_reporter = HTMLReporter()
    html_out = html_reporter.save_html_report(multi_res, "test_multi_report.html")
    assert "test_multi_report.html" in html_out

    # Test Markdown multi-target reporting
    md_reporter = MarkdownReporter()
    md_str = md_reporter.to_markdown(multi_res)
    assert "Multi-Target Security Summary Report" in md_str

    # Test CSV multi-target reporting
    csv_reporter = CSVReporter()
    csv_str = csv_reporter.to_csv(multi_res)
    assert "8890" in csv_str or "8891" in csv_str
