import pytest
from tests.mock_server import MockServerThread
from emla.engine import EMLAEngine
from emla.models import ScanResult

@pytest.fixture(scope="module")
def mock_server():
    server = MockServerThread(port=8889)
    server.start()
    yield server
    server.stop()

def test_engine_single_url_scan(mock_server):
    engine = EMLAEngine()
    result = engine.scan(f"{mock_server.base_url}/about", single_url=True)

    assert isinstance(result, ScanResult)
    assert result.single_url_mode is True
    assert result.total_endpoints == 1
    assert result.target_url == f"{mock_server.base_url}/about"
    assert result.duration_seconds >= 0.0
    assert result.overall_severity_rating in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_engine_full_crawl_scan(mock_server):
    engine = EMLAEngine()
    result = engine.scan(mock_server.base_url, single_url=False, max_depth=2, max_pages=10)

    assert isinstance(result, ScanResult)
    assert result.single_url_mode is False
    assert result.total_endpoints >= 3
    assert result.total_findings >= 1
    assert "CRITICAL" in result.severity_breakdown or "HIGH" in result.severity_breakdown
    assert len(result.endpoints_scanned) >= 3

def test_engine_with_custom_scoring_config(mock_server):
    from emla.scoring import ScoringConfig
    custom_config = ScoringConfig(worst_case_weight=0.5, average_case_weight=0.5)
    engine = EMLAEngine(scoring_config=custom_config)

    result = engine.scan(f"{mock_server.base_url}/login", single_url=True)
    assert result.total_endpoints == 1
    assert result.overall_score >= 0.0
