import pytest
from tests.mock_server import MockServerThread
from emla.models import DiscoveredEndpoint
from emla.trigger import ErrorTriggerModule
from emla.analyzer import ResponseAnalyzer

@pytest.fixture(scope="module")
def mock_server():
    server = MockServerThread(port=8889)
    server.start()
    yield server
    server.stop()

@pytest.fixture
def trigger_module():
    return ErrorTriggerModule(timeout=3.0)

def test_trigger_generation_count(trigger_module):
    ep = DiscoveredEndpoint(url="http://localhost:8889/search", method="GET", params=["q"])
    # Should generate 5 trigger requests: Type Mismatch, Missing Param, Special Chars, Verb Switch, Malformed Header
    triggers = trigger_module.generate_triggers(ep)
    assert len(triggers) == 5

def test_trigger_execution_against_mock(mock_server, trigger_module):
    search_ep = DiscoveredEndpoint(url=f"{mock_server.base_url}/search", method="GET", params=["q"])
    responses = trigger_module.generate_triggers(search_ep)

    # Inspect responses for 500 status code triggers
    error_resps = [r for r in responses if r.status_code == 500]
    assert len(error_resps) >= 2  # Type mismatch and Special chars triggers return 500

    # Test integration with ResponseAnalyzer
    analyzer = ResponseAnalyzer()
    all_findings = []
    for r in responses:
        findings = analyzer.analyze_response(r)
        all_findings.extend(findings)

    # Verify python traceback or SQL syntax error findings were detected
    titles = [f.title for f in all_findings]
    assert "Python Stack Trace Disclosed" in titles or "MySQL / MariaDB Error Disclosed" in titles

def test_post_trigger_execution_against_mock(mock_server, trigger_module):
    login_ep = DiscoveredEndpoint(url=f"{mock_server.base_url}/login", method="POST", params=["username", "password"])
    responses = trigger_module.generate_triggers(login_ep)

    analyzer = ResponseAnalyzer()
    all_findings = []
    for r in responses:
        findings = analyzer.analyze_response(r)
        all_findings.extend(findings)

    titles = [f.title for f in all_findings]
    assert "PHP Exception / Stack Trace Disclosed" in titles or "X-Powered-By Header Disclosed" in titles
