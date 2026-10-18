import pytest
from tests.mock_server import MockServerThread
from emla.models import DiscoveredEndpoint, ScanType, ScanIntensity
from emla.trigger import ErrorTriggerModule
from emla.reporter import XMLReporter, TextReporter
from emla.engine import EMLAEngine

@pytest.fixture(scope="module")
def mock_server():
    server = MockServerThread(port=8892)
    server.start()
    yield server
    server.stop()

def test_passive_scan_mode_zero_triggers(mock_server):
    trigger = ErrorTriggerModule(timeout=3.0)
    ep = DiscoveredEndpoint(url=f"{mock_server.base_url}/search", method="GET", params=["q"])
    
    # PASSIVE mode should generate ONLY 1 base request (0 error provocation triggers)
    triggers = trigger.generate_triggers(ep, scan_type=ScanType.PASSIVE)
    assert len(triggers) == 1

def test_active_scan_mode_triggers(mock_server):
    trigger = ErrorTriggerModule(timeout=3.0)
    ep = DiscoveredEndpoint(url=f"{mock_server.base_url}/search", method="GET", params=["q"])
    
    # ACTIVE mode generates standard triggers
    triggers = trigger.generate_triggers(ep, scan_type=ScanType.ACTIVE, intensity=ScanIntensity.MEDIUM)
    assert len(triggers) == 5

def test_aggressive_scan_mode_triggers(mock_server):
    trigger = ErrorTriggerModule(timeout=3.0)
    ep = DiscoveredEndpoint(url=f"{mock_server.base_url}/search", method="GET", params=["q"])
    
    # AGGRESSIVE mode generates exhaustive triggers
    triggers = trigger.generate_triggers(ep, scan_type=ScanType.AGGRESSIVE, intensity=ScanIntensity.HIGH)
    assert len(triggers) >= 8

def test_xml_and_text_reporters(mock_server):
    engine = EMLAEngine(trigger_timeout=3.0)
    res = engine.scan(mock_server.base_url, scan_type=ScanType.PASSIVE)

    # XML Reporter
    xml_rep = XMLReporter()
    xml_str = xml_rep.to_xml(res)
    assert "<testsuites" in xml_str
    assert mock_server.base_url in xml_str

    # Text Reporter
    txt_rep = TextReporter()
    txt_str = txt_rep.to_text(res)
    assert "EMLA SECURITY ANALYSIS SUMMARY REPORT" in txt_str
    assert res.target_url in txt_str
