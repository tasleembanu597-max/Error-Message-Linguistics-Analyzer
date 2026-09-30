import pytest
from tests.mock_server import MockServerThread
from emla.crawler import WebCrawler

@pytest.fixture(scope="module")
def mock_server():
    server = MockServerThread(port=8888)
    server.start()
    yield server
    server.stop()

def test_same_domain_check():
    crawler = WebCrawler(base_url="http://localhost:8080")
    assert crawler.is_same_domain("http://localhost:8080/page") is True
    assert crawler.is_same_domain("/relative/path") is True
    assert crawler.is_same_domain("http://external-domain.com/path") is False

def test_exclusion_paths_check():
    crawler = WebCrawler(base_url="http://localhost:8080", exclude_paths=["/logout", "/delete"])
    assert crawler.should_exclude("http://localhost:8080/logout") is True
    assert crawler.should_exclude("http://localhost:8080/delete?id=1") is True
    assert crawler.should_exclude("http://localhost:8080/about") is False

def test_url_normalization():
    crawler = WebCrawler(base_url="http://localhost:8080")
    normalized = crawler.normalize_url("../about#section1", "http://localhost:8080/pages/home")
    assert normalized == "http://localhost:8080/about"

def test_crawler_end_to_end(mock_server):
    crawler = WebCrawler(base_url=mock_server.base_url, max_depth=2, max_pages=10)
    endpoints = crawler.crawl()

    assert len(endpoints) >= 3
    urls = [ep.url for ep in endpoints]
    methods = [ep.method for ep in endpoints]

    # Verify discovered endpoints
    assert any("/about" in u for u in urls)
    assert any("/search" in u for u in urls)
    assert any("/login" in u for u in urls)

    # Verify POST form parameter extraction
    login_ep = next(ep for ep in endpoints if "/login" in ep.url)
    assert login_ep.method == "POST"
    assert "username" in login_ep.params
    assert "password" in login_ep.params
