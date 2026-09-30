import urllib.parse
import requests
from bs4 import BeautifulSoup
from typing import List, Set, Dict
from emla.models import DiscoveredEndpoint

class WebCrawler:
    """Crawls authorized web application endpoints within strict domain scope boundaries."""

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        exclude_paths: List[str] = None
    ):
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        self.target_domain = parsed.netloc.lower()
        self.scheme = parsed.scheme or "http"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.exclude_paths = exclude_paths or ["/logout", "/delete", "/exit"]

        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Dict[str, DiscoveredEndpoint] = {}

    def is_same_domain(self, url: str) -> bool:
        """Enforces domain/origin boundary matching."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc:  # Relative link
            return True
        return parsed.netloc.lower() == self.target_domain

    def should_exclude(self, url: str) -> bool:
        """Checks if URL matches excluded path patterns."""
        path = urllib.parse.urlparse(url).path.lower()
        return any(ex.lower() in path for ex in self.exclude_paths)

    def normalize_url(self, link: str, current_url: str) -> str:
        """Normalizes relative links to absolute URLs and strips fragments."""
        absolute = urllib.parse.urljoin(current_url, link)
        parsed = urllib.parse.urlparse(absolute)
        # Reconstruct without fragment (#) or trailing duplicate slashes
        clean_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") if parsed.path != "/" else "/",
            parsed.params,
            parsed.query,
            ""  # No fragment
        ))
        return clean_url

    def crawl(self) -> List[DiscoveredEndpoint]:
        """Executes crawl starting from base_url up to max_depth/max_pages limits."""
        queue = [(self.base_url, 0)]

        while queue and len(self.visited_urls) < self.max_pages:
            current_url, depth = queue.pop(0)

            if current_url in self.visited_urls or depth > self.max_depth:
                continue

            if not self.is_same_domain(current_url) or self.should_exclude(current_url):
                continue

            self.visited_urls.add(current_url)

            # Record GET endpoint
            parsed_query = urllib.parse.parse_qs(urllib.parse.urlparse(current_url).query)
            query_params = list(parsed_query.keys())
            
            endpoint_key = f"GET:{urllib.parse.urlparse(current_url).path or '/'}"
            if endpoint_key not in self.discovered_endpoints:
                self.discovered_endpoints[endpoint_key] = DiscoveredEndpoint(
                    url=current_url,
                    method="GET",
                    params=query_params
                )

            try:
                response = requests.get(current_url, timeout=5, headers={"User-Agent": "EMLA-Security-Crawler/1.0"})
                if "text/html" not in response.headers.get("Content-Type", ""):
                    continue

                soup = BeautifulSoup(response.text, "html.parser")

                # 1. Discover <a> links
                for a_tag in soup.find_all("a", href=True):
                    next_url = self.normalize_url(a_tag["href"], current_url)
                    if next_url not in self.visited_urls and self.is_same_domain(next_url):
                        queue.append((next_url, depth + 1))

                # 2. Discover <form> endpoints
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action", "")
                    form_url = self.normalize_url(action, current_url)
                    method = form_tag.get("method", "GET").upper()

                    inputs = [
                        inp.get("name") for inp in form_tag.find_all(["input", "select", "textarea"])
                        if inp.get("name")
                    ]

                    form_key = f"{method}:{urllib.parse.urlparse(form_url).path or '/'}"
                    if form_key not in self.discovered_endpoints:
                        self.discovered_endpoints[form_key] = DiscoveredEndpoint(
                            url=form_url,
                            method=method,
                            params=inputs
                        )

            except requests.RequestException:
                continue

        return list(self.discovered_endpoints.values())
