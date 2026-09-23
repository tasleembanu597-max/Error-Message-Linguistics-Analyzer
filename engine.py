import time
from datetime import datetime, timezone
import urllib.parse
from typing import List, Dict, Any, Optional

from emla.models import (
    DiscoveredEndpoint,
    EndpointResult,
    ScanResult,
    Finding,
    Severity,
    FindingCategory
)
from emla.crawler import WebCrawler
from emla.trigger import ErrorTriggerModule
from emla.analyzer import ResponseAnalyzer
from emla.scoring import ScoringEngine, ScoringConfig

class EMLAEngine:
    """Orchestrates end-to-end security crawl, error provocation, linguistic analysis, and scoring."""

    def __init__(
        self,
        trigger_timeout: float = 5.0,
        scoring_config: Optional[ScoringConfig] = None
    ):
        self.trigger_timeout = trigger_timeout
        self.scoring_config = scoring_config or ScoringConfig()
        self.analyzer = ResponseAnalyzer()
        self.scoring_engine = ScoringEngine(self.scoring_config)
        self.trigger_module = ErrorTriggerModule(timeout=self.trigger_timeout)

    def scan(
        self,
        target_url: str,
        single_url: bool = False,
        max_depth: int = 3,
        max_pages: int = 50,
        exclude_paths: Optional[List[str]] = None,
        verbose: bool = False
    ) -> ScanResult:
        """Executes full scan pipeline against target URL."""
        start_time = time.time()
        start_timestamp = datetime.now(timezone.utc).isoformat()

        target_url_clean = target_url.rstrip("/")
        discovered: List[DiscoveredEndpoint] = []

        if single_url:
            parsed = urllib.parse.urlparse(target_url_clean)
            query_params = list(urllib.parse.parse_qs(parsed.query).keys())
            discovered = [
                DiscoveredEndpoint(
                    url=target_url_clean,
                    method="GET",
                    params=query_params
                )
            ]
        else:
            crawler = WebCrawler(
                base_url=target_url_clean,
                max_depth=max_depth,
                max_pages=max_pages,
                exclude_paths=exclude_paths
            )
            discovered = crawler.crawl()
            # Fallback: ensure target URL is included if crawler returns empty
            if not discovered:
                parsed = urllib.parse.urlparse(target_url_clean)
                query_params = list(urllib.parse.parse_qs(parsed.query).keys())
                discovered = [
                    DiscoveredEndpoint(
                        url=target_url_clean,
                        method="GET",
                        params=query_params
                    )
                ]

        endpoint_results: List[EndpointResult] = []
        all_findings: List[Finding] = []
        severity_breakdown: Dict[str, int] = {s.value: 0 for s in Severity}
        category_breakdown: Dict[str, int] = {c.value: 0 for c in FindingCategory}

        for ep in discovered:
            triggers = self.trigger_module.generate_triggers(ep)
            response_findings_list: List[List[Finding]] = []
            flat_ep_findings: List[Finding] = []
            status_codes = []

            for resp in triggers:
                status_codes.append(resp.status_code)
                findings = self.analyzer.analyze_response(resp)
                response_findings_list.append(findings)
                flat_ep_findings.extend(findings)

            # Score endpoint
            score_detail = self.scoring_engine.calculate_endpoint_score(response_findings_list)
            
            # Summarize findings for this endpoint
            ep_summary: Dict[str, int] = {}
            for f in flat_ep_findings:
                ep_summary[f.severity.value] = ep_summary.get(f.severity.value, 0) + 1
                severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1
                category_breakdown[f.category.value] = category_breakdown.get(f.category.value, 0) + 1
                all_findings.append(f)

            primary_status = status_codes[0] if status_codes else 200

            endpoint_results.append(
                EndpointResult(
                    url=ep.url,
                    status_code=primary_status,
                    findings=flat_ep_findings,
                    score=score_detail.aggregated_score,
                    summary=ep_summary,
                    method=ep.method,
                    score_detail=score_detail
                )
            )

        # Overall target score calculation
        if endpoint_results:
            ep_scores = [ep_res.score for ep_res in endpoint_results]
            max_score = max(ep_scores)
            avg_score = sum(ep_scores) / len(ep_scores)
            overall_score = round(
                (self.scoring_config.worst_case_weight * max_score) +
                (self.scoring_config.average_case_weight * avg_score),
                2
            )
        else:
            overall_score = 0.0

        overall_rating = self.scoring_engine.get_severity_rating(overall_score)
        duration = round(time.time() - start_time, 3)

        return ScanResult(
            target_url=target_url_clean,
            timestamp=start_timestamp,
            duration_seconds=duration,
            single_url_mode=single_url,
            endpoints_scanned=endpoint_results,
            total_endpoints=len(endpoint_results),
            total_findings=len(all_findings),
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
            overall_score=overall_score,
            overall_severity_rating=overall_rating,
            config={
                "max_depth": max_depth,
                "max_pages": max_pages,
                "single_url": single_url,
                "timeout": self.trigger_timeout
            }
        )
