"""Error Message Linguistics Analyzer (EMLA) package."""

__version__ = "0.1.0"

from emla.models import (
    Finding,
    FindingCategory,
    Severity,
    ErrorResponse,
    DiscoveredEndpoint,
    EndpointResult,
    ScanResult
)
from emla.analyzer import ResponseAnalyzer
from emla.scoring import ScoringEngine, ScoringConfig
from emla.crawler import WebCrawler
from emla.trigger import ErrorTriggerModule
from emla.engine import EMLAEngine
from emla.reporter import JSONReporter


__all__ = [
    "Finding",
    "FindingCategory",
    "Severity",
    "ErrorResponse",
    "DiscoveredEndpoint",
    "EndpointResult",
    "ScanResult",
    "ResponseAnalyzer",
    "ScoringEngine",
    "ScoringConfig",
    "WebCrawler",
    "ErrorTriggerModule",
    "EMLAEngine",
    "JSONReporter",
    "__version__"
]
