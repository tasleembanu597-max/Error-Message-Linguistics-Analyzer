from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingCategory(str, Enum):
    STACK_TRACE = "STACK_TRACE"
    FILESYSTEM_PATH = "FILESYSTEM_PATH"
    DATABASE_ERROR = "DATABASE_ERROR"
    FRAMEWORK_VERSION = "FRAMEWORK_VERSION"
    RUNTIME_SERVER = "RUNTIME_SERVER"

@dataclass
class Finding:
    category: FindingCategory
    severity: Severity
    title: str
    detail: str
    snippet: Optional[str] = None
    confidence: str = "HIGH"

@dataclass
class ErrorResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    method: str = "GET"
    params: Optional[Dict[str, Any]] = None

@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)

@dataclass
class EndpointResult:
    url: str
    status_code: int
    findings: List[Finding] = field(default_factory=list)
    score: float = 0.0
    summary: Dict[str, int] = field(default_factory=dict)
    method: str = "GET"
    score_detail: Optional[Any] = None

@dataclass
class ScanResult:
    target_url: str
    timestamp: str
    duration_seconds: float
    single_url_mode: bool
    endpoints_scanned: List[EndpointResult] = field(default_factory=list)
    total_endpoints: int = 0
    total_findings: int = 0
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    category_breakdown: Dict[str, int] = field(default_factory=dict)
    overall_score: float = 0.0
    overall_severity_rating: str = "NONE"
    config: Dict[str, Any] = field(default_factory=dict)

