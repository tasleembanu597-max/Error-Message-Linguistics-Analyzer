import pytest
from emla.models import Finding, FindingCategory, Severity
from emla.scoring import ScoringEngine, ScoringConfig

@pytest.fixture
def engine():
    return ScoringEngine()

def test_zero_leakage_response(engine):
    findings = []
    detail = engine.calculate_response_score(findings)
    assert detail.score == 0.0
    assert detail.distinct_categories_count == 0
    assert detail.diversity_multiplier == 0.0
    assert engine.get_severity_rating(detail.score) == "NONE"

def test_single_finding_response(engine):
    findings = [
        Finding(
            category=FindingCategory.RUNTIME_SERVER,
            severity=Severity.LOW,
            title="Detailed Server Header Disclosed",
            detail="Server: Apache/2.4.41"
        )
    ]
    detail = engine.calculate_response_score(findings)
    assert detail.score == 3.0
    assert detail.distinct_categories_count == 1
    assert detail.diversity_multiplier == 1.00
    assert engine.get_severity_rating(detail.score) == "LOW"

def test_single_high_finding_response(engine):
    findings = [
        Finding(
            category=FindingCategory.DATABASE_ERROR,
            severity=Severity.HIGH,
            title="MySQL / MariaDB Error Disclosed",
            detail="SQL syntax error"
        )
    ]
    detail = engine.calculate_response_score(findings)
    assert detail.score == 25.0
    assert detail.distinct_categories_count == 1
    assert detail.diversity_multiplier == 1.00
    assert engine.get_severity_rating(detail.score) == "MEDIUM"

def test_multi_category_response(engine):
    findings = [
        Finding(
            category=FindingCategory.FRAMEWORK_VERSION,
            severity=Severity.HIGH,
            title="Django Debug Mode Active",
            detail="DEBUG = True"
        ),
        Finding(
            category=FindingCategory.STACK_TRACE,
            severity=Severity.CRITICAL,
            title="Python Stack Trace Disclosed",
            detail="Traceback"
        ),
        Finding(
            category=FindingCategory.FILESYSTEM_PATH,
            severity=Severity.HIGH,
            title="UNIX System File Path Disclosed",
            detail="/var/www/app/models.py"
        )
    ]
    # Primary Anchor: Django Debug Mode Active (45.0)
    # Secondary: Stack Trace (35.0 * 0.3 = 10.5), Path (15.0 * 0.3 = 4.5) -> Sum = 15.0
    # Sum: 45.0 + 15.0 = 60.0
    # Multiplier (3 categories): 1.30
    # Score: 60.0 * 1.30 = 78.0
    detail = engine.calculate_response_score(findings)
    assert detail.score == 78.0
    assert detail.distinct_categories_count == 3
    assert detail.diversity_multiplier == 1.30
    assert engine.get_severity_rating(detail.score) == "CRITICAL"

def test_category_deduplication(engine):
    # 3 findings of the SAME category (FILESYSTEM_PATH)
    findings = [
        Finding(category=FindingCategory.FILESYSTEM_PATH, severity=Severity.HIGH, title="UNIX System File Path Disclosed", detail="/var/www/a.py"),
        Finding(category=FindingCategory.FILESYSTEM_PATH, severity=Severity.HIGH, title="UNIX System File Path Disclosed", detail="/var/www/b.py"),
        Finding(category=FindingCategory.FILESYSTEM_PATH, severity=Severity.HIGH, title="UNIX System File Path Disclosed", detail="/var/www/c.py")
    ]
    detail = engine.calculate_response_score(findings)
    assert detail.score == 15.0  # Only counted once
    assert detail.distinct_categories_count == 1
    assert detail.deduplicated_findings_count == 1
    assert engine.get_severity_rating(detail.score) == "LOW"

def test_endpoint_aggregation(engine):
    # Response 1: MySQL Error (25.0)
    r1 = [Finding(category=FindingCategory.DATABASE_ERROR, severity=Severity.HIGH, title="MySQL / MariaDB Error Disclosed", detail="error")]
    
    # Response 2: Django Debug + Stack Trace + Path (78.0)
    r2 = [
        Finding(category=FindingCategory.FRAMEWORK_VERSION, severity=Severity.HIGH, title="Django Debug Mode Active", detail="DEBUG=True"),
        Finding(category=FindingCategory.STACK_TRACE, severity=Severity.CRITICAL, title="Python Stack Trace Disclosed", detail="Traceback"),
        Finding(category=FindingCategory.FILESYSTEM_PATH, severity=Severity.HIGH, title="UNIX System File Path Disclosed", detail="/var/www/app")
    ]

    endpoint_detail = engine.calculate_endpoint_score([r1, r2])
    # Max = 78.0, Avg = (25.0 + 78.0) / 2 = 51.5
    # Agg Score = (0.70 * 78.0) + (0.30 * 51.5) = 54.6 + 15.45 = 70.05
    assert endpoint_detail.worst_case_score == 78.0
    assert endpoint_detail.average_score == 51.5
    assert endpoint_detail.aggregated_score == 70.05
    assert endpoint_detail.severity_rating == "HIGH"

def test_custom_config_override():
    custom_config = ScoringConfig(
        base_weights={FindingCategory.STACK_TRACE: 50.0},
        worst_case_weight=1.0,
        average_case_weight=0.0
    )
    custom_engine = ScoringEngine(config=custom_config)
    findings = [Finding(category=FindingCategory.STACK_TRACE, severity=Severity.CRITICAL, title="Custom Trace", detail="trace")]
    
    detail = custom_engine.calculate_response_score(findings)
    assert detail.score == 50.0

    endpoint_detail = custom_engine.calculate_endpoint_score([findings])
    assert endpoint_detail.aggregated_score == 50.0
