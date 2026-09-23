from dataclasses import dataclass, field
from typing import List, Dict, Tuple
from emla.models import Finding, FindingCategory

@dataclass
class ScoringConfig:
    """Configurable weights and multipliers for Information Leakage Scoring."""
    # Base leakage weights per category
    base_weights: Dict[FindingCategory, float] = field(default_factory=lambda: {
        FindingCategory.STACK_TRACE: 35.0,
        FindingCategory.DATABASE_ERROR: 25.0,
        FindingCategory.FILESYSTEM_PATH: 15.0,
        FindingCategory.FRAMEWORK_VERSION: 8.0,
        FindingCategory.RUNTIME_SERVER: 3.0,
    })
    
    # Specific title weight overrides for extreme threat disclosures
    title_weights: Dict[str, float] = field(default_factory=lambda: {
        "Django Debug Mode Active": 45.0,
        "Flask / Werkzeug Debugger Exposed": 45.0,
        "Laravel Ignition Debug Screen Exposed": 45.0,
    })

    # Factor applied to secondary (non-anchor) categories in the same response
    secondary_factor: float = 0.30
    
    # Category-diversity multiplier mapping: 1=1.00x, 2=1.15x, 3=1.30x, 4=1.45x, 5+=1.50x (max cap)
    diversity_multipliers: Dict[int, float] = field(default_factory=lambda: {
        0: 0.00,
        1: 1.00,
        2: 1.15,
        3: 1.30,
        4: 1.45,
    })
    max_diversity_multiplier: float = 1.50

    # Endpoint aggregation weights (70% worst-case, 30% average)
    worst_case_weight: float = 0.70
    average_case_weight: float = 0.30

@dataclass
class ResponseScoreDetail:
    score: float
    primary_anchor: Tuple[str, float]
    secondary_contributions: List[Tuple[str, float]]
    distinct_categories_count: int
    diversity_multiplier: float
    deduplicated_findings_count: int
    explanation: str

@dataclass
class EndpointScoreDetail:
    aggregated_score: float
    severity_rating: str
    worst_case_score: float
    average_score: float
    response_details: List[ResponseScoreDetail]
    explanation: str

class ScoringEngine:
    """Computes direct Information Leakage Scores for responses and endpoints."""

    def __init__(self, config: ScoringConfig = None):
        self.config = config or ScoringConfig()

    def get_severity_rating(self, score: float) -> str:
        """Maps a numerical Direct Information Leakage Score to a severity rating."""
        if score == 0.0:
            return "NONE"
        elif score <= 15.0:
            return "LOW"
        elif score <= 40.0:
            return "MEDIUM"
        elif score <= 75.0:
            return "HIGH"
        else:
            return "CRITICAL"

    def get_finding_weight(self, finding: Finding) -> float:
        """Retrieves finding weight checking specific title overrides first."""
        if finding.title in self.config.title_weights:
            return self.config.title_weights[finding.title]
        return self.config.base_weights.get(finding.category, 0.0)

    def calculate_response_score(self, findings: List[Finding]) -> ResponseScoreDetail:
        """Calculates Information Leakage Score for a single response based on its findings."""
        if not findings:
            return ResponseScoreDetail(
                score=0.0,
                primary_anchor=("None", 0.0),
                secondary_contributions=[],
                distinct_categories_count=0,
                diversity_multiplier=0.0,
                deduplicated_findings_count=0,
                explanation="Zero findings detected. Score: 0.0 (Clean)"
            )

        # 1. Deduplicate by category, choosing highest weight per category
        category_max_finding: Dict[FindingCategory, Tuple[Finding, float]] = {}
        for f in findings:
            weight = self.get_finding_weight(f)
            if f.category not in category_max_finding or weight > category_max_finding[f.category][1]:
                category_max_finding[f.category] = (f, weight)

        category_items = [(cat, f.title, w) for cat, (f, w) in category_max_finding.items()]
        # Sort descending by weight
        category_items.sort(key=lambda x: x[2], reverse=True)

        primary_cat, primary_title, primary_weight = category_items[0]
        secondary_items = category_items[1:]

        sec_sum = 0.0
        sec_contributions = []
        for cat, title, w in secondary_items:
            contrib = round(w * self.config.secondary_factor, 2)
            sec_sum += contrib
            sec_contributions.append((title, contrib))

        n_cat = len(category_items)
        multiplier = self.config.diversity_multipliers.get(n_cat, self.config.max_diversity_multiplier)

        raw_sum = primary_weight + sec_sum
        final_score = round(raw_sum * multiplier, 2)

        explanation = (
            f"Primary Anchor: '{primary_title}' ({primary_weight} pts). "
            f"Secondary Contributions: {sec_sum} pts ({len(sec_contributions)} categories). "
            f"Diversity Multiplier: {multiplier}x ({n_cat} distinct categories). "
            f"Final Response Score: {final_score}"
        )

        return ResponseScoreDetail(
            score=final_score,
            primary_anchor=(primary_title, primary_weight),
            secondary_contributions=sec_contributions,
            distinct_categories_count=n_cat,
            diversity_multiplier=multiplier,
            deduplicated_findings_count=len(category_items),
            explanation=explanation
        )

    def calculate_endpoint_score(self, response_findings_list: List[List[Finding]]) -> EndpointScoreDetail:
        """Calculates aggregated Information Leakage Score for an endpoint across multiple response runs."""
        if not response_findings_list:
            return EndpointScoreDetail(
                aggregated_score=0.0,
                severity_rating="NONE",
                worst_case_score=0.0,
                average_score=0.0,
                response_details=[],
                explanation="No responses provided. Aggregated Score: 0.0 (NONE)"
            )

        resp_details = [self.calculate_response_score(findings) for findings in response_findings_list]
        scores = [r.score for r in resp_details]

        max_score = max(scores)
        avg_score = sum(scores) / len(scores)

        agg_score = round(
            (self.config.worst_case_weight * max_score) +
            (self.config.average_case_weight * avg_score),
            2
        )
        rating = self.get_severity_rating(agg_score)

        explanation = (
            f"Worst-Case Response Score: {max_score}, Average Score: {avg_score:.2f}. "
            f"Aggregated Formula: (0.70 * {max_score}) + (0.30 * {avg_score:.2f}) = {agg_score}. "
            f"Rating: {rating}"
        )

        return EndpointScoreDetail(
            aggregated_score=agg_score,
            severity_rating=rating,
            worst_case_score=max_score,
            average_score=avg_score,
            response_details=resp_details,
            explanation=explanation
        )
