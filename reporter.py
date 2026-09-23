import json
import os
from typing import Dict, Any
from emla.models import ScanResult, FindingCategory, Severity
from emla import __version__

class JSONReporter:
    """Serializes EMLA ScanResult objects into structured JSON documents."""

    def to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Converts ScanResult into a clean, serializable dictionary."""
        endpoints_data = []
        for ep in scan_result.endpoints_scanned:
            findings_data = []
            for f in ep.findings:
                findings_data.append({
                    "category": f.category.value if isinstance(f.category, FindingCategory) else str(f.category),
                    "severity": f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
                    "title": f.title,
                    "detail": f.detail,
                    "snippet": f.snippet,
                    "confidence": f.confidence
                })

            ep_dict = {
                "url": ep.url,
                "method": ep.method,
                "status_code": ep.status_code,
                "aggregated_score": ep.score,
                "findings_count": len(ep.findings),
                "findings_summary": ep.summary,
                "findings": findings_data
            }

            if ep.score_detail and hasattr(ep.score_detail, "explanation"):
                ep_dict["score_explanation"] = ep.score_detail.explanation

            endpoints_data.append(ep_dict)

        report = {
            "scan_metadata": {
                "target_url": scan_result.target_url,
                "timestamp": scan_result.timestamp,
                "duration_seconds": scan_result.duration_seconds,
                "emla_version": __version__,
                "configuration": scan_result.config
            },
            "summary": {
                "overall_score": scan_result.overall_score,
                "overall_severity_rating": scan_result.overall_severity_rating,
                "total_endpoints_scanned": scan_result.total_endpoints,
                "total_findings_count": scan_result.total_findings,
                "severity_breakdown": scan_result.severity_breakdown,
                "category_breakdown": scan_result.category_breakdown
            },
            "endpoints": endpoints_data
        }
        return report

    def to_json(self, scan_result: ScanResult, indent: int = 2) -> str:
        """Serializes ScanResult into formatted JSON string."""
        return json.dumps(self.to_dict(scan_result), indent=indent)

    def save_report(self, scan_result: ScanResult, filepath: str = "report.json") -> str:
        """Saves JSON report to specified file path."""
        json_str = self.to_json(scan_result)
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(json_str)
        return os.path.abspath(filepath)
