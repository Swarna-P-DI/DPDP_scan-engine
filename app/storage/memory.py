from __future__ import annotations

from copy import deepcopy
from typing import Any


class InMemoryReportStore:
    def __init__(self) -> None:
        self._latest: dict[str, Any] | None = None
        self._reports: dict[str, dict[str, Any]] = {}

    def save(self, report: dict[str, Any]) -> dict[str, Any]:
        run_id = report["metadata"]["run_id"]
        self._reports[run_id] = deepcopy(report)
        self._latest = deepcopy(report)
        return report

    def latest(self) -> dict[str, Any]:
        return deepcopy(self._latest or _empty_report())


def _empty_report() -> dict[str, Any]:
    return {
        "summary": {"status": "no_scan_run"},
        "metadata": {},
        "profiling": {},
        "pii_findings": [],
        "pii_index": [],
        "pii_summary": {"by_type": {}, "by_source": {}, "exposure": {"masked": 0, "encrypted": 0, "unprotected": 0}, "total": 0},
        "risk_heatmap": {"high": 0, "medium": 0, "low": 0, "table_level": {"high": 0, "medium": 0, "low": 0}, "dataset_level": {"high": 0, "medium": 0, "low": 0}},
        "raid": {"risks": [], "issues": [], "assumptions": [], "dependencies": [], "recommendations": []},
        "compliance_status": [],
        "data_intelligence": {"what": [], "where": [], "how": []},
        "ownership_details": [],
        "latency_stats": {"count": 0, "avg_ms": 0, "max_ms": 0, "records": []},
    }


report_store = InMemoryReportStore()
