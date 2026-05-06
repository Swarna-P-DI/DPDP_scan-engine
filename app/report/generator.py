from __future__ import annotations

import statistics
import uuid
from datetime import datetime, timezone
from typing import Any

from app.pii_engine.index import sanitize_findings
from app.reporting.service import consolidated_report


def build_report(
    *,
    file_name: str,
    file_type: str,
    profiling: dict[str, Any],
    findings: list[dict[str, Any]],
    column_risks: list[dict[str, Any]],
    heatmap: dict[str, Any],
    raid: dict[str, Any],
    latency_records: list[dict[str, Any]],
    pii_index: list[dict[str, Any]] | None = None,
    compliance_status: list[dict[str, Any]] | None = None,
    ownership_details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    latencies = [float(item["latency_ms"]) for item in latency_records]
    latency_stats = {
        "count": len(latencies),
        "avg_ms": round(statistics.fmean(latencies), 4) if latencies else 0,
        "p95_ms": round(_percentile(latencies, 0.95), 4) if latencies else 0,
        "max_ms": round(max(latencies), 4) if latencies else 0,
        "target_ms": 1.0,
        "within_target": all(value < 1.0 for value in latencies) if latencies else True,
        "records": latency_records,
    }
    metadata = {
        "run_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "file": file_name,
        "file_type": file_type,
        "engine": "SCAN + RAID PII Intelligence",
        "version": "1.1.0",
    }
    safe_findings = sanitize_findings(findings)
    pii_index = pii_index or []
    compliance_status = compliance_status or []
    consolidated = consolidated_report(
        metadata=metadata,
        profiling=profiling,
        pii_index=pii_index,
        raid=raid,
        compliance=compliance_status,
        ownership_details=ownership_details,
    )
    return {
        "summary": {
            "files_scanned": 1,
            "findings": len(findings),
            "high_risk_findings": heatmap.get("high", 0),
            "medium_risk_findings": heatmap.get("medium", 0),
            "low_risk_findings": heatmap.get("low", 0),
        },
        "metadata": metadata,
        "profiling": profiling,
        "pii_findings": safe_findings,
        "pii_index": pii_index,
        "pii_summary": consolidated["pii_summary"],
        "column_risks": column_risks,
        "risk_heatmap": heatmap,
        "raid": raid,
        "compliance_status": compliance_status,
        "data_intelligence": consolidated["data_intelligence"],
        "ownership_details": ownership_details or [],
        "consolidated_report": consolidated,
        "latency_stats": latency_stats,
        "pdf_ready": {
            "sections": [
                {"title": "Summary", "data": "summary"},
                {"title": "Profiling", "data": "profiling"},
                {"title": "PII Findings", "data": "pii_findings"},
                {"title": "Risk Heatmap", "data": "risk_heatmap"},
                {"title": "RAID", "data": "raid"},
                {"title": "Latency", "data": "latency_stats"},
            ]
        },
    }


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]
