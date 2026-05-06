import logging

from backend.services.scan_evidence import (
    build_data_findings_and_raid,
)

logger = logging.getLogger(__name__)


def gap_analysis_agent(state):
    logger.info("Gap Analysis Agent")

    findings, raid = build_data_findings_and_raid(
        state["source_inventory"],
        state.get("schema_analysis") or {},
        state["profiling"],
        state.get("dq_report") or {},
        state.get("column_intelligence") or {}
    )

    for violation in state.get("document_violations", []) or []:
        severity = violation.get("severity", "medium")
        findings["gaps"].append({
            "type": violation.get("type", "document_alignment"),
            "description": violation.get("description"),
            "evidence": f"Document rule mismatch in {violation.get('doc_id')}",
            "owner": "Data Engineering / Data Steward",
            "severity": severity,
            "table": violation.get("table"),
            "field": violation.get("field"),
            "expected": violation.get("expected"),
            "actual": violation.get("actual"),
            "doc_id": violation.get("doc_id"),
        })
        findings["data_issues"].append(violation.get("description"))
        findings["recommendations"].append({
            "action": f"Align {violation.get('field')} with document expectation from {violation.get('doc_id')}.",
            "type": violation.get("type", "document_alignment"),
            "priority": "high" if severity == "high" else "medium",
            "owner": "Data Engineering / Data Steward",
            "reason": violation.get("description"),
        })

    return {"gap_analysis": findings}
