import logging

from config import ENABLE_LLM_SYNTHESIS
from services.scan_evidence import (
    build_data_findings_and_raid,
    compact_profiling,
    compact_source_inventory,
)
from utils.parser import safe_json_parse

logger = logging.getLogger(__name__)


def _llm_synthesis(state, findings, raid):
    from utils.llm import invoke_llm

    prompt = f"""
You are a Senior Data Governance Analyst.

Refine the deterministic data findings and RAID using only the compact evidence.
Do not add facts that are not supported by the evidence.
Return ONLY valid JSON with keys data_findings and raid.

Current Data Findings:
{findings}

Current RAID:
{raid}

Source Inventory:
{compact_source_inventory(state["source_inventory"])}

Schema Analysis:
{state.get("schema_analysis")}

Profiling Evidence:
{compact_profiling(state["profiling"])}

Data Quality Report:
{state.get("dq_report")}
"""

    parsed = safe_json_parse(invoke_llm(prompt))
    if not isinstance(parsed, dict) or parsed.get("error"):
        return findings, raid
    return parsed.get("data_findings", findings), parsed.get("raid", raid)


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

    if ENABLE_LLM_SYNTHESIS:
        findings, raid = _llm_synthesis(state, findings, raid)

    return {"gap_analysis": findings}
