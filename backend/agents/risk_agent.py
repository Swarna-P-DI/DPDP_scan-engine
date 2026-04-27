import logging

from backend.services.risk_engine import issues_to_risks

logger = logging.getLogger(__name__)


def risk_agent(state):
    logger.info("Risk Engine Agent")
    findings = state.get("gap_analysis") or {}
    dq_issues = (state.get("dq_report") or {}).get("table_wise_issues", [])
    issues = list(findings.get("gaps", [])) + [
        {
            "type": "quality",
            "description": item.get("issue"),
            "severity": item.get("severity"),
            "table": item.get("table"),
            "evidence": "profiling metric exceeded threshold",
        }
        for item in dq_issues
    ]
    for result in state.get("unstructured_results", []) or []:
        for finding in result.get("findings", []):
            issues.append({
                "type": "unstructured_pii",
                "description": f"{result.get('file_name')} contains {finding.get('pii_type')} data in {finding.get('field')}.",
                "severity": "high" if finding.get("sensitivity") == "high" else "medium",
                "evidence": finding.get("evidence"),
                "owner": "Data Engineering / Data Steward",
            })
    for violation in state.get("document_violations", []) or []:
        issues.append({
            "type": violation.get("type", "document_alignment"),
            "description": violation.get("description"),
            "severity": "critical" if (
                violation.get("type") == "compliance_gap"
                and str(violation.get("expected")).upper() == "MASKED"
                and str(violation.get("actual")).upper() == "NOT_MASKED"
            ) else violation.get("severity", "medium"),
            "table": violation.get("table"),
            "column": violation.get("field"),
            "evidence": f"Document expectation from {violation.get('doc_id')}",
            "owner": "Data Engineering / Data Steward",
        })
    return issues_to_risks(issues, state.get("column_intelligence") or {})
