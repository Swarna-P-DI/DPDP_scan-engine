import logging

from backend.services.deduplication import deduplicate_recommendations

logger = logging.getLogger(__name__)


def _priority(severity):
    severity = str(severity or "").lower()
    if severity in {"critical", "high"}:
        return "high"
    if severity == "medium":
        return "medium"
    return "low"


def _recommendation_for_risk(risk):
    affected = risk.get("affected_columns") or []
    target = (
        f"{affected[0].get('table')}.{affected[0].get('column')}"
        if affected else "the affected dataset"
    )
    description = str(risk.get("description", "")).lower()

    if "unmasked" in description or "not masked" in description:
        action = f"Mask, tokenize, or restrict access to {target}."
    elif "partially masked" in description:
        action = f"Validate masking strength and re-identification risk for {target}."
    elif "owner" in description:
        action = f"Assign dataset owner and data steward for {target}."
    elif "primary key" in description:
        action = f"Define primary key or uniqueness controls for {target}."
    elif "duplicate" in description:
        action = f"Deduplicate records and enforce uniqueness rules for {target}."
    elif "null" in description:
        action = f"Define completeness rules and remediate null-heavy fields in {target}."
    elif "invalid" in description:
        action = f"Fix invalid formats and add validation rules for {target}."
    else:
        action = f"Review and remediate: {risk.get('description')}."

    return {
        "risk_id": risk.get("id"),
        "action": action,
        "priority": _priority(risk.get("severity")),
        "owner": risk.get("owner") or "Data Engineering / Data Steward",
        "reasoning": f"Risk {risk.get('id')} is {risk.get('severity')} severity with {risk.get('likelihood')} likelihood.",
        "reason": risk.get("description"),
    }


def raid_agent(state):
    logger.info("RAID Agent")
    findings = state.get("gap_analysis") or {}
    previous_raid = state.get("raid") or {}
    risks = state.get("risks") or previous_raid.get("risks", [])
    prioritized_risks = state.get("prioritized_risks") or risks

    issues = findings.get("gaps", []) or previous_raid.get("issues", [])
    assumptions = list(previous_raid.get("assumptions", []))
    dependencies = list(previous_raid.get("dependencies", []))

    if not state.get("relationship_inference") and not assumptions:
        assumptions.append({
            "description": "No explicit relationships were found in source metadata.",
            "validation_needed": "Confirm whether joins are enforced outside the database.",
        })

    ownership = []
    for table in (state.get("source_inventory") or {}).get("tables", []):
        owner = table.get("dataset_owner") or table.get("owner") or "unknown"
        steward = table.get("data_steward") or "Data Engineering / Data Steward"
        if owner in (None, "", "unknown", "postgres"):
            ownership.append({
                "table": table.get("qualified_name"),
                "dataset_owner": owner,
                "data_steward": steward,
                "status": "missing_owner",
            })

    recommendations = [_recommendation_for_risk(risk) for risk in risks]
    recommendations.extend(previous_raid.get("recommendations", []))

    raid = {
        "context": {
            "run_scope": "metadata, profiling, classification, governance, risk, and recommendations",
            "risk_count": len(risks),
            "issue_count": len(issues),
            "document_alignment_count": len(state.get("document_alignment") or []),
            "cross_table_risk_count": len([
                risk for risk in risks
                if len(risk.get("affected_columns") or []) > 1
            ]),
        },
        "issues": issues,
        "risks": risks,
        "prioritized_risks": prioritized_risks,
        "assumptions": assumptions,
        "dependencies": dependencies,
        "ownership": ownership,
        "recommendations": deduplicate_recommendations(recommendations),
    }

    return {"raid": raid, "recommendations": raid["recommendations"]}
