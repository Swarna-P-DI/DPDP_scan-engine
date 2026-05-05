from __future__ import annotations

from collections import Counter
from typing import Any


def generate_raid(
    *,
    findings: list[dict[str, Any]],
    pii_index: list[dict[str, Any]],
    compliance: list[dict[str, Any]],
    profiling: dict[str, Any],
) -> dict[str, Any]:
    risks = []
    issues = []
    assumptions = [{
        "description": "Access-control and encryption flags default to scan metadata when source connector details are unavailable.",
        "validation_needed": "Confirm source IAM/RBAC and encryption posture from the authoritative connector.",
    }]
    dependencies = [{
        "description": "Remediation depends on masking/tokenization services and source-specific IAM policy updates.",
        "owner": "Data Engineering / Security",
    }]
    recommendations = []

    for entry in pii_index:
        pii_type = str(entry.get("pii_type") or "").upper()
        if pii_type == "AADHAAR" and not entry.get("masked"):
            risks.append({
                "risk": f"Aadhaar stored unmasked in {entry.get('source_id')}",
                "severity": "HIGH",
                "source_id": entry.get("source_id"),
                "location": entry.get("location"),
            })
        if not entry.get("encrypted"):
            issues.append({
                "issue": f"No encryption confirmed for {pii_type} in {entry.get('source_id')}",
                "severity": "MEDIUM",
                "location": entry.get("location"),
            })

    for report in compliance:
        if report.get("compliance_status") == "VIOLATION":
            risks.append({
                "risk": f"DPDP violation indicators found for {report.get('source_id')}",
                "severity": "HIGH",
                "issues": report.get("issues", []),
            })
        elif report.get("compliance_status") == "RISK":
            risks.append({
                "risk": f"DPDP control gaps found for {report.get('source_id')}",
                "severity": "MEDIUM",
                "issues": report.get("issues", []),
            })
        recommendations.extend({
            "recommendation": item,
            "priority": "HIGH" if report.get("compliance_status") == "VIOLATION" else "MEDIUM",
        } for item in report.get("recommendations", []))

    if profiling.get("row_count", 0) == 0 and profiling.get("document_pages", 0) == 0:
        assumptions.append({
            "description": "No row/page volume was available from profiling.",
            "validation_needed": "Run against representative source data before final compliance decisions.",
        })

    dependencies.append({
        "description": "Depends on source inventory connectors for encryption, public exposure, and access-control facts.",
        "owner": "Platform Connectors",
    })

    return {
        "risks": _dedupe_dicts(risks),
        "issues": _dedupe_dicts(issues),
        "assumptions": assumptions,
        "dependencies": dependencies,
        "recommendations": _dedupe_dicts(recommendations),
        "summary": {
            "pii_types": dict(Counter(entry.get("pii_type") for entry in pii_index)),
            "compliance": dict(Counter(item.get("compliance_status") for item in compliance)),
            "findings": len(findings),
        },
    }


def _dedupe_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in items:
        key = tuple(sorted((str(k), str(v)) for k, v in item.items()))
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output

