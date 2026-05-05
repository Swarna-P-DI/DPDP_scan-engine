from __future__ import annotations

from typing import Any


def build_raid(findings: list[dict[str, Any]], column_risks: list[dict[str, Any]], profiling: dict[str, Any]) -> dict[str, Any]:
    risks = []
    issues = []
    assumptions = [{
        "description": "Uploaded files are representative of the dataset being assessed.",
        "validation_needed": "Confirm sample coverage before production remediation decisions.",
    }]
    dependencies = [{
        "description": "Masking, tokenization, or vault integration must be available for remediation.",
        "owner": "Data Engineering / Security",
    }]
    recommendations = []

    high_columns = [item for item in column_risks if item.get("risk") == "HIGH"]
    if high_columns:
        risks.append({
            "risk": "Aadhaar or PAN stored in plain text",
            "severity": "HIGH",
            "affected": high_columns,
        })
        issues.append({
            "issue": "No masking applied to high sensitivity identifiers in scanned content",
            "severity": "HIGH",
        })
        recommendations.append({
            "recommendation": "Apply tokenization or irreversible masking to Aadhaar and PAN values.",
            "priority": "HIGH",
        })

    if any(item.get("type") in {"email", "phone"} for item in findings):
        risks.append({
            "risk": "Contact data exposure may enable unsolicited outreach or account takeover workflows",
            "severity": "MEDIUM",
        })
        recommendations.append({
            "recommendation": "Restrict contact fields to least-privilege roles and mask in non-production.",
            "priority": "MEDIUM",
        })

    null_heavy = [
        {"column": column, "null_pct": stats.get("null_pct")}
        for column, stats in (profiling.get("columns") or {}).items()
        if float(stats.get("null_pct") or 0) >= 50
    ]
    if null_heavy:
        issues.append({
            "issue": "Null-heavy columns reduce discovery confidence",
            "severity": "MEDIUM",
            "columns": null_heavy,
        })

    if not findings:
        recommendations.append({
            "recommendation": "No PII was detected; keep periodic scans enabled for drift monitoring.",
            "priority": "LOW",
        })

    return {
        "risks": risks,
        "issues": issues,
        "assumptions": assumptions,
        "dependencies": dependencies,
        "recommendations": recommendations,
    }
