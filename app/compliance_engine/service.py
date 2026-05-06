from __future__ import annotations

from collections import defaultdict
from typing import Any


def evaluate_dpdp_compliance(
    pii_index: list[dict[str, Any]],
    *,
    source_controls: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    source_controls = source_controls or {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in pii_index:
        grouped[str(entry.get("source_id") or "unknown")].append(entry)

    reports = []
    for source_id, entries in sorted(grouped.items()):
        controls = source_controls.get(source_id, {})
        access_controlled = controls.get("access_controlled", True)
        publicly_exposed = controls.get("publicly_exposed", False)
        issues = []
        recommendations = []

        for entry in entries:
            pii_type = str(entry.get("pii_type") or "").upper()
            masking_status = str((entry.get("metadata") or {}).get("masking_status") or "").upper()
            masking_unknown = masking_status in {"UNKNOWN", ""}
            if masking_unknown:
                issues.append(f"{pii_type} masking status is missing or unknown at {entry.get('location')}.")
                recommendations.append(f"Add explicit masking metadata for {pii_type} at {entry.get('location')}.")
            elif not entry.get("masked"):
                issues.append(f"{pii_type} is not masked at {entry.get('location')}.")
                recommendations.append(f"Mask or tokenize {pii_type} at {entry.get('location')}.")
            if not entry.get("encrypted"):
                issues.append(f"{pii_type} is not confirmed encrypted at {entry.get('location')}.")
                recommendations.append(f"Enable encryption for {source_id}.")

        if access_controlled is not True:
            issues.append("Access controls are missing or unknown.")
            recommendations.append("Validate IAM/RBAC policies and least-privilege access.")
        if publicly_exposed:
            issues.append("Source is marked publicly exposed.")
            recommendations.append("Remove public exposure or isolate the source behind approved access controls.")

        has_unmasked_aadhaar = any(
            entry.get("pii_type") == "aadhaar"
            and not entry.get("masked")
            and str((entry.get("metadata") or {}).get("masking_status") or "").upper() not in {"UNKNOWN", ""}
            for entry in entries
        )
        if publicly_exposed or has_unmasked_aadhaar:
            status = "VIOLATION"
        elif issues:
            status = "RISK"
        else:
            status = "COMPLIANT"

        reports.append({
            "source_id": source_id,
            "compliance_status": status,
            "issues": _dedupe(issues),
            "recommendations": _dedupe(recommendations),
            "controls": {
                "access_controlled": bool(access_controlled),
                "publicly_exposed": bool(publicly_exposed),
            },
        })
    return reports


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))
