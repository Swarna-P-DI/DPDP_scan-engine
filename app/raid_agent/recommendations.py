from __future__ import annotations

from typing import Any


def recommendations_for_field(field: dict[str, Any], risk: dict[str, Any]) -> list[str]:
    recommendations: list[str] = []
    pii_type = str(field.get("pii_type") or "").upper()
    exposure = str(risk.get("exposure_type") or field.get("exposure_type") or "INTERNAL").upper()
    risk_category = str(risk.get("risk_category") or "").upper()

    if pii_type == "AADHAAR" and not field.get("is_masked"):
        recommendations.append("Apply tokenization or encryption")
    if exposure == "PUBLIC":
        recommendations.append("Restrict API access")
    if not field.get("is_encrypted"):
        recommendations.append("Enable field-level encryption")
    if risk_category in {"HIGH", "CRITICAL"}:
        recommendations.append("Apply data minimization")
    if risk.get("retention_violation") or field.get("retention_violation"):
        recommendations.append("Retention policy violation")
    if field.get("is_masked") and not field.get("is_tokenized"):
        recommendations.append("Evaluate tokenization for production workflows")
    if not recommendations:
        recommendations.append("Maintain least-privilege access and periodic RAID monitoring")
    return list(dict.fromkeys(recommendations))
