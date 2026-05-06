from __future__ import annotations

from collections import defaultdict
from typing import Any


def data_intelligence_response(pii_index: list[dict[str, Any]]) -> dict[str, list[str]]:
    what = sorted({str(entry.get("pii_type", "")).upper() for entry in pii_index if entry.get("pii_type")})
    where = sorted({str(entry.get("source_id")) for entry in pii_index if entry.get("source_id")})
    how_values = set()
    for entry in pii_index:
        if entry.get("encrypted"):
            how_values.add("Encrypted")
        elif entry.get("masked"):
            how_values.add("Masked")
        else:
            how_values.add("Unmasked")
        if not entry.get("encrypted"):
            how_values.add("Plain text")
    return {"what": what, "where": where, "how": sorted(how_values)}


def pii_summary(pii_index: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)
    exposure = {"masked": 0, "encrypted": 0, "unprotected": 0}
    for entry in pii_index:
        by_type[str(entry.get("pii_type"))] += 1
        by_source[str(entry.get("source_id"))] += 1
        if entry.get("encrypted"):
            exposure["encrypted"] += 1
        elif entry.get("masked"):
            exposure["masked"] += 1
        else:
            exposure["unprotected"] += 1
    return {
        "by_type": dict(sorted(by_type.items())),
        "by_source": dict(sorted(by_source.items())),
        "exposure": exposure,
        "total": len(pii_index),
    }


def consolidated_report(
    *,
    metadata: dict[str, Any],
    profiling: dict[str, Any],
    pii_index: list[dict[str, Any]],
    raid: dict[str, Any],
    compliance: list[dict[str, Any]],
    ownership_details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "metadata": metadata,
        "profiling": profiling,
        "pii_summary": pii_summary(pii_index),
        "pii_index": pii_index,
        "raid_output": raid,
        "compliance_status": compliance,
        "recommendations": raid.get("recommendations", []),
        "ownership_details": ownership_details or [],
        "data_intelligence": data_intelligence_response(pii_index),
    }

