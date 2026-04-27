def _metadata_penalty(source_inventory):
    penalty = 0
    drivers = []

    for table in source_inventory.get("tables", []):
        table_name = table.get("qualified_name")
        if table.get("owner") in (None, "", "unknown"):
            penalty += 5
            drivers.append({
                "factor": "metadata_completeness",
                "severity": "medium",
                "penalty": 5,
                "detail": f"{table_name} has unknown ownership"
            })
        if not table.get("primary_key"):
            penalty += 5
            drivers.append({
                "factor": "metadata_completeness",
                "severity": "medium",
                "penalty": 5,
                "detail": f"{table_name} has no primary key"
            })

    return penalty, drivers


def _pii_penalty(column_intelligence):
    penalty = 0
    drivers = []

    for table, columns in column_intelligence.get("tables", {}).items():
        for column in columns:
            if not column.get("pii_detected"):
                continue

            if column.get("masking_status") == "NOT_MASKED":
                applied = 15
                severity = "high"
            elif column.get("masking_status") == "PARTIALLY_MASKED":
                applied = 8
                severity = "medium"
            elif column.get("masking_status") == "UNKNOWN":
                applied = 5
                severity = "medium"
            else:
                applied = 0
                severity = "low"

            if applied:
                penalty += applied
                drivers.append({
                    "factor": "pii_masking",
                    "severity": severity,
                    "penalty": applied,
                    "detail": (
                        f"{table}.{column.get('column')} is {column.get('pii_type')} "
                        f"with masking_status={column.get('masking_status')}"
                    )
                })

    return penalty, drivers


def _sufficiency_penalty(profiling):
    penalty = 0
    drivers = []

    for table, stats in profiling.items():
        sample_sufficiency = stats.get("sample_sufficiency", {})
        if sample_sufficiency.get("status") == "INSUFFICIENT":
            applied = 8
            penalty += applied
            drivers.append({
                "factor": "sample_sufficiency",
                "severity": "medium",
                "penalty": applied,
                "detail": sample_sufficiency.get("message", f"{table} has insufficient sample size")
            })

    return penalty, drivers


def compute_data_readiness_score(quality_score, findings, source_inventory, column_intelligence, profiling):
    metadata_penalty, metadata_drivers = _metadata_penalty(source_inventory)
    pii_penalty, pii_drivers = _pii_penalty(column_intelligence)
    sufficiency_penalty, sufficiency_drivers = _sufficiency_penalty(profiling)

    finding_penalty = 0
    finding_drivers = []
    for gap in (findings or {}).get("gaps", []):
        if gap.get("type") in {"profiling", "metadata", "ownership", "integrity"}:
            continue
        description = str(gap.get("description", "")).lower()
        if "unmasked" in description or "insufficient data" in description:
            continue
        if gap.get("severity") == "high":
            applied = 5
        elif gap.get("severity") == "medium":
            applied = 2
        else:
            applied = 0
        if applied:
            finding_penalty += applied
            finding_drivers.append({
                "factor": "data_findings",
                "severity": gap.get("severity"),
                "penalty": applied,
                "detail": gap.get("description")
            })

    drivers = metadata_drivers + pii_drivers + sufficiency_drivers + finding_drivers
    risk_penalty = min(
        metadata_penalty + pii_penalty + sufficiency_penalty + finding_penalty,
        80
    )
    final_score = max(float(quality_score or 0) - risk_penalty, 0)

    return {
        "quality_score": quality_score,
        "risk_penalty": risk_penalty,
        "final_score": round(final_score, 2),
        "score_drivers": drivers,
        "score_components": {
            "data_quality": quality_score,
            "metadata_penalty": metadata_penalty,
            "pii_masking_penalty": pii_penalty,
            "sample_sufficiency_penalty": sufficiency_penalty,
            "findings_penalty": finding_penalty
        }
    }
