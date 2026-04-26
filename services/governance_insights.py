def build_ai_insights(column_intelligence, raid, gap_analysis, relationship_inference, profiling):
    insights = []
    seen = set()

    def add_insight(insight_type, insight, severity):
        key = (insight_type, insight)
        if key in seen:
            return
        seen.add(key)
        insights.append({
            "type": insight_type,
            "insight": insight,
            "severity": severity
        })

    unmasked_columns = []
    partially_masked = []
    for table, columns in (column_intelligence or {}).get("tables", {}).items():
        for column in columns:
            if column.get("pii_detected") and column.get("masking_status") == "NOT_MASKED":
                unmasked_columns.append(f"{table}.{column.get('column')}")
            elif column.get("pii_detected") and column.get("masking_status") == "PARTIALLY_MASKED":
                partially_masked.append(f"{table}.{column.get('column')}")

    if len(unmasked_columns) >= 2:
        add_insight(
            "risk_pattern",
            "Customer PII exists in multiple columns without masking, increasing exposure risk.",
            "high"
        )
    elif len(unmasked_columns) == 1:
        add_insight(
            "risk_pattern",
            f"Unmasked sensitive data remains exposed in {unmasked_columns[0]}.",
            "high"
        )

    if partially_masked:
        add_insight(
            "control_gap",
            f"Partial masking is present in {len(partially_masked)} sensitive column(s), which may still allow re-identification.",
            "medium"
        )

    insufficient_samples = [
        table for table, stats in (profiling or {}).items()
        if stats.get("sample_sufficiency", {}).get("status") == "INSUFFICIENT"
    ]
    if insufficient_samples:
        add_insight(
            "data_quality",
            "Low sample size reduces confidence in profiling and scoring.",
            "medium"
        )

    high_risks = [risk for risk in (raid or {}).get("risks", []) if risk.get("severity") == "high"]
    if len(high_risks) >= 3:
        add_insight(
            "risk_pattern",
            f"{len(high_risks)} high-severity RAID risks were identified, indicating elevated governance exposure.",
            "high"
        )

    ownership_gaps = [
        gap for gap in (gap_analysis or {}).get("gaps", [])
        if gap.get("type") == "ownership"
    ]
    if ownership_gaps:
        add_insight(
            "governance_gap",
            "Unresolved ownership gaps weaken accountability for remediation and access decisions.",
            "medium"
        )

    if relationship_inference:
        add_insight(
            "lineage_signal",
            f"Inferred relationships across {len(relationship_inference)} column pair(s) suggest shared identifiers that should be validated for lineage and access control.",
            "medium"
        )

    return insights
