def build_dpdp_compliance_summary(column_intelligence, raid):
    summary = column_intelligence.get("summary", {})
    unmasked_pii = summary.get("unmasked_pii_columns", 0)
    pii_columns = summary.get("pii_columns", 0)
    high_risks = [
        risk for risk in (raid or {}).get("risks", [])
        if risk.get("severity") in {"high", "critical"}
    ]

    if unmasked_pii:
        status = "ACTION_REQUIRED"
    elif pii_columns:
        status = "CONTROLLED"
    else:
        status = "NO_PII_DETECTED"

    return {
        "status": status,
        "pii_columns": pii_columns,
        "unmasked_pii_columns": unmasked_pii,
        "high_risk_count": len(high_risks),
        "required_actions": [
            "Apply masking, tokenization, or access restriction to unmasked PII columns.",
            "Validate purpose limitation and access controls for sensitive columns.",
            "Maintain traceability for detected PII and remediation ownership."
        ] if unmasked_pii else [
            "Continue periodic scans to detect new PII and masking drift."
        ]
    }
