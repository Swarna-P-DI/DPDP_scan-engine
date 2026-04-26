from services.classification import classify_column
from services.masking_check import column_masking_status
from services.pii_detector import detect_column_pii


def recommend_masking(pii_type, masking_status, data_type):
    if masking_status in ("MASKED", "PARTIALLY_MASKED"):
        return "NONE"

    pii_type = (pii_type or "").upper()
    lowered_type = str(data_type or "").lower()

    if pii_type == "EMAIL":
        return "partial_email_mask"
    if pii_type == "NAME":
        return "tokenization"
    if pii_type in {"PHONE", "AADHAAR", "PAN"}:
        return "hash" if any(
            token in lowered_type
            for token in ("int", "numeric", "decimal", "float", "double", "real")
        ) else "tokenization"
    if any(token in lowered_type for token in ("int", "numeric", "decimal", "float", "double", "real")):
        return "hash"
    return "redact"


def build_column_intelligence(source_inventory, profiling):
    intelligence = {}
    summary = {
        "columns_scanned": 0,
        "pii_columns": 0,
        "unmasked_pii_columns": 0,
        "high_risk_columns": 0,
        "sensitive_columns": 0
    }

    for table in source_inventory.get("tables", []):
        table_name = table.get("qualified_name")
        table_profile = profiling.get(table_name, {})
        sample_values = table_profile.get("sample_values", {})
        column_profiles = table_profile.get("column_profiles", {})
        intelligence[table_name] = []

        for column in table.get("columns", []):
            column_name = column.get("name")
            values = sample_values.get(column_name, [])
            column_profile = column_profiles.get(column_name, {})
            pii = detect_column_pii(column_name, values, column_profile)
            masking_status = column_masking_status(values) if pii.get("pii_detected") else "NOT_APPLICABLE"
            classified = classify_column(table_name, column_name, pii, masking_status, column_profile)
            recommended_masking = recommend_masking(
                pii.get("pii_type"),
                masking_status,
                column.get("type")
            ) if pii.get("pii_detected") else "NONE"

            record = {
                "column": column_name,
                "data_type": column.get("type"),
                "nullable": column.get("nullable"),
                "pii_detected": pii["pii_detected"],
                "pii_type": pii.get("pii_type"),
                "pii_confidence": pii.get("confidence"),
                "confidence_score": pii.get("confidence_score", classified.get("confidence_score")),
                "sensitivity_level": classified.get("sensitivity_level", pii.get("sensitivity", "low")),
                "detection_sources": pii.get("detection_sources", []),
                "final_decision": pii.get("final_decision", pii.get("pii_detected")),
                "language": pii.get("language", "en"),
                "detected_by": pii.get("detected_by"),
                "masking_status": masking_status,
                "recommended_masking": recommended_masking,
                "classification": classified["classification"],
                "tags": classified["tags"],
                "risk": classified["risk"],
                "evidence": pii.get("evidence")
            }
            intelligence[table_name].append(record)

            summary["columns_scanned"] += 1
            if record["pii_detected"]:
                summary["pii_columns"] += 1
            if record["pii_detected"] and record["masking_status"] == "NOT_MASKED":
                summary["unmasked_pii_columns"] += 1
            if record["risk"] == "HIGH":
                summary["high_risk_columns"] += 1
            if record["classification"] == "Sensitive":
                summary["sensitive_columns"] += 1

    return {
        "summary": summary,
        "tables": intelligence
    }


def build_traceability(column_intelligence, run_id):
    records = []

    for table, columns in column_intelligence.get("tables", {}).items():
        for column in columns:
            if column.get("pii_detected") or column.get("classification") != "Public":
                records.append({
                    "table": table,
                    "column": column.get("column"),
                    "detected_by": column.get("detected_by") or "classification_engine",
                    "pii_type": column.get("pii_type"),
                    "classification": column.get("classification"),
                    "risk": column.get("risk"),
                    "scan_run_id": run_id
                })

    return records
