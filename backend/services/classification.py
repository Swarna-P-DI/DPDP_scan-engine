FINANCIAL_HINTS = ("amount", "price", "salary", "revenue", "payment", "account", "balance")
CUSTOMER_HINTS = ("customer", "client", "user", "person")
IDENTIFIER_HINTS = ("id", "uuid", "key", "code")


def classify_column(table_name, column_name, pii_detection, masking_status, profiling=None):
    lowered = f"{table_name}.{column_name}".lower()
    tags = []

    if pii_detection.get("pii_detected"):
        tags.append("PII")

    if any(hint in lowered for hint in FINANCIAL_HINTS):
        tags.append("Financial")

    if any(hint in lowered for hint in CUSTOMER_HINTS):
        tags.append("Customer Data")

    if any(hint in lowered.split(".")[-1] for hint in IDENTIFIER_HINTS):
        tags.append("Identifier")

    inferred_type = (profiling or {}).get("inferred_type")
    if inferred_type:
        tags.append(f"Type:{inferred_type}")

    if pii_detection.get("pii_detected"):
        classification = "Sensitive"
    elif tags:
        classification = "Confidential"
    else:
        classification = "Public"

    sensitivity_level = pii_detection.get("sensitivity", "low")
    if pii_detection.get("pii_detected") and masking_status == "NOT_MASKED":
        risk = "HIGH"
        sensitivity_level = "high"
    elif pii_detection.get("pii_detected") and masking_status in ("PARTIALLY_MASKED", "UNKNOWN"):
        risk = "MEDIUM"
        sensitivity_level = "medium" if sensitivity_level == "low" else sensitivity_level
    elif classification == "Confidential":
        risk = "MEDIUM"
        sensitivity_level = "medium"
    else:
        risk = "LOW"

    return {
        "classification": classification,
        "tags": tags or ["Public"],
        "risk": risk,
        "sensitivity_level": sensitivity_level,
        "confidence_score": pii_detection.get("confidence_score", 0.4 if classification != "Public" else 0.2),
    }
