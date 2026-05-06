from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PiiClassification:
    pii_type: str
    pii_category: str
    sensitivity_level: str
    sensitivity_score: float


CLASSIFICATIONS: dict[str, PiiClassification] = {
    "AADHAAR": PiiClassification("Aadhaar", "Unique Identifier", "HIGH", 0.9),
    "PAN": PiiClassification("PAN", "Financial Identifier", "HIGH", 0.85),
    "IFSC": PiiClassification("IFSC", "Financial Routing", "MEDIUM", 0.7),
}


def classify_pii(pii_type: str) -> PiiClassification:
    key = str(pii_type or "").strip().upper()
    if key not in CLASSIFICATIONS:
        raise ValueError(f"Unsupported PII type: {pii_type}")
    return CLASSIFICATIONS[key]
