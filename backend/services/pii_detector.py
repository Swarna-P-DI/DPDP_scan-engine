import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Tuple

PII_PATTERNS = {
    "EMAIL": re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"),
    "PHONE": re.compile(r"^(?:\+?91[-\s]?)?[6-9]\d{9}$"),
    "AADHAAR": re.compile(r"^\d{4}[\s-]?\d{4}[\s-]?\d{4}$"),
    "PAN": re.compile(r"^[A-Z]{5}\d{4}[A-Z]$"),
    "IFSC": re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$"),
    "FINANCIAL": re.compile(r"^(?:\d{9,18}|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})$"),
}

COLUMN_HINTS = {
    "EMAIL": ("email", "e_mail", "mail_id"),
    "PHONE": ("phone", "mobile", "contact", "telephone", "msisdn"),
    "AADHAAR": ("aadhaar", "aadhar", "uidai"),
    "PAN": ("pan", "tax_id"),
    "IFSC": ("ifsc", "bank_code", "branch_code"),
    "FINANCIAL": ("account", "bank", "card", "iban", "ifsc", "salary", "payment", "balance"),
    "NAME": ("name", "first_name", "last_name", "customer_name", "full_name"),
}

SENSITIVITY = {
    "AADHAAR": "high",
    "PAN": "high",
    "IFSC": "high",
    "FINANCIAL": "high",
    "EMAIL": "high",
    "PHONE": "high",
    "NAME": "medium",
}

DECISION_THRESHOLD = 0.75
REGEX_CONFIDENCE = 0.9
SEMANTIC_CONFIDENCE = 0.7

NON_ENGLISH_RANGES = (
    ("\u0900", "\u097f", "hi"),
    ("\u0980", "\u09ff", "bn"),
    ("\u0b80", "\u0bff", "ta"),
    ("\u0c00", "\u0c7f", "te"),
    ("\u0c80", "\u0cff", "kn"),
    ("\u0d00", "\u0d7f", "ml"),
)


def detect_language(values: Iterable[Any]) -> str:
    text = " ".join(str(value or "") for value in values)[:2000]
    for start, end, language in NON_ENGLISH_RANGES:
        if any(start <= char <= end for char in text):
            return language
    return "en"


def _normalize(value: Any) -> str:
    return str(value or "").strip()


def _name_like_hits(values: List[Any]) -> int:
    hits = 0
    for value in values:
        text = _normalize(value)
        if re.fullmatch(r"[A-Za-z][A-Za-z .'-]{1,80}", text) and len(text.split()) <= 4:
            hits += 1
    return hits


def _cache_key(column_name: str, values: Iterable[Any], profiling: Dict[str, Any] | None = None) -> Tuple[str, Tuple[str, ...], Tuple[str, ...]]:
    patterns = tuple(sorted(str(item.get("pattern")) for item in (profiling or {}).get("patterns", [])))
    sample = tuple(_normalize(value).lower() for value in list(values)[:50])
    return str(column_name or "").lower(), sample, patterns


@lru_cache(maxsize=2048)
def _detect_pii_cached(column_name: str, values: Tuple[str, ...], profile_patterns: Tuple[str, ...]) -> Dict[str, Any]:
    normalized_column = str(column_name or "").lower()
    usable_values = [value for value in values if _normalize(value)]
    sample_count = len(usable_values)
    detected = []
    language = detect_language(usable_values)

    for pii_type, pattern in PII_PATTERNS.items():
        hints = any(hint in normalized_column for hint in COLUMN_HINTS[pii_type])
        hits = sum(1 for value in usable_values if pattern.match(_normalize(value)))
        ratio = hits / sample_count if sample_count else 0
        if hits:
            confidence_score = REGEX_CONFIDENCE if ratio >= 0.3 else round(ratio, 2)
            detected.append({
                "pii_type": pii_type,
                "sensitivity": SENSITIVITY[pii_type],
                "confidence_score": round(confidence_score, 2),
                "detected_by": "regex",
                "detection_source": "regex",
                "evidence": f"{hits}/{sample_count} sampled values matched {pii_type}; column hint={hints}",
            })
        elif hints:
            detected.append({
                "pii_type": pii_type,
                "sensitivity": SENSITIVITY[pii_type],
                "confidence_score": SEMANTIC_CONFIDENCE,
                "detected_by": "semantic",
                "detection_source": "semantic",
                "evidence": f"Column name matched {pii_type} semantic hint.",
            })

    name_hint = any(hint in normalized_column for hint in COLUMN_HINTS["NAME"])
    name_hits = _name_like_hits(usable_values)
    name_ratio = name_hits / sample_count if sample_count else 0
    if name_hint and (name_ratio >= 0.3 or sample_count == 0):
        detected.append({
            "pii_type": "NAME",
            "sensitivity": SENSITIVITY["NAME"],
            "confidence_score": max(round(name_ratio, 2), SEMANTIC_CONFIDENCE),
            "detected_by": "semantic",
            "detection_source": "semantic",
            "evidence": f"{name_hits}/{sample_count} sampled values looked name-like; column hint={name_hint}",
        })

    for pattern_name in profile_patterns:
        mapped = {
            "email": "EMAIL",
            "phone": "PHONE",
            "aadhaar": "AADHAAR",
            "pan": "PAN",
            "ifsc": "IFSC",
        }.get(pattern_name)
        if mapped and not any(item["pii_type"] == mapped for item in detected):
            detected.append({
                "pii_type": mapped,
                "sensitivity": SENSITIVITY[mapped],
                "confidence_score": REGEX_CONFIDENCE,
                "detected_by": "profiling_pattern",
                "detection_source": "regex",
                "evidence": f"Profiling pattern {pattern_name} matched sampled values.",
            })

    if not detected:
        return {
            "pii_detected": False,
            "pii_type": None,
            "sensitivity": "low",
            "confidence": "none",
            "confidence_score": 0.0,
            "detection_sources": [],
            "final_decision": False,
            "detected_by": None,
            "language": language,
            "evidence": "No PII pattern, semantic hint, or profile pattern matched",
        }

    priority = {"AADHAAR": 7, "PAN": 6, "IFSC": 5, "FINANCIAL": 4, "EMAIL": 3, "PHONE": 2, "NAME": 1}
    best = sorted(detected, key=lambda item: (priority[item["pii_type"]], item["confidence_score"]), reverse=True)[0]
    confidence = "high" if best["confidence_score"] >= 0.8 else "medium" if best["confidence_score"] >= 0.5 else "low"
    final_decision = best["confidence_score"] >= DECISION_THRESHOLD
    return {
        "pii_detected": final_decision,
        "confidence": confidence,
        "detection_sources": sorted({item["detection_source"] for item in detected}),
        "final_decision": final_decision,
        "language": language,
        **best,
    }


def detect_pii(column_name: str, sample_values: Iterable[Any], profiling: Dict[str, Any] | None = None) -> Dict[str, Any]:
    column_key, values_key, patterns_key = _cache_key(column_name, sample_values, profiling)
    return dict(_detect_pii_cached(column_key, values_key, patterns_key))


def detect_column_pii(column_name: str, values: Iterable[Any], profiling: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return detect_pii(column_name, values, profiling)
