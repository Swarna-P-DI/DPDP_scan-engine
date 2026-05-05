from __future__ import annotations

import re


OCR_TRANSLATION = str.maketrans({
    "O": "0",
    "o": "0",
    "I": "1",
    "l": "1",
    "|": "1",
})


def normalize_ocr_digits(value: str) -> str:
    return str(value or "").translate(OCR_TRANSLATION)


def digits_only(value: str) -> str:
    return re.sub(r"\D+", "", normalize_ocr_digits(value))


def compact_alnum(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "", str(value or "")).upper()


def context_boost(entity: str, context: str | None, base: float) -> float:
    text = str(context or "").lower()
    hints = {
        "aadhaar": ("aadhaar", "aadhar", "uidai", "identity"),
        "pan": ("pan", "tax", "income tax"),
        "email": ("email", "mail"),
        "phone": ("phone", "mobile", "contact"),
    }
    if any(token in text for token in hints.get(entity, ())):
        return min(1.0, base + 0.08)
    return base
