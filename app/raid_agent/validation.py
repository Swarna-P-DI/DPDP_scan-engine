from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

PAN_ENTITY_TYPES = frozenset("PCHFATBLJG")
PAN_PATTERN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
IFSC_PATTERN = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")

_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


@dataclass(frozen=True, slots=True)
class ValidationResult:
    is_valid: bool
    reason: str = "valid"
    normalized_value: str | None = None
    confidence_adjustment: float = 0.0
    evidence: list[str] = field(default_factory=list)


def is_valid_aadhaar(number: str) -> bool:
    digits = re.sub(r"\D", "", str(number or ""))
    if len(digits) != 12 or not digits.isdigit():
        return False
    checksum = 0
    for index, item in enumerate(reversed(digits)):
        checksum = _D[checksum][_P[index % 8][int(item)]]
    return checksum == 0


def validate_aadhaar(value: str) -> ValidationResult:
    digits = re.sub(r"\D", "", str(value or ""))
    if not is_valid_aadhaar(digits):
        logger.info("Rejected Aadhaar candidate after Verhoeff validation")
        return ValidationResult(False, "aadhaar_checksum_failed", digits, -1.0)
    return ValidationResult(True, normalized_value=digits, evidence=["verhoeff_checksum"])


def validate_pan(value: str, *, column_context: str | None = None, name_initial: str | None = None) -> ValidationResult:
    pan = re.sub(r"[^A-Za-z0-9]", "", str(value or "")).upper()
    if not PAN_PATTERN.fullmatch(pan):
        logger.info("Rejected PAN candidate after regex normalization")
        return ValidationResult(False, "pan_format_failed", pan, -1.0)
    if pan[3] not in PAN_ENTITY_TYPES:
        logger.info("Rejected PAN candidate with invalid entity type")
        return ValidationResult(False, "pan_entity_type_failed", pan, -1.0)
    evidence = ["pan_entity_type"]
    adjustment = 0.0
    if name_initial:
        expected = str(name_initial).strip().upper()[:1]
        if expected and pan[4] != expected:
            adjustment = -0.08
            evidence.append("pan_name_initial_mismatch")
    return ValidationResult(True, normalized_value=pan, confidence_adjustment=adjustment, evidence=evidence)


def validate_ifsc(value: str, *, bank_lookup: Callable[[str], bool] | None = None) -> ValidationResult:
    ifsc = re.sub(r"[^A-Za-z0-9]", "", str(value or "")).upper()
    if not IFSC_PATTERN.fullmatch(ifsc):
        logger.info("Rejected IFSC candidate after strict structure validation")
        return ValidationResult(False, "ifsc_format_failed", ifsc, -1.0)
    if bank_lookup and not bank_lookup(ifsc[:4]):
        logger.info("Rejected IFSC candidate after bank-code lookup")
        return ValidationResult(False, "ifsc_bank_lookup_failed", ifsc, -1.0)
    return ValidationResult(True, normalized_value=ifsc, evidence=["ifsc_structure"])


def validate_identifier(pii_type: str, value: str, *, column_context: str | None = None) -> ValidationResult:
    key = str(pii_type or "").upper()
    if key == "AADHAAR":
        return validate_aadhaar(value)
    if key == "PAN":
        return validate_pan(value, column_context=column_context)
    if key == "IFSC":
        return validate_ifsc(value)
    return ValidationResult(False, "unsupported_pii_type", str(value or ""), -1.0)
