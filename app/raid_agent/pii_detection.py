from __future__ import annotations

import logging
import re
import hashlib
import os
from dataclasses import dataclass, field
from typing import Iterable

from app.raid_agent.validation import is_valid_aadhaar, validate_identifier

logger = logging.getLogger(__name__)

AADHAAR_PATTERN = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.IGNORECASE)
IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE)
MASK_PATTERN = re.compile(r"(?:X{3,}|\*{3,}|#{3,})", re.IGNORECASE)
MASK_CHAR_PATTERN = re.compile(r"[Xx*#]")
NEGATIVE_CONTEXT = ("transaction_id", "txn_id", "reference_no", "ref_no", "request_id", "trace_id")

CONTEXT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "AADHAAR": ("aadhaar", "adhar", "uidai", "uid_no", "unique_id", "aadhaar_no", "aadhaar_number"),
    "PAN": ("pan", "pan_id", "pan_no", "pan_number", "tax_id", "income_tax"),
    "IFSC": ("ifsc", "ifsc_code", "bank_code", "branch_code", "routing_code"),
}


@dataclass(slots=True)
class PiiDetectionResult:
    pii_type: str
    confidence_score: float
    detection_method: str
    is_masked: bool = False
    hashed_value: str | None = None
    last4_value: str | None = None
    detected_value: str | None = None
    value_hash: str | None = None
    value_preview: str | None = None
    mask_ratio: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "pii_type": self.pii_type,
            "confidence_score": round(self.confidence_score, 4),
            "detection_method": self.detection_method,
            "is_masked": self.is_masked,
            "hashed_value": self.hashed_value,
            "last4_value": self.last4_value,
            "value_hash": self.value_hash,
            "value_preview": self.value_preview,
            "mask_ratio": round(self.mask_ratio, 4),
            "evidence": list(self.evidence),
        }


class PiiDetectionEngine:
    """Regex and metadata-context detector for Indian identifiers."""

    def detect_field(
        self,
        column_name: str,
        sample_values: Iterable[object] | None = None,
        *,
        table_name: str | None = None,
    ) -> list[PiiDetectionResult]:
        try:
            context_hits = self._detect_from_column_name(column_name, table_name=table_name)
            value_hits = self._detect_from_values(sample_values or [])
            return self._apply_context_adjustments(self._merge_hits(context_hits + value_hits), column_name, table_name)
        except Exception:
            logger.exception("PII detection failed for column %s", column_name)
            return []

    def _detect_from_column_name(self, column_name: str, *, table_name: str | None = None) -> list[PiiDetectionResult]:
        normalized = _normalize_name(column_name)
        table_context = _normalize_name(table_name)
        detections: list[PiiDetectionResult] = []
        for pii_type, keywords in CONTEXT_KEYWORDS.items():
            if any(keyword in normalized for keyword in keywords):
                confidence = 0.88 if any(keyword == normalized for keyword in keywords) else 0.78
                if any(token in table_context for token in ("customer", "kyc", "bank")):
                    confidence += 0.05
                detections.append(PiiDetectionResult(
                    pii_type=pii_type,
                    confidence_score=min(1.0, confidence),
                    detection_method="column_context",
                    evidence=[f"column_name:{column_name}"],
                ))
        return detections

    def _detect_from_values(self, sample_values: Iterable[object]) -> list[PiiDetectionResult]:
        detections: list[PiiDetectionResult] = []
        for raw_value in sample_values:
            text = str(raw_value or "").strip()
            if not text:
                continue
            ratio = mask_ratio(text)
            masked = is_masked_value(text)
            for pii_type, pattern in (("AADHAAR", AADHAAR_PATTERN), ("PAN", PAN_PATTERN), ("IFSC", IFSC_PATTERN)):
                match = pattern.search(text)
                if not match and not masked:
                    continue
                detected = match.group(0).upper() if match else None
                evidence = ["mask_pattern"]
                confidence = 0.72
                if match:
                    validation = validate_identifier(pii_type, detected)
                    if not validation.is_valid:
                        logger.info("Rejected %s candidate in sample value: %s", pii_type, validation.reason)
                        continue
                    detected = validation.normalized_value or detected
                    evidence = ["value_regex", *validation.evidence]
                    confidence = max(0.0, min(1.0, 0.98 + validation.confidence_adjustment))
                hashed = hash_value(detected or text)
                detections.append(PiiDetectionResult(
                    pii_type=pii_type,
                    confidence_score=confidence,
                    detection_method="regex" if match else "mask_heuristic",
                    is_masked=masked,
                    hashed_value=hashed,
                    last4_value=last4_value(detected or text),
                    detected_value=hashed,
                    value_hash=hashed,
                    value_preview=masked_preview(detected or text),
                    mask_ratio=ratio,
                    evidence=evidence,
                ))
                if match:
                    break
        return detections

    def _merge_hits(self, detections: list[PiiDetectionResult]) -> list[PiiDetectionResult]:
        merged: dict[str, PiiDetectionResult] = {}
        for detection in detections:
            existing = merged.get(detection.pii_type)
            if existing is None or detection.confidence_score > existing.confidence_score:
                merged[detection.pii_type] = detection
            elif existing:
                existing.evidence.extend(item for item in detection.evidence if item not in existing.evidence)
                existing.is_masked = existing.is_masked or detection.is_masked
                existing.mask_ratio = max(existing.mask_ratio, detection.mask_ratio)
                existing.hashed_value = existing.hashed_value or detection.hashed_value
                existing.last4_value = existing.last4_value or detection.last4_value
                existing.value_hash = existing.value_hash or detection.value_hash
                existing.value_preview = existing.value_preview or detection.value_preview
        return sorted(merged.values(), key=lambda item: item.confidence_score, reverse=True)

    def _apply_context_adjustments(
        self,
        detections: list[PiiDetectionResult],
        column_name: str,
        table_name: str | None,
    ) -> list[PiiDetectionResult]:
        column_context = _normalize_name(column_name)
        table_context = _normalize_name(table_name)
        positive_table = any(token in table_context for token in ("customer", "kyc", "bank"))
        negative_column = any(token in column_context for token in NEGATIVE_CONTEXT)
        for detection in detections:
            if positive_table:
                detection.confidence_score = min(1.0, detection.confidence_score + 0.04)
                detection.evidence.append(f"table_context:{table_name}")
            if negative_column:
                detection.confidence_score = max(0.0, detection.confidence_score - 0.18)
                detection.evidence.append(f"negative_column_context:{column_name}")
        return sorted(detections, key=lambda item: item.confidence_score, reverse=True)


def hash_value(value: str, *, salt: str | None = None) -> str:
    configured_salt = salt if salt is not None else os.getenv("RAID_HASH_SALT", "raid-agent-static-salt-v1")
    normalized = str(value or "").strip().upper()
    return hashlib.sha256(f"{configured_salt}:{normalized}".encode("utf-8")).hexdigest()


def last4_value(value: object) -> str | None:
    alnum = re.sub(r"[^A-Za-z0-9]", "", str(value or ""))
    return alnum[-4:] if len(alnum) >= 4 else None


def mask_ratio(value: object) -> float:
    text = str(value or "")
    protected_chars = re.sub(r"[\s-]", "", text)
    if not protected_chars:
        return 0.0
    masked_chars = len(MASK_CHAR_PATTERN.findall(protected_chars))
    return round(masked_chars / len(protected_chars), 4)


def is_masked_value(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if mask_ratio(text) > 0.7:
        return True
    return bool(MASK_PATTERN.search(text) and last4_value(text))


def masked_preview(value: object) -> str:
    last4 = last4_value(value)
    return f"********{last4}" if last4 else "********"


def _normalize_name(value: object) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower())


__all__ = [
    "AADHAAR_PATTERN",
    "PAN_PATTERN",
    "IFSC_PATTERN",
    "PiiDetectionEngine",
    "PiiDetectionResult",
    "hash_value",
    "is_valid_aadhaar",
    "is_masked_value",
    "mask_ratio",
]
