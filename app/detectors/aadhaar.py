from __future__ import annotations

import re
import time
from difflib import SequenceMatcher

from app.core.models import Detection, SourceLocation
from app.detectors.base import BaseDetector
from app.pii_engine.india import aadhaar_checksum_valid
from app.utils.normalization import context_boost, digits_only, normalize_ocr_digits

try:
    from rapidfuzz.distance import Levenshtein
except Exception:  # pragma: no cover - optional dependency fallback
    Levenshtein = None


AADHAAR_REGEX = re.compile(r"\b[2-9]{1}[0-9]{11}\b")
SPACED_CANDIDATE_REGEX = re.compile(r"(?<!\d)(?:[2-9OIl|][\dOIl|\s-]{10,20})(?!\d)")


class AadhaarDetector(BaseDetector):
    entity_type = "aadhaar"

    def detect(self, text: str, source: SourceLocation, context: str | None = None) -> list[Detection]:
        start = time.perf_counter_ns()
        value = str(text or "")
        detections: list[Detection] = []
        seen: set[str] = set()

        normalized = normalize_ocr_digits(value)
        for match in AADHAAR_REGEX.finditer(normalized):
            aadhaar = match.group(0)
            if aadhaar in seen:
                continue
            seen.add(aadhaar)
            checksum_valid = aadhaar_checksum_valid(aadhaar)
            latency_ms = (time.perf_counter_ns() - start) / 1_000_000
            detections.append(Detection(
                type=self.entity_type,
                value=aadhaar,
                confidence=context_boost(self.entity_type, context, 0.98 if checksum_valid else 0.9),
                method="regex",
                latency_ms=latency_ms,
                source=SourceLocation(**{**source.to_dict(), "offset": match.start()}),
                context=context,
                metadata={"checksum_valid": checksum_valid},
            ))

        for match in SPACED_CANDIDATE_REGEX.finditer(value):
            candidate = digits_only(match.group(0))
            if len(candidate) != 12 or candidate[0] in {"0", "1"} or candidate in seen:
                continue
            confidence = context_boost(self.entity_type, context, self._similarity(candidate))
            if confidence < 0.86:
                continue
            checksum_valid = aadhaar_checksum_valid(candidate)
            seen.add(candidate)
            latency_ms = (time.perf_counter_ns() - start) / 1_000_000
            detections.append(Detection(
                type=self.entity_type,
                value=candidate,
                confidence=confidence if checksum_valid else min(confidence, 0.88),
                method="fuzzy",
                latency_ms=latency_ms,
                source=SourceLocation(**{**source.to_dict(), "offset": match.start()}),
                context=context,
                metadata={"checksum_valid": checksum_valid},
            ))

        return detections

    @staticmethod
    def _similarity(candidate: str) -> float:
        if not candidate:
            return 0.0
        shape = "2" + ("0" * 11)
        if Levenshtein:
            distance = Levenshtein.distance(candidate, shape, weights=(1, 1, 0))
            return max(0.86, 1.0 - (distance / 12))
        return max(0.86, SequenceMatcher(None, candidate, shape).ratio())
