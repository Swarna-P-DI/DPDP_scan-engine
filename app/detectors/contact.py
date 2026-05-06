from __future__ import annotations

import re
import time

from app.core.models import Detection, SourceLocation
from app.detectors.base import BaseDetector
from app.utils.normalization import context_boost


EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_REGEX = re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)")


class EmailDetector(BaseDetector):
    entity_type = "email"

    def detect(self, text: str, source: SourceLocation, context: str | None = None) -> list[Detection]:
        start = time.perf_counter_ns()
        detections = []
        for match in EMAIL_REGEX.finditer(str(text or "")):
            detections.append(Detection(
                type=self.entity_type,
                value=match.group(0),
                confidence=context_boost(self.entity_type, context, 0.96),
                method="regex",
                latency_ms=(time.perf_counter_ns() - start) / 1_000_000,
                source=SourceLocation(**{**source.to_dict(), "offset": match.start()}),
                context=context,
            ))
        return detections


class PhoneDetector(BaseDetector):
    entity_type = "phone"

    def detect(self, text: str, source: SourceLocation, context: str | None = None) -> list[Detection]:
        start = time.perf_counter_ns()
        detections = []
        for match in PHONE_REGEX.finditer(str(text or "")):
            detections.append(Detection(
                type=self.entity_type,
                value=match.group(0),
                confidence=context_boost(self.entity_type, context, 0.93),
                method="regex",
                latency_ms=(time.perf_counter_ns() - start) / 1_000_000,
                source=SourceLocation(**{**source.to_dict(), "offset": match.start()}),
                context=context,
            ))
        return detections
