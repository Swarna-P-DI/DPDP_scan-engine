from __future__ import annotations

import time

from app.core.models import Detection, SourceLocation
from app.detectors.base import BaseDetector
from app.pii_engine.india import IFSC_REGEX
from app.utils.normalization import context_boost


class IfscDetector(BaseDetector):
    entity_type = "ifsc"

    def detect(self, text: str, source: SourceLocation, context: str | None = None) -> list[Detection]:
        start = time.perf_counter_ns()
        value = str(text or "").upper()
        detections: list[Detection] = []
        seen: set[str] = set()
        for match in IFSC_REGEX.finditer(value):
            ifsc = match.group(0)
            if ifsc in seen:
                continue
            seen.add(ifsc)
            detections.append(Detection(
                type=self.entity_type,
                value=ifsc,
                confidence=context_boost(self.entity_type, context, 0.96),
                method="regex",
                latency_ms=(time.perf_counter_ns() - start) / 1_000_000,
                source=SourceLocation(**{**source.to_dict(), "offset": match.start()}),
                context=context,
                metadata={"format_valid": True},
            ))
        return detections

