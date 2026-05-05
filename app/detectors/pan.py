from __future__ import annotations

import re
import time

from app.core.models import Detection, SourceLocation
from app.detectors.base import BaseDetector
from app.utils.normalization import compact_alnum, context_boost


PAN_REGEX = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
PAN_LOOSE_REGEX = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z][\s-]*){5}(?:\d[\s-]*){4}[A-Za-z](?![A-Za-z0-9])")


class PanDetector(BaseDetector):
    entity_type = "pan"

    def detect(self, text: str, source: SourceLocation, context: str | None = None) -> list[Detection]:
        start = time.perf_counter_ns()
        value = str(text or "")
        detections: list[Detection] = []
        seen: set[str] = set()

        upper = value.upper()
        for match in PAN_REGEX.finditer(upper):
            pan = match.group(0)
            seen.add(pan)
            detections.append(Detection(
                type=self.entity_type,
                value=pan,
                confidence=context_boost(self.entity_type, context, 0.97),
                method="regex",
                latency_ms=(time.perf_counter_ns() - start) / 1_000_000,
                source=SourceLocation(**{**source.to_dict(), "offset": match.start()}),
                context=context,
            ))

        for match in PAN_LOOSE_REGEX.finditer(value):
            pan = compact_alnum(match.group(0))
            if pan in seen or not PAN_REGEX.fullmatch(pan):
                continue
            seen.add(pan)
            detections.append(Detection(
                type=self.entity_type,
                value=pan,
                confidence=context_boost(self.entity_type, context, 0.9),
                method="fuzzy",
                latency_ms=(time.perf_counter_ns() - start) / 1_000_000,
                source=SourceLocation(**{**source.to_dict(), "offset": match.start()}),
                context=context,
            ))

        return detections
