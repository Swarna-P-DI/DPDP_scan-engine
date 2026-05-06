from __future__ import annotations

from collections.abc import Iterable

from app.core.models import Detection, SourceLocation
from app.detectors.aadhaar import AadhaarDetector
from app.detectors.base import BaseDetector
from app.detectors.contact import EmailDetector, PhoneDetector
from app.detectors.ifsc import IfscDetector
from app.detectors.pan import PanDetector


class DetectionEngine:
    def __init__(self, detectors: Iterable[BaseDetector] | None = None) -> None:
        self.detectors = list(detectors or [
            AadhaarDetector(),
            PanDetector(),
            IfscDetector(),
            EmailDetector(),
            PhoneDetector(),
        ])

    def detect(self, text: object, source: SourceLocation, context: str | None = None) -> list[Detection]:
        normalized = "" if text is None else str(text)
        results: list[Detection] = []
        for detector in self.detectors:
            results.extend(detector.detect(normalized, source, context=context))
        return results
