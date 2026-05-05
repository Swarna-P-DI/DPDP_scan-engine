from __future__ import annotations

from abc import ABC, abstractmethod

from app.core.models import Detection, SourceLocation


class BaseDetector(ABC):
    entity_type: str

    @abstractmethod
    def detect(self, text: str, source: SourceLocation, context: str | None = None) -> list[Detection]:
        """Return detections found in text."""
