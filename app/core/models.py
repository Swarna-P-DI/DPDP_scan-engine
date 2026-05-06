from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


RiskLevel = Literal["HIGH", "MEDIUM", "LOW"]
DetectionMethod = Literal["regex", "fuzzy"]


@dataclass(slots=True)
class SourceLocation:
    file: str
    column: str | None = None
    row: int | None = None
    page: int | None = None
    offset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "file": self.file,
                "column": self.column,
                "row": self.row,
                "page": self.page,
                "offset": self.offset,
            }.items()
            if value is not None
        }


@dataclass(slots=True)
class Detection:
    type: str
    value: str
    confidence: float
    method: DetectionMethod
    latency_ms: float
    source: SourceLocation
    context: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "type": self.type,
            "value": self.value,
            "confidence": round(float(self.confidence), 4),
            "method": self.method,
            "latency_ms": round(float(self.latency_ms), 4),
            "source": self.source.to_dict(),
        }
        if self.context:
            payload["context"] = self.context
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload

    def latency_record(self) -> dict[str, Any]:
        return {"entity": self.type, "latency_ms": round(float(self.latency_ms), 4)}


@dataclass(slots=True)
class ParsedInput:
    file_name: str
    file_type: str
    dataframe: Any | None = None
    text_pages: list[dict[str, Any]] = field(default_factory=list)
    raw_record_count: int = 0
