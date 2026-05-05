from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any


class StructuredEventLog:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def record(self, event: str, source: str, action: str, status: str = "OK", **details: Any) -> dict[str, Any]:
        payload = {
            "event": event,
            "source": source,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": status,
        }
        if details:
            payload["details"] = details
        self._events.append(payload)
        self._events = self._events[-1000:]
        return deepcopy(payload)

    def all(self) -> list[dict[str, Any]]:
        return deepcopy(self._events)

    def summarize(self, prompt: str, raid: dict[str, Any] | None = None) -> dict[str, Any]:
        text = str(prompt or "").lower()
        events = self.all()
        raid = raid or {}
        high_risks = [
            risk for risk in raid.get("risks", [])
            if str(risk.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
        ]
        aadhaar_risks = [
            risk for risk in raid.get("risks", [])
            if "aadhaar" in str(risk).lower()
        ]
        if "aadhaar" in text:
            focus = aadhaar_risks
        elif "high" in text or "exposure" in text:
            focus = high_risks
        else:
            focus = raid.get("risks", [])[:10]
        return {
            "prompt": prompt,
            "summary": f"{len(focus)} matching RAID risk(s), {len(events)} trace event(s) available.",
            "risks": focus,
            "recent_events": events[-10:],
        }


event_log = StructuredEventLog()


def summarize_logs(prompt: str, raid: dict[str, Any] | None = None) -> dict[str, Any]:
    return event_log.summarize(prompt, raid)
