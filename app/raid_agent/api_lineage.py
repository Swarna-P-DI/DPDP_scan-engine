from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

EXPOSURE_WEIGHTS = {
    "INTERNAL": 0.0,
    "PARTNER": 0.05,
    "PUBLIC": 0.1,
}


def map_api_payloads_to_fields(api_payloads: list[dict[str, Any]], catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    by_column = {_normalize(item.get("column_name")): item for item in catalog}
    for api in api_payloads or []:
        try:
            leaf_fields = _flatten_json_keys(api.get("payload") or api.get("request") or {})
            matched = False
            for json_path, key in leaf_fields:
                column = by_column.get(_normalize(key))
                if not column:
                    continue
                matched = True
                exposure = normalize_exposure_type(api.get("exposure_type"))
                display_exposure = str(api.get("exposure") or api.get("exposure_type") or exposure).strip().upper() or exposure
                risk_level = "HIGH" if exposure in {"PUBLIC", "PARTNER"} and column.get("sensitivity_level") == "HIGH" else "MEDIUM"
                mappings.append({
                    "field_id": column["field_id"],
                    "api_path": api.get("api_path") or api.get("path") or api.get("endpoint") or "unknown",
                    "path": api.get("api_path") or api.get("path") or api.get("endpoint") or "unknown",
                    "http_method": str(api.get("http_method") or api.get("method") or "GET").upper(),
                    "method": str(api.get("http_method") or api.get("method") or "GET").upper(),
                    "service_name": api.get("service_name") or "unknown",
                    "service": api.get("service_name") or api.get("service") or "unknown",
                    "exposure_type": exposure,
                    "exposure": display_exposure,
                    "exposure_weight": exposure_weight(exposure),
                    "request_count": _safe_int(api.get("request_count"), default=0),
                    "response_count": _safe_int(api.get("response_count"), default=0),
                    "request_rate": request_rate(api),
                    "authenticated": _safe_bool(api.get("authenticated"), default=True),
                    "last_accessed": api.get("last_accessed") or api.get("accessed_at"),
                    "risk_level": risk_level,
                    "json_path": json_path,
                })
            if leaf_fields and not matched:
                logger.warning("API exposure payload did not map to any PII field", extra={"api_path": api.get("api_path") or api.get("path") or api.get("endpoint")})
            if not leaf_fields:
                logger.warning("API exposure payload had no request keys to map", extra={"api_path": api.get("api_path") or api.get("path") or api.get("endpoint")})
        except Exception:
            logger.exception("API lineage mapping failed for payload %s", api.get("api_path"))
    return _dedupe_mappings(mappings)


def api_exposure_alerts(mappings: list[dict[str, Any]], catalog: list[dict[str, Any]]) -> list[dict[str, str]]:
    by_field = {item.get("field_id"): item for item in catalog}
    alerts = []
    for mapping in mappings:
        field = by_field.get(mapping.get("field_id"), {})
        if mapping.get("exposure_type") == "PUBLIC" and field.get("sensitivity_level") == "HIGH":
            alerts.append({
                "field_id": str(mapping.get("field_id")),
                "alert": "High sensitivity PII exposed through public API",
                "risk_level": "CRITICAL" if field.get("pii_type") == "Aadhaar" else "HIGH",
                "api_path": str(mapping.get("api_path")),
            })
    return alerts


def normalize_exposure_type(value: object) -> str:
    exposure = str(value or "INTERNAL").strip().upper()
    aliases = {
        "EXTERNAL": "PUBLIC",
        "PUBLIC_API": "PUBLIC",
        "INTERNET": "PUBLIC",
        "THIRD_PARTY": "PARTNER",
        "VENDOR": "PARTNER",
    }
    return aliases.get(exposure, exposure if exposure in EXPOSURE_WEIGHTS else "INTERNAL")


def exposure_weight(exposure_type: object) -> float:
    return EXPOSURE_WEIGHTS[normalize_exposure_type(exposure_type)]


def frequency_weight(request_count: int | None, response_count: int | None = None) -> float:
    total = max(int(request_count or 0), int(response_count or 0))
    if total >= 100_000:
        return 0.08
    if total >= 10_000:
        return 0.05
    if total >= 1_000:
        return 0.02
    return 0.0


def request_rate(api: dict[str, Any]) -> float:
    """Return requests per minute using caller-supplied window metadata when available."""
    count = _safe_int(api.get("request_count"), default=0)
    minutes = _safe_float(
        api.get("request_window_minutes")
        or api.get("window_minutes")
        or api.get("period_minutes")
    )
    if minutes is None:
        seconds = _safe_float(api.get("request_window_seconds") or api.get("window_seconds") or api.get("period_seconds"))
        minutes = seconds / 60 if seconds and seconds > 0 else 1440.0
    if minutes <= 0:
        minutes = 1440.0
    return round(count / minutes, 4)


def _flatten_json_keys(payload: Any, prefix: str = "$") -> list[tuple[str, str]]:
    if isinstance(payload, dict):
        output: list[tuple[str, str]] = []
        for key, value in payload.items():
            path = f"{prefix}.{key}"
            if isinstance(value, (dict, list)):
                output.extend(_flatten_json_keys(value, path))
            else:
                output.append((path, str(key)))
        return output
    if isinstance(payload, list):
        output = []
        for index, item in enumerate(payload):
            output.extend(_flatten_json_keys(item, f"{prefix}[{index}]"))
        return output
    return []


def _normalize(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _dedupe_mappings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in items:
        key = (item.get("field_id"), item.get("api_path"), item.get("http_method"))
        if key not in seen:
            seen.add(key)
            output.append(item)
        else:
            existing = next(entry for entry in output if (entry.get("field_id"), entry.get("api_path"), entry.get("http_method")) == key)
            existing["request_count"] = int(existing.get("request_count") or 0) + int(item.get("request_count") or 0)
            existing["response_count"] = int(existing.get("response_count") or 0) + int(item.get("response_count") or 0)
            existing["request_rate"] = round(float(existing.get("request_rate") or 0) + float(item.get("request_rate") or 0), 4)
            existing["last_accessed"] = max(str(existing.get("last_accessed") or ""), str(item.get("last_accessed") or "")) or None
    return output


def _safe_int(value: object, *, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: object) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_bool(value: object, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if not text:
        return default
    return text in {"true", "yes", "y", "1", "authenticated"}
