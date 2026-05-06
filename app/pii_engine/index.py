from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any


HASH_PATTERNS = (
    re.compile(r"^[a-fA-F0-9]{32}$"),
    re.compile(r"^[a-fA-F0-9]{40}$"),
    re.compile(r"^[a-fA-F0-9]{64}$"),
)


def hash_value(value: object, pii_type: str | None = None) -> str:
    normalized = str(value or "").strip().upper()
    digest_input = f"{pii_type or 'pii'}:{normalized}"
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()


def masked_preview(value: object) -> str:
    text = str(value or "").strip()
    if len(text) <= 4:
        return "*" * len(text)
    return f"{'*' * max(4, len(text) - 4)}{text[-4:]}"


def is_masked(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if any(pattern.fullmatch(text) for pattern in HASH_PATTERNS):
        return True
    if re.fullmatch(r"[*xX#]{3,}", text):
        return True
    if any(mask in text for mask in ("*", "x", "X", "#")):
        visible = len(re.sub(r"[*xX#\s@._+-]", "", text))
        hidden = len(re.findall(r"[*xX#]", text))
        return hidden >= visible
    return False


def is_encrypted(value: object, source_metadata: dict[str, Any] | None = None) -> bool:
    source_metadata = source_metadata or {}
    if source_metadata.get("encrypted") is True or source_metadata.get("encryption_enabled") is True:
        return True
    text = str(value or "").strip()
    if len(text) < 24:
        return False
    entropy = _entropy(text)
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", text) and entropy >= 3.8)


def build_pii_index(
    findings: list[dict[str, Any]],
    *,
    source_metadata: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> list[dict[str, Any]]:
    created_at = timestamp or datetime.now(timezone.utc).isoformat()
    entries = []
    for finding in findings:
        pii_type = str(finding.get("type") or "").lower()
        raw_value = finding.get("value")
        source = finding.get("source") or {}
        source_id = source.get("file") or source.get("table")
        if not source_id and source_metadata:
            source_id = source_metadata.get("source_id")
        source_id = source_id or "unknown"
        source_type = _source_type(source_id, source_metadata)
        location = _location(source)
        masked = bool(finding.get("masked", is_masked(raw_value)))
        encrypted = bool(finding.get("encrypted", is_encrypted(raw_value, source_metadata)))
        entries.append({
            "pii_type": pii_type,
            "value_hash": hash_value(raw_value, pii_type),
            "source_id": source_id,
            "source_type": source_type,
            "location": location,
            "masked": masked,
            "encrypted": encrypted,
            "timestamp": created_at,
            "confidence": finding.get("confidence"),
            "metadata": {
                **finding.get("metadata", {}),
                "value_preview": masked_preview(raw_value),
                "search_terms": _searchable_terms(source_id, source_type, location, pii_type, raw_value, finding.get("context")),
            },
        })
    return entries


class PiiIndexRepository:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def replace(self, entries: list[dict[str, Any]]) -> None:
        self._entries = deepcopy(entries)
        self._rebuild()

    def add_many(self, entries: list[dict[str, Any]]) -> None:
        self._entries.extend(deepcopy(entries))
        self._rebuild()

    def all(self) -> list[dict[str, Any]]:
        return deepcopy(self._entries)

    def lookup(self, *, pii_types: list[str] | None = None, value_hashes: list[str] | None = None) -> list[dict[str, Any]]:
        if value_hashes:
            candidates = [item for value_hash in value_hashes for item in self._by_hash.get(value_hash, [])]
        elif pii_types:
            candidates = [item for pii_type in pii_types for item in self._by_type.get(pii_type.lower(), [])]
        else:
            candidates = self._entries
        if pii_types:
            allowed = {item.lower() for item in pii_types}
            candidates = [item for item in candidates if item.get("pii_type") in allowed]
        return deepcopy(candidates)

    def _rebuild(self) -> None:
        self._by_type = defaultdict(list)
        self._by_hash = defaultdict(list)
        self._by_source = defaultdict(list)
        for entry in self._entries:
            self._by_type[str(entry.get("pii_type", "")).lower()].append(entry)
            self._by_hash[str(entry.get("value_hash", ""))].append(entry)
            self._by_source[str(entry.get("source_id", ""))].append(entry)


def sanitize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized = []
    for finding in findings:
        item = deepcopy(finding)
        value = item.pop("value", None)
        item["value_hash"] = hash_value(value, item.get("type"))
        item["value_preview"] = masked_preview(value)
        item["masked"] = is_masked(value)
        item["encrypted"] = is_encrypted(value)
        sanitized.append(item)
    return sanitized


def _location(source: dict[str, Any]) -> str:
    parts = []
    for key in ("table", "column", "file", "page", "row", "offset"):
        if source.get(key) is not None:
            parts.append(f"{key}={source[key]}")
    return ";".join(parts) or "unknown"


def _source_type(source_id: str, source_metadata: dict[str, Any] | None) -> str:
    if source_metadata and source_metadata.get("source_type"):
        return str(source_metadata["source_type"])
    lowered = source_id.lower()
    if "." in lowered:
        return lowered.rsplit(".", 1)[-1]
    return "file"


def _searchable_terms(*values: object) -> list[str]:
    seen = set()
    output = []
    for value in values:
        for token in re.findall(r"[A-Za-z0-9@._+-]+", str(value or "").lower()):
            if token and token not in seen:
                seen.add(token)
                output.append(token)
    return output


def _entropy(value: str) -> float:
    probabilities = [value.count(char) / len(value) for char in set(value)] if value else []
    return -sum(probability * math.log2(probability) for probability in probabilities)


pii_index_store = PiiIndexRepository()
