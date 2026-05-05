from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from app.detectors.engine import DetectionEngine
from app.core.models import SourceLocation
from app.pii_engine.index import hash_value


PII_TYPE_ALIASES = {
    "aadhaar": "aadhaar",
    "aadhar": "aadhaar",
    "pan": "pan",
    "ifsc": "ifsc",
    "email": "email",
    "phone": "phone",
    "mobile": "phone",
    "name": "name",
    "financial": "financial",
    "account": "financial",
}


class FederatedSearchService:
    def __init__(self, detection_engine: DetectionEngine | None = None) -> None:
        self.detection_engine = detection_engine or DetectionEngine()

    def parse(self, query: str) -> dict[str, Any]:
        raw_terms = [term.strip() for term in re.split(r"\s*\+\s*|\s+", query or "") if term.strip()]
        pii_types = []
        value_hashes = []
        name_terms = []
        source = SourceLocation(file="query")
        for term in raw_terms:
            lowered = term.lower()
            if lowered in PII_TYPE_ALIASES:
                pii_types.append(PII_TYPE_ALIASES[lowered])
                continue
            detections = self.detection_engine.detect(term, source, context="query")
            if detections:
                for detection in detections:
                    pii_types.append(detection.type)
                    value_hashes.append(hash_value(detection.value, detection.type))
            else:
                name_terms.append(term)
        return {
            "pii_types": sorted(set(pii_types)),
            "value_hashes": sorted(set(value_hashes)),
            "name_terms": name_terms,
        }

    def search(self, query: str, pii_index: list[dict[str, Any]]) -> dict[str, Any]:
        parsed = self.parse(query)
        matches = [
            entry for entry in pii_index
            if (not parsed["pii_types"] or entry.get("pii_type") in parsed["pii_types"])
            and (not parsed["value_hashes"] or entry.get("value_hash") in parsed["value_hashes"])
            and _matches_name_terms(entry, parsed["name_terms"])
        ]
        groups: dict[str, dict[str, Any]] = {}
        by_identity = defaultdict(list)
        for entry in matches:
            key = _identity_key(entry)
            by_identity[key].append(entry)
        for key, entries in by_identity.items():
            rank = _rank_score(parsed, entries)
            groups[key] = {
                "identity_key": key,
                "rank": rank,
                "sources": sorted({entry.get("source_id") for entry in entries}),
                "records": sorted(entries, key=lambda item: (item.get("source_id"), item.get("location"))),
            }
        return {
            "query": query,
            "parsed": parsed,
            "total_matches": len(matches),
            "groups": sorted(groups.values(), key=lambda item: item["rank"], reverse=True),
        }


def _identity_key(entry: dict[str, Any]) -> str:
    location = str(entry.get("location") or "")
    row_match = re.search(r"row=([^;]+)", location)
    row_part = f":row={row_match.group(1)}" if row_match else ""
    return f"{entry.get('source_id')}{row_part}:{entry.get('value_hash')[:12]}"


def _matches_name_terms(entry: dict[str, Any], terms: list[str]) -> bool:
    if not terms:
        return True
    haystack = _searchable_text(entry)
    return all(str(term or "").lower() in haystack for term in terms)


def _searchable_text(entry: dict[str, Any]) -> str:
    metadata = entry.get("metadata") or {}
    values = [
        entry.get("pii_type"),
        entry.get("source_id"),
        entry.get("source_type"),
        entry.get("location"),
        metadata.get("column"),
        metadata.get("classification"),
        metadata.get("risk"),
        metadata.get("masking_status"),
        metadata.get("value_preview"),
    ]
    values.extend(metadata.get("search_terms") or [])
    values.extend(metadata.get("sample_values") or [])
    row_data = metadata.get("row_data") or {}
    if isinstance(row_data, dict):
        values.extend(row_data.keys())
        values.extend(row_data.values())
    return " ".join(str(value or "").lower() for value in values)


def _rank_score(parsed: dict[str, Any], entries: list[dict[str, Any]]) -> int:
    if not entries:
        return 0

    requested_types = set(parsed.get("pii_types") or [])
    matched_types = {entry.get("pii_type") for entry in entries if entry.get("pii_type")}
    exact_hash_match = bool(parsed.get("value_hashes")) and any(
        entry.get("value_hash") in parsed.get("value_hashes", []) for entry in entries
    )
    name_terms = parsed.get("name_terms") or []
    term_match_ratio = 0.0
    if name_terms:
        searchable = " ".join(_searchable_text(entry) for entry in entries)
        term_match_ratio = sum(1 for term in name_terms if str(term).lower() in searchable) / len(name_terms)

    match_strength = 1.0 if exact_hash_match else 0.85 if term_match_ratio == 1.0 else 0.75 if requested_types & matched_types else 0.45
    matched_fields_count = min(len(matched_types) / max(len(requested_types), 1), 1.0)
    cross_source_matches = min(len({entry.get("source_id") for entry in entries if entry.get("source_id")}) / 3, 1.0)
    validation_values = [
        float(entry.get("confidence") or (entry.get("metadata") or {}).get("confidence") or 0.75)
        for entry in entries
    ]
    validation_score = max(0.0, min(sum(validation_values) / len(validation_values), 1.0))

    weighted_score = (
        0.4 * match_strength
        + 0.2 * max(matched_fields_count, term_match_ratio)
        + 0.2 * cross_source_matches
        + 0.2 * validation_score
    )
    return int(round(max(0.0, min(weighted_score, 1.0)) * 100))
