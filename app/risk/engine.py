from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


ENTITY_RISK = {
    "aadhaar": "HIGH",
    "pan": "HIGH",
    "ifsc": "HIGH",
    "phone": "MEDIUM",
    "email": "MEDIUM",
    "name": "LOW",
}
RISK_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def risk_for_entities(entities: list[str]) -> str:
    levels = [ENTITY_RISK.get(entity.lower(), "LOW") for entity in entities]
    return max(levels or ["LOW"], key=lambda level: RISK_ORDER[level])


def classify_columns(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in findings:
        source = finding.get("source", {})
        column = source.get("column") or "document_text"
        file_name = source.get("file") or "unknown"
        grouped[(file_name, column)].add(str(finding.get("type", "")).lower())

    rows = []
    for (file_name, column), entities in sorted(grouped.items()):
        detected = sorted(entity for entity in entities if entity)
        rows.append({
            "file": file_name,
            "column": column,
            "risk": risk_for_entities(detected),
            "pii_detected": detected,
        })
    return rows


def generate_heatmap(column_risks: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    column_counts = Counter(item["risk"].lower() for item in column_risks)
    finding_counts = Counter(risk_for_entities([str(item.get("type", "")).lower()]).lower() for item in findings)
    return {
        "table_level": {
            "high": int(column_counts.get("high", 0)),
            "medium": int(column_counts.get("medium", 0)),
            "low": int(column_counts.get("low", 0)),
        },
        "dataset_level": {
            "high": int(finding_counts.get("high", 0)),
            "medium": int(finding_counts.get("medium", 0)),
            "low": int(finding_counts.get("low", 0)),
        },
        "high": int(finding_counts.get("high", 0)),
        "medium": int(finding_counts.get("medium", 0)),
        "low": int(finding_counts.get("low", 0)),
    }


def generate_exposure_heatmap(pii_index: list[dict[str, Any]]) -> dict[str, Any]:
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in pii_index:
        source = str(entry.get("source_id") or "unknown")
        pii_type = str(entry.get("pii_type") or "unknown")
        key = (source, pii_type)
        cell = cells.setdefault(key, {
            "source_id": source,
            "pii_type": pii_type,
            "count": 0,
            "masked": 0,
            "encrypted": 0,
            "unprotected": 0,
            "risk_score": 0,
            "risk_level": "LOW",
        })
        cell["count"] += 1
        if entry.get("encrypted"):
            score = 1
            cell["encrypted"] += 1
        elif entry.get("masked"):
            score = 2
            cell["masked"] += 1
        else:
            score = 3
            cell["unprotected"] += 1
        if pii_type == "aadhaar" and not entry.get("masked") and not entry.get("encrypted"):
            score = 3
        cell["risk_score"] = max(cell["risk_score"], score)
        cell["risk_level"] = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}[cell["risk_score"]]
    return {
        "dimensions": ["source_id", "pii_type"],
        "cells": sorted(cells.values(), key=lambda item: (item["source_id"], item["pii_type"])),
    }
