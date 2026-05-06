from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.compliance_engine.service import evaluate_dpdp_compliance
from app.observability.logger import event_log
from app.pii_engine.index import hash_value, is_encrypted, is_masked, pii_index_store
from app.raid_agent.service import generate_raid
from app.reporting.service import consolidated_report
from app.risk.engine import generate_exposure_heatmap
from app.storage.memory import report_store


REPORTS_DIR = Path("storage/reports")


def hydrate_from_latest_inventory_report() -> dict[str, Any]:
    existing = report_store.latest()
    if existing.get("pii_index"):
        return existing

    latest = _latest_json_report()
    if latest is None:
        return existing

    with latest.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    report = build_inventory_intelligence_report(payload, artifact_path=str(latest))
    report_store.save(report)
    pii_index_store.replace(report.get("pii_index", []))
    event_log.record(
        "scan_execution",
        "metadata_inventory",
        "hydrate_latest_inventory_report",
        artifact=str(latest),
        findings=len(report.get("pii_index", [])),
    )
    return report


def build_inventory_intelligence_report(
    payload: dict[str, Any],
    *,
    artifact_path: str | None = None,
    status: str = "hydrated_from_scan_outputs",
) -> dict[str, Any]:
    metadata = _metadata(payload, artifact_path)
    profiling = payload.get("profiling") or {}
    source_inventory = payload.get("source_inventory") or (payload.get("metadata") or {}).get("source_inventory") or {}
    column_intelligence = payload.get("column_intelligence") or payload.get("classification") or {}
    pii_index = _index_from_column_intelligence(column_intelligence, source_inventory, metadata, profiling)
    compliance = evaluate_dpdp_compliance(pii_index, source_controls=_source_controls(source_inventory))
    raid = generate_raid(
        findings=[],
        pii_index=pii_index,
        compliance=compliance,
        profiling={"row_count": _profiled_rows(profiling), "column_count": len(pii_index)},
    )
    existing_raid = payload.get("raid") or {}
    raid = _merge_raid(existing_raid, raid)
    heatmap = {
        "source_vs_pii": generate_exposure_heatmap(pii_index),
        "high": sum(1 for item in pii_index if item.get("pii_type") in {"aadhaar", "pan", "ifsc"} and not item.get("masked")),
        "medium": sum(1 for item in pii_index if item.get("masked") and not item.get("encrypted")),
        "low": sum(1 for item in pii_index if item.get("encrypted")),
    }
    ownership_details = _ownership(source_inventory)
    consolidated = consolidated_report(
        metadata=metadata,
        profiling=profiling,
        pii_index=pii_index,
        raid=raid,
        compliance=compliance,
        ownership_details=ownership_details,
    )
    return {
        "summary": {
            "status": status,
            "files_scanned": 0,
            "sources_scanned": len(source_inventory.get("tables", [])),
            "findings": len(pii_index),
            "high_risk_findings": heatmap["high"],
            "medium_risk_findings": heatmap["medium"],
            "low_risk_findings": heatmap["low"],
        },
        "metadata": metadata,
        "profiling": profiling,
        "pii_findings": [],
        "pii_index": pii_index,
        "pii_summary": consolidated["pii_summary"],
        "column_risks": _column_risks(pii_index),
        "risk_heatmap": heatmap,
        "raid": raid,
        "compliance_status": compliance,
        "data_intelligence": consolidated["data_intelligence"],
        "ownership_details": ownership_details,
        "consolidated_report": consolidated,
        "latency_stats": {"count": 0, "avg_ms": 0, "max_ms": 0, "records": []},
    }


def latest_intelligence_report() -> dict[str, Any]:
    return hydrate_from_latest_inventory_report()


def _latest_json_report() -> Path | None:
    if not REPORTS_DIR.exists():
        return None
    reports = sorted(
        (path for path in REPORTS_DIR.glob("*.json") if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return reports[0] if reports else None


def _metadata(payload: dict[str, Any], artifact_path: str | None) -> dict[str, Any]:
    overview = payload.get("overview") or {}
    existing = payload.get("metadata") or {}
    return {
        "run_id": payload.get("run_id") or overview.get("run_id") or existing.get("run_id") or "latest",
        "created_at": existing.get("created_at") or overview.get("created_at"),
        "engine": "SCAN + RAID Metadata Inventory Intelligence",
        "version": "1.1.0",
        "source": "latest_scan_outputs",
        "artifact_path": artifact_path,
    }


def _index_from_column_intelligence(
    column_intelligence: dict[str, Any],
    source_inventory: dict[str, Any],
    metadata: dict[str, Any],
    profiling: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    tables = column_intelligence.get("tables") if isinstance(column_intelligence, dict) else {}
    source_types = _table_source_types(source_inventory)
    profiling = profiling or {}
    entries = []
    for table_name, columns in (tables or {}).items():
        table_profile = profiling.get(table_name) if isinstance(profiling, dict) else {}
        table_metadata = _table_metadata(source_inventory, table_name)
        for column in columns or []:
            if not column.get("pii_detected"):
                continue
            pii_type = str(column.get("pii_type") or "unknown").lower()
            column_name = str(column.get("column") or "unknown")
            row_entries = _row_entries(
                table_name=table_name,
                source_type=source_types.get(table_name, "metadata_inventory"),
                table_profile=table_profile or {},
                table_metadata=table_metadata,
                column=column,
                column_name=column_name,
                pii_type=pii_type,
                timestamp=metadata.get("created_at"),
            )
            if row_entries:
                entries.extend(row_entries)
                continue
            masking_status = str(column.get("masking_status") or "").upper()
            encrypted = bool(column.get("encrypted") or column.get("encryption_enabled"))
            fingerprint = f"{metadata.get('run_id')}:{table_name}:{column_name}:{pii_type}"
            value_hash = column.get("value_hash") or hash_value(fingerprint, pii_type)
            sample_values = _sample_values(table_profile, column_name)
            searchable_terms = _searchable_terms(table_name, column_name, pii_type, sample_values)
            entries.append({
                "pii_type": pii_type,
                "value_hash": value_hash,
                "source_id": table_name,
                "source_type": source_types.get(table_name, "metadata_inventory"),
                "location": f"table={table_name};column={column_name}",
                "masked": masking_status in {"MASKED", "PARTIALLY_MASKED"},
                "encrypted": encrypted,
                "timestamp": metadata.get("created_at"),
                "confidence": column.get("confidence_score"),
                "metadata": {
                    "column": column_name,
                    "masking_status": masking_status or "UNKNOWN",
                    "classification": column.get("classification"),
                    "risk": column.get("risk"),
                    "detected_by": column.get("detected_by"),
                    "raw_value_available": bool(sample_values),
                    "sample_values": sample_values[:10],
                    "search_terms": searchable_terms,
                },
            })
    return entries


def _row_entries(
    *,
    table_name: str,
    source_type: str,
    table_profile: dict[str, Any],
    table_metadata: dict[str, Any],
    column: dict[str, Any],
    column_name: str,
    pii_type: str,
    timestamp: str | None,
) -> list[dict[str, Any]]:
    records = table_profile.get("sample_records") or []
    if not records:
        return []

    entries = []
    primary_keys = table_metadata.get("primary_key") or []
    encrypted_by_source = bool(table_metadata.get("encrypted") or table_metadata.get("encryption_enabled"))
    for index, record in enumerate(records):
        if not isinstance(record, dict) or column_name not in record:
            continue
        raw_value = record.get(column_name)
        if raw_value in (None, ""):
            continue
        row_ref = _row_ref(record, primary_keys, index)
        masked = is_masked(raw_value)
        encrypted = is_encrypted(raw_value, {"encrypted": encrypted_by_source})
        entries.append({
            "pii_type": pii_type,
            "value_hash": hash_value(raw_value, pii_type),
            "source_id": table_name,
            "source_type": source_type,
            "location": f"table={table_name};column={column_name};row={row_ref}",
            "masked": masked,
            "encrypted": encrypted,
            "timestamp": timestamp,
            "confidence": column.get("confidence_score"),
            "metadata": {
                "column": column_name,
                "masking_status": "MASKED" if masked else "NOT_MASKED",
                "classification": column.get("classification"),
                "risk": column.get("risk"),
                "detected_by": column.get("detected_by"),
                "raw_value_available": True,
                "row_data": {str(key): value for key, value in record.items()},
                "search_terms": _searchable_terms(table_name, column_name, pii_type, [str(value) for value in record.values()]),
            },
        })
    return entries


def _table_metadata(source_inventory: dict[str, Any], table_name: str) -> dict[str, Any]:
    for table in source_inventory.get("tables", []):
        if str(table.get("qualified_name")) == table_name:
            return table
    return {}


def _row_ref(record: dict[str, Any], primary_keys: list[str], index: int) -> str:
    parts = [str(record.get(key)) for key in primary_keys if record.get(key) not in (None, "")]
    return ",".join(parts) if parts else str(index)


def _sample_values(table_profile: dict[str, Any], column_name: str) -> list[str]:
    column_profiles = table_profile.get("column_profiles") if isinstance(table_profile, dict) else {}
    column_profile = (column_profiles or {}).get(column_name) or {}
    values = []
    for item in column_profile.get("value_distribution") or []:
        if isinstance(item, dict) and item.get("value") is not None:
            values.append(str(item["value"]))
    if values:
        return _dedupe_strings(values)

    sample_values = table_profile.get("sample_values") if isinstance(table_profile, dict) else {}
    if isinstance(sample_values, dict):
        return _dedupe_strings(str(value) for value in sample_values.get(column_name, []) if value is not None)
    return []


def _searchable_terms(table_name: str, column_name: str, pii_type: str, sample_values: list[str]) -> list[str]:
    text = " ".join([table_name, column_name, pii_type, *sample_values])
    return _dedupe_strings(token.lower() for token in re.findall(r"[A-Za-z0-9@._+-]+", text) if token)


def _dedupe_strings(values) -> list[str]:
    seen = set()
    output = []
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            output.append(text)
    return output


def _table_source_types(source_inventory: dict[str, Any]) -> dict[str, str]:
    source_type = str(source_inventory.get("source_type") or "metadata_inventory")
    return {
        str(table.get("qualified_name")): str(table.get("source_type") or source_type)
        for table in source_inventory.get("tables", [])
    }


def _source_controls(source_inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    controls = {}
    for table in source_inventory.get("tables", []):
        name = str(table.get("qualified_name"))
        controls[name] = {
            "access_controlled": table.get("access_controlled", True),
            "publicly_exposed": table.get("publicly_exposed", False),
        }
    return controls


def _ownership(source_inventory: dict[str, Any]) -> list[dict[str, Any]]:
    details = []
    for table in source_inventory.get("tables", []):
        details.append({
            "source_id": table.get("qualified_name"),
            "dataset_owner": table.get("dataset_owner") or table.get("owner") or "unknown",
            "data_steward": table.get("data_steward") or "Data Engineering / Data Steward",
            "ownership_status": table.get("ownership_status") or "unknown",
        })
    return details


def _column_risks(pii_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for entry in pii_index:
        level = "LOW" if entry.get("encrypted") else "MEDIUM" if entry.get("masked") else "HIGH"
        rows.append({
            "file": None,
            "source_id": entry.get("source_id"),
            "column": (entry.get("metadata") or {}).get("column"),
            "risk": level,
            "pii_detected": [entry.get("pii_type")],
        })
    return rows


def _profiled_rows(profiling: dict[str, Any]) -> int:
    total = 0
    for stats in profiling.values() if isinstance(profiling, dict) else []:
        if isinstance(stats, dict):
            total += int(stats.get("row_count") or stats.get("sample_size") or 0)
    return total


def _merge_raid(existing: dict[str, Any], generated: dict[str, Any]) -> dict[str, Any]:
    merged = dict(generated)
    for key in ("risks", "issues", "assumptions", "dependencies", "recommendations"):
        merged[key] = _dedupe((existing.get(key) or []) + (generated.get(key) or []))
    if existing.get("context"):
        merged["context"] = existing["context"]
    return merged


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in items:
        key = tuple(sorted((str(k), str(v)) for k, v in item.items())) if isinstance(item, dict) else str(item)
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output
