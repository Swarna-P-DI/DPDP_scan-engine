from __future__ import annotations

import asyncio
from typing import Any

import pandas as pd

from app.core.models import SourceLocation
from app.compliance_engine.service import evaluate_dpdp_compliance
from app.detectors.engine import DetectionEngine
from app.observability.logger import event_log
from app.pii_engine.index import build_pii_index, pii_index_store
from app.profiling.profiler import profile_dataframe
from app.raid.agent import build_raid
from app.raid_agent.service import generate_raid
from app.report.generator import build_report
from app.risk.engine import classify_columns, generate_exposure_heatmap, generate_heatmap
from app.storage.memory import report_store
from app.utils.file_parsers import parse_upload


class ScanService:
    def __init__(self, detection_engine: DetectionEngine | None = None) -> None:
        self.detection_engine = detection_engine or DetectionEngine()

    async def scan_bytes(self, file_name: str, content: bytes) -> dict[str, Any]:
        event_log.record("scan_execution", file_name, "scan_started")
        parsed = await asyncio.to_thread(parse_upload, file_name, content)
        findings = []
        latency_records = []
        profiling: dict[str, Any]

        if parsed.dataframe is not None:
            df: pd.DataFrame = parsed.dataframe
            profiling = profile_dataframe(df)
            for row_index, row in df.iterrows():
                row_metadata = _row_metadata(row.to_dict())
                for column in df.columns:
                    context = f"{file_name} {column}"
                    source = SourceLocation(file=file_name, column=str(column), row=int(row_index))
                    detections = self.detection_engine.detect(row[column], source, context=context)
                    if detections:
                        event_log.record("pii_detection", file_name, "detect_structured", source_location=str(source.to_dict()), count=len(detections))
                    for detection in detections:
                        payload = detection.to_dict()
                        payload["metadata"] = {
                            **payload.get("metadata", {}),
                            **row_metadata,
                        }
                        findings.append(payload)
                        latency_records.append(detection.latency_record())
        else:
            profiling = {"row_count": 0, "column_count": 0, "columns": {}, "document_pages": len(parsed.text_pages)}
            for page in parsed.text_pages:
                source = SourceLocation(file=file_name, column="document_text", page=int(page["page"]))
                detections = self.detection_engine.detect(page["text"], source, context=f"{file_name} page {page['page']}")
                if detections:
                    event_log.record("pii_detection", file_name, "detect_unstructured", source_location=str(source.to_dict()), count=len(detections))
                for detection in detections:
                    payload = detection.to_dict()
                    findings.append(payload)
                    latency_records.append(detection.latency_record())

        column_risks = classify_columns(findings)
        heatmap = generate_heatmap(column_risks, findings)
        pii_index = build_pii_index(findings, source_metadata={"source_type": parsed.file_type})
        pii_index_store.replace(pii_index)
        heatmap["source_vs_pii"] = generate_exposure_heatmap(pii_index)
        compliance_status = evaluate_dpdp_compliance(pii_index)
        base_raid = build_raid(findings, column_risks, profiling)
        intelligence_raid = generate_raid(
            findings=findings,
            pii_index=pii_index,
            compliance=compliance_status,
            profiling=profiling,
        )
        raid = _merge_raid(base_raid, intelligence_raid)
        report = build_report(
            file_name=file_name,
            file_type=parsed.file_type,
            profiling=profiling,
            findings=findings,
            column_risks=column_risks,
            heatmap=heatmap,
            raid=raid,
            latency_records=latency_records,
            pii_index=pii_index,
            compliance_status=compliance_status,
        )
        event_log.record("scan_execution", file_name, "scan_completed", findings=len(findings), status="OK")
        return report_store.save(report)


def _merge_raid(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = {**base}
    for key in ("risks", "issues", "assumptions", "dependencies", "recommendations"):
        merged[key] = _dedupe(base.get(key, []) + extra.get(key, []))
    merged["summary"] = extra.get("summary", {})
    return merged


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in items:
        key = tuple(sorted((str(k), str(v)) for k, v in item.items()))
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output


def _row_metadata(row: dict[str, Any]) -> dict[str, Any]:
    row_data = {
        str(key): None if pd.isna(value) else str(value)
        for key, value in row.items()
    }
    return {
        "row_data": row_data,
        "search_terms": _search_terms(row_data.values()),
    }


def _search_terms(values) -> list[str]:
    import re

    seen = set()
    output = []
    for value in values:
        for token in re.findall(r"[A-Za-z0-9@._+-]+", str(value or "").lower()):
            if token and token not in seen:
                seen.add(token)
                output.append(token)
    return output
