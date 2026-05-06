from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone, timedelta
import logging
from typing import Any

from app.observability.logger import event_log
from app.raid_agent.api_lineage import api_exposure_alerts, map_api_payloads_to_fields, normalize_exposure_type
from app.raid_agent.classification import classify_pii
from app.raid_agent.field_id import generate_field_id, split_qualified_table
from app.raid_agent.pii_detection import PiiDetectionEngine
from app.raid_agent.recommendations import recommendations_for_field
from app.raid_agent.risk_scoring import score_risk

logger = logging.getLogger(__name__)
SAMPLE_LIMIT = 10_000


class RaidAgentService:
    """Metadata-first RAID agent for PII discovery, API lineage, and DPDP risk output."""

    def __init__(self, detector: PiiDetectionEngine | None = None) -> None:
        self.detector = detector or PiiDetectionEngine()

    def analyze(
        self,
        *,
        metadata: dict[str, Any],
        sample_data: dict[str, Any] | None = None,
        api_payloads: list[dict[str, Any]] | None = None,
        historical_catalog: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        try:
            source_system = _source_system(metadata)
            row_counts = _row_counts(metadata)
            columns = _metadata_columns(metadata)
            catalog = []
            detection_events = []
            sampling_applied = False
            sample_payload = sample_data or metadata
            for column in columns:
                schema_name = column["schema_name"]
                table_name = column["table_name"]
                column_name = column["column_name"]
                field_id = generate_field_id(source_system, schema_name, table_name, column_name)
                raw_samples = _samples_for_field(sample_payload, schema_name, table_name, column_name, field_id)
                samples, field_sampling_applied = _limit_samples(raw_samples)
                sampling_applied = sampling_applied or field_sampling_applied
                detections = self.detector.detect_field(column_name, samples, table_name=table_name)
                if not detections:
                    continue
                detection = detections[0]
                classification = classify_pii(detection.pii_type)
                volume_metrics = _volume_metrics(metadata, samples, schema_name, table_name, column_name)
                catalog_entry = {
                    "field_id": field_id,
                    "source_system": source_system,
                    "schema_name": schema_name,
                    "table_name": table_name,
                    "column_name": column_name,
                    "pii_type": classification.pii_type,
                    "pii_category": classification.pii_category,
                    "sensitivity_level": classification.sensitivity_level,
                    "sensitivity_score": classification.sensitivity_score,
                    "detection_confidence": detection.confidence_score,
                    "is_masked": detection.is_masked or _metadata_masked(column),
                    "mask_ratio": detection.mask_ratio,
                    "is_encrypted": _metadata_flag(column, "is_encrypted", "encrypted", "encryption_enabled"),
                    "is_tokenized": _metadata_flag(column, "is_tokenized", "tokenized", "tokenization_enabled"),
                    "data_owner": column.get("data_owner") or column.get("owner"),
                    "business_unit": column.get("business_unit"),
                    "steward_email": column.get("steward_email") or column.get("data_steward_email"),
                    "retention_period_days": _safe_int(column.get("retention_period_days")),
                    "last_accessed": column.get("last_accessed"),
                    **volume_metrics,
                    "detected_at": _now(),
                    "detection_method": detection.detection_method,
                    "evidence": detection.evidence,
                    "confidence_factors": _confidence_factors(detection.evidence, detection.confidence_score),
                    "sampling_applied": field_sampling_applied,
                }
                catalog.append(catalog_entry)
                detection_events.append({
                    "field_id": field_id,
                    "hashed_value": detection.hashed_value or detection.value_hash,
                    "last4_value": detection.last4_value,
                    "detection_method": detection.detection_method,
                    "confidence_score": detection.confidence_score,
                    "detected_at": catalog_entry["detected_at"],
                })

            api_mappings = map_api_payloads_to_fields(api_payloads or [], catalog)
            exposure_by_field = _exposure_by_field(api_mappings)
            frequency_by_field = _frequency_by_field(api_mappings)
            last_accessed_by_field = _last_accessed_by_field(api_mappings)
            for entry in catalog:
                entry["exposure_type"] = exposure_by_field.get(entry["field_id"], "INTERNAL")
                entry["last_accessed"] = entry.get("last_accessed") or last_accessed_by_field.get(entry["field_id"])
            anomaly_by_field, anomalies = detect_pii_anomalies_by_field(historical_catalog or [], catalog)
            risk_assessments = []
            output = []
            for entry in catalog:
                exposure = entry["exposure_type"]
                api_frequency = frequency_by_field.get(entry["field_id"], {})
                retention_violation = _retention_violation(entry.get("last_accessed"), entry.get("retention_period_days"))
                row_count = entry.get("row_count") or row_counts.get(f"{entry['schema_name']}.{entry['table_name']}")
                risk = score_risk(
                    pii_type=str(entry["pii_type"]),
                    sensitivity_score=float(entry["sensitivity_score"]),
                    is_masked=bool(entry["is_masked"]),
                    exposure_type=exposure,
                    row_count=row_count,
                    distinct_count=entry.get("distinct_count"),
                    is_tokenized=bool(entry["is_tokenized"]),
                    mask_ratio=float(entry.get("mask_ratio") or 0),
                    request_count=api_frequency.get("request_count"),
                    response_count=api_frequency.get("response_count"),
                    request_rate=api_frequency.get("request_rate"),
                    last_accessed=entry.get("last_accessed"),
                )
                entry["retention_violation"] = retention_violation
                entry["anomaly_flag"] = entry["field_id"] in anomaly_by_field
                entry["request_rate"] = api_frequency.get("request_rate", 0.0)
                risk_payload = {
                    "field_id": entry["field_id"],
                    **risk.to_dict(),
                    "exposure_type": exposure,
                    "anomaly_flag": entry["anomaly_flag"],
                    "retention_violation": retention_violation,
                    "request_count": api_frequency.get("request_count", 0),
                    "response_count": api_frequency.get("response_count", 0),
                    "request_rate": api_frequency.get("request_rate", 0.0),
                    "risk_factors": _risk_factors(entry, risk.risk_category, exposure),
                    "confidence_factors": list(entry.get("confidence_factors") or []),
                }
                entry["sensitivity_score"] = risk_payload["sensitivity_score"]
                entry["exposure_type"] = exposure
                risk_payload["recommendations"] = recommendations_for_field(entry, risk_payload)
                risk_assessments.append(risk_payload)
                output.append(_output_record(entry, risk_payload))

            alerts = api_exposure_alerts(api_mappings, catalog)
            inventory_summary = build_inventory_summary(
                catalog=catalog,
                detection_events=detection_events,
                api_mappings=api_mappings,
                risk_assessments=risk_assessments,
                anomalies=anomalies,
            )
            event_log.record("raid_agent", source_system, "analysis_completed", fields=len(catalog), alerts=len(alerts))
            return {
                "inventory_summary": inventory_summary,
                "detected_pii": output,
                "pii_field_catalog": catalog,
                "pii_detection_events": detection_events,
                "detection_events": detection_events,
                "pii_api_mapping": api_mappings,
                "pii_risk_assessment": risk_assessments,
                "api_exposure_alerts": alerts,
                "anomalies": anomalies,
                "summary": {
                    "fields_evaluated": len(columns),
                    "pii_fields": len(inventory_summary),
                    "inventory_records": len(inventory_summary),
                    "detection_events": len(detection_events),
                    "critical_fields": sum(1 for item in inventory_summary if item["risk_category"] == "CRITICAL"),
                    "public_exposures": sum(1 for item in inventory_summary if item["exposure"] == "PUBLIC"),
                    "masked_fields": sum(1 for item in inventory_summary if item["masked"]),
                    "retention_violations": sum(1 for item in inventory_summary if item["retention_violation"]),
                    "anomaly_fields": sum(1 for item in risk_assessments if item["anomaly_flag"]),
                    "metadata_first": True,
                    "sampling_limit": SAMPLE_LIMIT,
                    "sampling_applied": sampling_applied,
                },
            }
        except Exception:
            logger.exception("RAID agent analysis failed")
            event_log.record("raid_agent", "unknown", "analysis_failed", status="ERROR")
            raise


def build_inventory_summary(
    *,
    catalog: list[dict[str, Any]],
    detection_events: list[dict[str, Any]],
    api_mappings: list[dict[str, Any]],
    risk_assessments: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build UI-safe field-level inventory while preserving raw audit events separately."""
    try:
        risk_by_field = {str(item.get("field_id")): item for item in risk_assessments or []}
        events_by_field: dict[str, list[dict[str, Any]]] = {}
        for event in detection_events or []:
            events_by_field.setdefault(str(event.get("field_id")), []).append(event)
        apis_by_field: dict[str, list[dict[str, Any]]] = {}
        for mapping in api_mappings or []:
            apis_by_field.setdefault(str(mapping.get("field_id")), []).append(mapping)
        anomaly_by_field = {str(item.get("field_id")): item for item in anomalies or [] if item.get("field_id")}

        grouped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        for field in catalog or []:
            key = (
                str(field.get("source_system") or "unknown"),
                str(field.get("schema_name") or "public"),
                str(field.get("table_name") or "unknown"),
                str(field.get("column_name") or "unknown"),
                str(field.get("pii_type") or "PII"),
            )
            risk = risk_by_field.get(str(field.get("field_id")), {})
            field_events = events_by_field.get(str(field.get("field_id")), [])
            field_apis = apis_by_field.get(str(field.get("field_id")), [])
            entry = grouped.setdefault(key, _empty_inventory_record(field))
            entry["match_count"] += _match_count(field, field_events)
            entry["sample_rows"].extend(_sample_rows(field_events))
            entry["masked_observations"] += 1 if field.get("is_masked") else 0
            entry["total_observations"] += 1
            entry["latest_detection"] = max(str(entry.get("latest_detection") or ""), str(field.get("detected_at") or "")) or None
            entry["api_exposure"].extend(field_apis)
            entry["api_exposure_summary"] = _api_exposure_summary(entry["api_exposure"])
            entry["request_count"] = sum(int(item.get("request_count") or 0) for item in entry["api_exposure"])
            entry["request_rate"] = round(sum(float(item.get("request_rate") or 0) for item in entry["api_exposure"]), 4)
            entry["exposure"] = _highest_exposure(entry.get("exposure"), field.get("exposure_type"))
            entry["exposure_type"] = entry["exposure"]
            entry["risk_score"] = max(float(entry.get("risk_score") or 0), _risk_score_100(risk))
            entry["risk_category"] = _highest_risk(entry.get("risk_category"), risk.get("risk_category") or field.get("risk_category"))
            entry["highest_risk"] = entry["risk_category"]
            if entry["risk_category"] in {"HIGH", "CRITICAL"} and float(entry.get("risk_score") or 0) <= 0:
                logger.warning("RAID risk score missing for non-low risk field", extra={"field_id": field.get("field_id"), "risk_category": entry["risk_category"]})
                entry["risk_score"] = _risk_floor_100(entry["risk_category"])
            entry["confidence_score"] = max(float(entry.get("confidence_score") or 0), float(field.get("detection_confidence") or 0))
            entry["anomaly_score"] = max(float(entry.get("anomaly_score") or 0), 1.0 if field.get("anomaly_flag") or str(field.get("field_id")) in anomaly_by_field else 0.0)
            entry["anomaly"] = anomaly_by_field.get(str(field.get("field_id")), {}).get("type") or ("Flagged" if entry["anomaly_score"] else "None")
            entry["recommendations"].extend(risk.get("recommendations") or [])
            entry["risk_factors"].extend(risk.get("risk_factors") or [])
            entry["confidence_factors"].extend(risk.get("confidence_factors") or field.get("confidence_factors") or [])

        output = []
        for entry in grouped.values():
            entry["sample_rows"] = _dedupe_text([str(item) for item in entry["sample_rows"]])[:5]
            entry["recommendations"] = _dedupe_text([str(item) for item in entry["recommendations"]])
            entry["risk_factors"] = _dedupe_text([str(item) for item in entry["risk_factors"]])
            entry["confidence_factors"] = _dedupe_text([str(item) for item in entry["confidence_factors"]])
            entry["masked_percentage"] = round((entry.pop("masked_observations") / max(entry.pop("total_observations"), 1)) * 100, 2)
            entry["protection_status"] = _protection_status(entry)
            if not entry.get("api_exposure") and entry.get("request_rate"):
                logger.warning("RAID aggregation retained API traffic without endpoint mappings", extra={"field_id": entry.get("field_id"), "request_rate": entry.get("request_rate")})
            entry["masked"] = bool(entry["is_masked"])
            entry["encrypted"] = bool(entry["is_encrypted"])
            entry["tokenized"] = bool(entry["is_tokenized"])
            entry["owner"] = entry.get("data_owner") or "Not Configured"
            entry["steward"] = entry.get("steward_email") or "Not Configured"
            entry["retention_days"] = entry.get("retention_period_days")
            entry["rows"] = entry.get("row_count")
            entry["column"] = entry.get("column_name")
            entry["schema"] = entry.get("schema_name")
            entry["table"] = entry.get("table_name")
            entry["source"] = f"{entry.get('schema_name')}.{entry.get('table_name')}"
            output.append(entry)
        sorted_output = sorted(output, key=lambda item: (str(item.get("source") or ""), str(item.get("column_name") or ""), str(item.get("pii_type") or "")))
        for index, entry in enumerate(sorted_output, start=101):
            entry["pii_id"] = f"PII-{index:06d}"
            for api in entry.get("api_exposure") or []:
                api["pii_id"] = entry["pii_id"]
                api["field_name"] = entry.get("field_name")
                api["source"] = entry.get("source")
        return sorted(sorted_output, key=lambda item: (_risk_rank(item.get("risk_category")), item.get("source", ""), item.get("column_name", "")), reverse=True)
    except Exception:
        logger.exception("RAID inventory aggregation failed")
        event_log.record("raid_agent", "unknown", "inventory_aggregation_failed", status="ERROR")
        return []


def _empty_inventory_record(field: dict[str, Any]) -> dict[str, Any]:
    return {
        "field_id": field.get("field_id"),
        "source_system": field.get("source_system"),
        "schema_name": field.get("schema_name"),
        "table_name": field.get("table_name"),
        "column_name": field.get("column_name"),
        "field_name": _titleize(field.get("column_name")),
        "pii_type": field.get("pii_type"),
        "pii_category": field.get("pii_category"),
        "compliance_mapping": _compliance_mapping(field.get("pii_type")),
        "sensitivity_level": field.get("sensitivity_level"),
        "row_count": field.get("row_count"),
        "total_rows": field.get("row_count"),
        "distinct_count": field.get("distinct_count"),
        "null_percentage": field.get("null_percentage"),
        "pii_density": field.get("pii_density") or 0,
        "sensitivity_score": _sensitivity_score_100(field.get("pii_type"), field.get("sensitivity_score")),
        "column_sensitivity_score": _sensitivity_score_100(field.get("pii_type"), field.get("sensitivity_score")),
        "sample_patterns": list(field.get("sample_patterns") or field.get("evidence") or []),
        "anomaly_indicators": [],
        "is_masked": bool(field.get("is_masked")),
        "is_encrypted": bool(field.get("is_encrypted")),
        "is_tokenized": bool(field.get("is_tokenized")),
        "data_owner": field.get("data_owner") or "Not Configured",
        "business_unit": field.get("business_unit") or "Not Configured",
        "steward_email": field.get("steward_email") or "Not Configured",
        "retention_period_days": field.get("retention_period_days"),
        "retention_violation": bool(field.get("retention_violation")),
        "exposure": field.get("exposure_type") or "INTERNAL",
        "exposure_type": field.get("exposure_type") or "INTERNAL",
        "request_count": 0,
        "request_rate": 0.0,
        "api_exposure": [],
        "api_exposure_summary": "No API Exposure",
        "match_count": 0,
        "sample_rows": [],
        "latest_detection": field.get("detected_at"),
        "highest_risk": "LOW",
        "risk_category": "LOW",
        "risk_score": 0.0,
        "confidence_score": float(field.get("detection_confidence") or 0),
        "anomaly_score": 0.0,
        "anomaly": "None",
        "recommendations": [],
        "risk_factors": [],
        "confidence_factors": [],
        "masked_observations": 0,
        "total_observations": 0,
    }


def _match_count(field: dict[str, Any], events: list[dict[str, Any]]) -> int:
    return max(len(events), _safe_int(field.get("pii_count")) or 0, _safe_int(field.get("distinct_count")) or 0, 1)


def _sample_rows(events: list[dict[str, Any]]) -> list[str]:
    rows = []
    for event in events or []:
        for key in ("row_number", "row", "sample_row"):
            if event.get(key) is not None:
                rows.append(str(event[key]))
                break
    return rows


def _api_exposure_summary(api_items: list[dict[str, Any]]) -> str:
    if not api_items:
        return "No API Exposure"
    exposures = Counter(normalize_exposure_type(item.get("exposure_type")) for item in api_items)
    return ", ".join(f"{count} {exposure}" for exposure, count in exposures.items())


def _compliance_mapping(pii_type: Any) -> list[str]:
    key = str(pii_type or "").upper()
    if key in {"AADHAAR", "PAN"}:
        return ["DPDP"]
    if key in {"EMAIL", "PHONE", "FULL NAME", "NAME"}:
        return ["DPDP", "GDPR"]
    return ["DPDP"]


def _sensitivity_score_100(pii_type: Any, score: Any) -> int:
    key = str(pii_type or "").upper()
    defaults = {
        "AADHAAR": 95,
        "PAN": 90,
        "EMAIL": 45,
        "PHONE": 50,
        "FULL NAME": 70,
        "NAME": 70,
        "IFSC": 65,
    }
    if score is not None:
        try:
            numeric = float(score)
            if numeric > 0:
                return int(round(numeric * 100 if numeric <= 1 else numeric))
            logger.warning("RAID sensitivity score missing or zero; deriving from PII type", extra={"pii_type": key})
        except (TypeError, ValueError):
            logger.warning("RAID sensitivity score mapping failed; deriving from PII type", extra={"pii_type": key, "score": score})
    return defaults.get(key, 50)


def _highest_exposure(left: Any, right: Any) -> str:
    priority = {"INTERNAL": 0, "PARTNER": 1, "PUBLIC": 2}
    left_key = normalize_exposure_type(left)
    right_key = normalize_exposure_type(right)
    return left_key if priority[left_key] >= priority[right_key] else right_key


def _risk_score_100(risk: dict[str, Any]) -> float:
    value = risk.get("overall_risk_score") or risk.get("risk_score") or 0
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(score * 100, 2) if score <= 1 else round(score, 2)


def _risk_floor_100(risk_category: Any) -> float:
    return {
        "CRITICAL": 90.0,
        "HIGH": 70.0,
        "MEDIUM": 40.0,
        "LOW": 1.0,
    }.get(str(risk_category or "").upper(), 0.0)


def _highest_risk(left: Any, right: Any) -> str:
    risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    left_key = str(left or "LOW").upper()
    right_key = str(right or "LOW").upper()
    return left_key if risk_order.index(left_key if left_key in risk_order else "LOW") >= risk_order.index(right_key if right_key in risk_order else "LOW") else right_key


def _risk_rank(value: Any) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(value or "").upper(), 0)


def _protection_status(entry: dict[str, Any]) -> str:
    if entry.get("is_tokenized"):
        return "Tokenized"
    if entry.get("is_encrypted") and entry.get("is_masked"):
        return "Masked + Encrypted"
    if entry.get("is_encrypted"):
        return "Encrypted"
    if entry.get("is_masked"):
        return "Masked"
    return "Unprotected"


def _titleize(value: Any) -> str:
    return str(value or "Unknown Field").replace("_", " ").replace("-", " ").title()


def detect_pii_anomalies(previous_catalog: list[dict[str, Any]], current_catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _, anomalies = detect_pii_anomalies_by_field(previous_catalog, current_catalog)
    previous_count = len(previous_catalog or [])
    current_count = len(current_catalog or [])
    if previous_count <= 100 or current_count <= previous_count * 1.5:
        return anomalies
    aggregate = {
        "type": "PII_FIELD_SPIKE",
        "severity": "HIGH",
        "message": f"PII field count increased from {previous_count} to {current_count}.",
    }
    return [aggregate, *anomalies]


def detect_pii_anomalies_by_field(
    previous_catalog: list[dict[str, Any]],
    current_catalog: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    previous_by_field = {str(item.get("field_id")): item for item in previous_catalog or []}
    previous_types = {str(item.get("pii_type") or "").upper() for item in previous_catalog or [] if item.get("pii_type")}
    anomaly_by_field: dict[str, dict[str, Any]] = {}
    anomalies: list[dict[str, Any]] = []
    for current in current_catalog or []:
        field_id = str(current.get("field_id"))
        previous = previous_by_field.get(field_id)
        if not previous:
            current_type = str(current.get("pii_type") or "").upper()
            if previous_catalog and current_type and current_type not in previous_types:
                payload = {
                    "type": "NEW_PII_TYPE",
                    "severity": "MEDIUM",
                    "field_id": field_id,
                    "message": f"New PII type detected: {current.get('pii_type')}",
                    "pii_type": current.get("pii_type"),
                }
                anomaly_by_field[field_id] = payload
                anomalies.append(payload)
            continue
        current_type = str(current.get("pii_type") or "").upper()
        previous_type = str(previous.get("pii_type") or "").upper()
        if current_type and previous_type and current_type != previous_type:
            payload = {
                "type": "PII_TYPE_CHANGE",
                "severity": "HIGH",
                "field_id": field_id,
                "message": "PII type changed for existing field",
                "previous_pii_type": previous.get("pii_type"),
                "current_pii_type": current.get("pii_type"),
            }
            anomaly_by_field[field_id] = payload
            anomalies.append(payload)
        previous_exposure = normalize_exposure_type(previous.get("exposure_type"))
        current_exposure = normalize_exposure_type(current.get("exposure_type"))
        if previous_exposure != current_exposure:
            payload = {
                "type": "EXPOSURE_TYPE_CHANGE",
                "severity": "HIGH" if current_exposure == "PUBLIC" else "MEDIUM",
                "field_id": field_id,
                "message": "API exposure type changed",
                "previous_exposure_type": previous_exposure,
                "current_exposure_type": current_exposure,
            }
            anomaly_by_field[field_id] = payload
            anomalies.append(payload)
        previous_count = _metric(previous, "pii_count", "distinct_count", "row_count")
        current_count = _metric(current, "pii_count", "distinct_count", "row_count")
        previous_density = float(previous.get("pii_density") or 0)
        current_density = float(current.get("pii_density") or 0)
        count_spike = previous_count > 100 and current_count > previous_count * 1.5
        density_spike = previous_count > 100 and previous_density > 0 and current_density > previous_density * 1.5
        if count_spike or density_spike:
            payload = {
                "type": "PII_SPIKE",
                "severity": "HIGH",
                "field_id": field_id,
                "message": "PII spike detected",
                "previous_count": previous_count,
                "current_count": current_count,
                "previous_density": previous_density,
                "current_density": current_density,
                "increase_pct": round(((current_count - previous_count) / previous_count) * 100, 2) if previous_count else None,
            }
            anomaly_by_field[field_id] = payload
            anomalies.append(payload)
    return anomaly_by_field, anomalies


def generate_raid(
    *,
    findings: list[dict[str, Any]],
    pii_index: list[dict[str, Any]],
    compliance: list[dict[str, Any]],
    profiling: dict[str, Any],
) -> dict[str, Any]:
    risks = []
    issues = []
    assumptions = [{
        "description": "Access-control and encryption flags default to scan metadata when source connector details are unavailable.",
        "validation_needed": "Confirm source IAM/RBAC and encryption posture from the authoritative connector.",
    }]
    dependencies = [{
        "description": "Remediation depends on masking/tokenization services and source-specific IAM policy updates.",
        "owner": "Data Engineering / Security",
    }]
    recommendations = []

    for entry in pii_index:
        pii_type = str(entry.get("pii_type") or "").upper()
        if pii_type == "AADHAAR" and not entry.get("masked"):
            risks.append({
                "risk": f"Aadhaar stored unmasked in {entry.get('source_id')}",
                "severity": "HIGH",
                "source_id": entry.get("source_id"),
                "location": entry.get("location"),
            })
        if not entry.get("encrypted"):
            issues.append({
                "issue": f"No encryption confirmed for {pii_type} in {entry.get('source_id')}",
                "severity": "MEDIUM",
                "location": entry.get("location"),
            })

    for report in compliance:
        if report.get("compliance_status") == "VIOLATION":
            risks.append({
                "risk": f"DPDP violation indicators found for {report.get('source_id')}",
                "severity": "HIGH",
                "issues": report.get("issues", []),
            })
        elif report.get("compliance_status") == "RISK":
            risks.append({
                "risk": f"DPDP control gaps found for {report.get('source_id')}",
                "severity": "MEDIUM",
                "issues": report.get("issues", []),
            })
        recommendations.extend({
            "recommendation": item,
            "priority": "HIGH" if report.get("compliance_status") == "VIOLATION" else "MEDIUM",
        } for item in report.get("recommendations", []))

    if profiling.get("row_count", 0) == 0 and profiling.get("document_pages", 0) == 0:
        assumptions.append({
            "description": "No row/page volume was available from profiling.",
            "validation_needed": "Run against representative source data before final compliance decisions.",
        })

    dependencies.append({
        "description": "Depends on source inventory connectors for encryption, public exposure, and access-control facts.",
        "owner": "Platform Connectors",
    })

    return {
        "risks": _dedupe_dicts(risks),
        "issues": _dedupe_dicts(issues),
        "assumptions": assumptions,
        "dependencies": dependencies,
        "recommendations": _dedupe_dicts(recommendations),
        "summary": {
            "pii_types": dict(Counter(entry.get("pii_type") for entry in pii_index)),
            "compliance": dict(Counter(item.get("compliance_status") for item in compliance)),
            "findings": len(findings),
        },
    }


def _dedupe_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in items:
        key = tuple(sorted((str(k), str(v)) for k, v in item.items()))
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output


def _source_system(metadata: dict[str, Any]) -> str:
    inventory = metadata.get("source_inventory") or {}
    return str(metadata.get("source_system") or inventory.get("source_system") or inventory.get("source_type") or "unknown")


def _metadata_columns(metadata: dict[str, Any]) -> list[dict[str, str]]:
    columns: list[dict[str, Any]] = []
    for table in (metadata.get("source_inventory") or {}).get("tables") or []:
        schema_name, table_name = split_qualified_table(table.get("qualified_name") or table.get("table_name") or "")
        for column in table.get("columns") or []:
            column_data = dict(column) if isinstance(column, dict) else {}
            column_name = column_data.get("name") or column_data.get("column") or column
            columns.append({
                **{key: value for key, value in table.items() if key in {"data_owner", "business_unit", "steward_email", "owner"}},
                **column_data,
                "schema_name": schema_name,
                "table_name": table_name,
                "column_name": str(column_name),
            })

    for qualified_name, column_items in ((metadata.get("column_intelligence") or {}).get("tables") or {}).items():
        schema_name, table_name = split_qualified_table(qualified_name)
        for column in column_items or []:
            column_name = column.get("column") or column.get("name")
            if column_name:
                columns.append({
                    **column,
                    "schema_name": schema_name,
                    "table_name": table_name,
                    "column_name": str(column_name),
                    "masking_status": str(column.get("masking_status") or ""),
                })
    return _dedupe_columns(columns)


def _dedupe_columns(columns: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    output = []
    for column in columns:
        key = (column["schema_name"], column["table_name"], column["column_name"])
        if key not in seen:
            seen.add(key)
            output.append(column)
    return output


def _samples_for_field(sample_data: dict[str, Any], schema_name: str, table_name: str, column_name: str, field_id: str) -> list[Any]:
    if field_id in sample_data:
        return _as_list(sample_data[field_id])
    table_key = f"{schema_name}.{table_name}"
    table_samples = sample_data.get(table_key) or sample_data.get(table_name)
    if isinstance(table_samples, list):
        return [row.get(column_name) for row in table_samples if isinstance(row, dict) and column_name in row]
    if isinstance(table_samples, dict):
        return _as_list(table_samples.get(column_name))
    return _profiling_samples(sample_data, table_key, column_name)


def _profiling_samples(sample_data: dict[str, Any], table_key: str, column_name: str) -> list[Any]:
    profile = sample_data.get("profiling", {}).get(table_key, {}) if isinstance(sample_data.get("profiling"), dict) else {}
    records = profile.get("sample_records") or []
    return [row.get(column_name) for row in records if isinstance(row, dict) and column_name in row]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _limit_samples(samples: list[Any]) -> tuple[list[Any], bool]:
    if len(samples) > SAMPLE_LIMIT:
        return samples[:SAMPLE_LIMIT], True
    return samples, False


def _metadata_masked(column: dict[str, Any]) -> bool:
    return str(column.get("masking_status") or "").upper() in {"MASKED", "TOKENIZED", "HASHED"}


def _metadata_flag(column: dict[str, Any], *names: str) -> bool:
    for name in names:
        value = column.get(name)
        if isinstance(value, bool):
            return value
        if str(value or "").strip().upper() in {"TRUE", "YES", "Y", "1", "ENABLED"}:
            return True
    return False


def _row_counts(metadata: dict[str, Any]) -> dict[str, int]:
    counts = {}
    profiling = metadata.get("profiling") or {}
    for table_key, profile in profiling.items():
        if isinstance(profile, dict) and profile.get("row_count") is not None:
            counts[str(table_key)] = int(profile["row_count"])
    return counts


def _exposure_by_field(mappings: list[dict[str, Any]]) -> dict[str, str]:
    exposure = {}
    priority = {"INTERNAL": 0, "PARTNER": 1, "PUBLIC": 2}
    for mapping in mappings:
        field_id = str(mapping.get("field_id"))
        mapped_exposure = normalize_exposure_type(mapping.get("exposure_type"))
        if priority[mapped_exposure] > priority.get(exposure.get(field_id, "INTERNAL"), 0):
            exposure[field_id] = mapped_exposure
        else:
            exposure.setdefault(field_id, "INTERNAL")
    return exposure


def _output_record(entry: dict[str, Any], risk: dict[str, Any]) -> dict[str, Any]:
    issues = []
    recommendations = list(risk.get("recommendations") or [str(risk["recommendation"])])
    if entry["sensitivity_level"] == "HIGH" and not entry["is_masked"]:
        issues.append("High sensitivity identifier is not masked.")
    if risk["risk_category"] == "CRITICAL":
        issues.append("Public exposure creates critical DPDP compliance risk.")
    if risk.get("anomaly_flag"):
        issues.append("PII spike detected.")
    if risk.get("retention_violation"):
        issues.append("Retention policy violation.")
    return {
        "field_id": entry["field_id"],
        "source_system": entry.get("source_system"),
        "schema_name": entry.get("schema_name"),
        "table_name": entry.get("table_name"),
        "column_name": entry.get("column_name"),
        "pii_type": entry["pii_type"],
        "pii_category": entry.get("pii_category"),
        "sensitivity": entry["sensitivity_level"],
        "sensitivity_level": entry["sensitivity_level"],
        "sensitivity_score": risk.get("sensitivity_score"),
        "detection_confidence": entry.get("detection_confidence"),
        "risk": risk["risk_category"],
        "risk_category": risk["risk_category"],
        "risk_score": risk.get("overall_risk_score"),
        "risk_factors": list(risk.get("risk_factors") or []),
        "confidence_factors": list(risk.get("confidence_factors") or entry.get("confidence_factors") or []),
        "exposure_type": risk.get("exposure_type"),
        "request_count": risk.get("request_count", 0),
        "response_count": risk.get("response_count", 0),
        "request_rate": risk.get("request_rate", 0.0),
        "is_masked": bool(entry.get("is_masked")),
        "is_encrypted": bool(entry.get("is_encrypted")),
        "is_tokenized": bool(entry.get("is_tokenized")),
        "data_owner": entry.get("data_owner"),
        "business_unit": entry.get("business_unit"),
        "steward_email": entry.get("steward_email"),
        "retention_period_days": entry.get("retention_period_days"),
        "anomaly_flag": bool(risk.get("anomaly_flag")),
        "retention_violation": bool(risk.get("retention_violation")),
        "row_count": entry.get("row_count"),
        "distinct_count": entry.get("distinct_count"),
        "pii_count": entry.get("pii_count"),
        "pii_density": entry.get("pii_density"),
        "sampling_applied": bool(entry.get("sampling_applied")),
        "issues": issues,
        "recommendations": _dedupe_text(recommendations),
    }


def _dedupe_text(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _volume_metrics(
    metadata: dict[str, Any],
    samples: list[Any],
    schema_name: str,
    table_name: str,
    column_name: str,
) -> dict[str, Any]:
    table_key = f"{schema_name}.{table_name}"
    profile = (metadata.get("profiling") or {}).get(table_key) or {}
    row_count = _safe_int(profile.get("row_count"))
    column_profile = ((profile.get("column_profiles") or {}).get(column_name) or (profile.get("columns") or {}).get(column_name) or {})
    distinct_count = _safe_int(column_profile.get("distinct_count") or column_profile.get("unique_count"))
    null_percentage = _safe_float(column_profile.get("null_percentage") or column_profile.get("null_pct"))
    if distinct_count is None and samples:
        distinct_count = len({str(value) for value in samples if value not in (None, "")})
    if row_count is None and samples:
        row_count = len(samples)
    pii_count = distinct_count if distinct_count is not None else (len(samples) if samples else 0)
    density = round((pii_count / row_count), 4) if row_count else 0.0
    return {
        "row_count": row_count,
        "distinct_count": distinct_count,
        "pii_count": pii_count,
        "pii_density": density,
        "null_percentage": null_percentage,
        "sample_patterns": column_profile.get("sample_patterns") or [],
    }


def _safe_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _metric(item: dict[str, Any], *names: str) -> float:
    for name in names:
        value = item.get(name)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
    return 0.0


def _frequency_by_field(mappings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for mapping in mappings:
        field_id = str(mapping.get("field_id"))
        current = output.setdefault(field_id, {"request_count": 0, "response_count": 0, "request_rate": 0.0})
        current["request_count"] += int(mapping.get("request_count") or 0)
        current["response_count"] += int(mapping.get("response_count") or 0)
        current["request_rate"] = round(float(current.get("request_rate") or 0) + float(mapping.get("request_rate") or 0), 4)
    return output


def _last_accessed_by_field(mappings: list[dict[str, Any]]) -> dict[str, str]:
    output: dict[str, str] = {}
    for mapping in mappings:
        field_id = str(mapping.get("field_id"))
        value = str(mapping.get("last_accessed") or "")
        if value and value > output.get(field_id, ""):
            output[field_id] = value
    return output


def _retention_violation(last_accessed: Any, retention_period_days: Any) -> bool:
    days = _safe_int(retention_period_days)
    if not days or not last_accessed:
        return False
    accessed_at = _parse_datetime(last_accessed)
    if not accessed_at:
        return False
    return datetime.now(timezone.utc) - accessed_at > timedelta(days=days)


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _risk_factors(entry: dict[str, Any], risk_category: str, exposure: str) -> list[str]:
    factors = [f"{entry.get('pii_type')} detected"]
    if exposure == "PUBLIC":
        factors.append("Public API exposure")
    elif exposure == "PARTNER":
        factors.append("Partner API exposure")
    if not entry.get("is_masked"):
        factors.append("Unmasked")
    elif float(entry.get("mask_ratio") or 0) > 0:
        factors.append(f"Masked ratio {entry.get('mask_ratio')}")
    if not entry.get("is_encrypted"):
        factors.append("Not encrypted")
    if entry.get("is_tokenized"):
        factors.append("Tokenized")
    if entry.get("row_count") and int(entry.get("row_count") or 0) > 100_000:
        factors.append("High volume")
    if entry.get("request_rate") and float(entry.get("request_rate") or 0) >= 10:
        factors.append("High request rate")
    if entry.get("retention_violation"):
        factors.append("Retention policy violation")
    if entry.get("anomaly_flag"):
        factors.append("PII spike detected")
    if risk_category == "CRITICAL":
        factors.append("Critical risk override")
    return _dedupe_text(factors)


def _confidence_factors(evidence: list[str], confidence_score: float) -> list[str]:
    factors = list(evidence or [])
    if confidence_score >= 0.95:
        factors.append("high_confidence")
    elif confidence_score >= 0.75:
        factors.append("context_supported")
    return _dedupe_text(factors)
