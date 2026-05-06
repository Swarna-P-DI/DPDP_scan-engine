from __future__ import annotations

from datetime import datetime, timezone, timedelta

from app.raid_agent.field_id import generate_field_id
from app.raid_agent.pii_detection import PiiDetectionEngine, hash_value, mask_ratio
from app.raid_agent.risk_scoring import risk_decay, score_risk
from app.raid_agent.service import SAMPLE_LIMIT, RaidAgentService, detect_pii_anomalies
from app.raid_agent.validation import is_valid_aadhaar


def test_field_id_generation_normalizes_scan_metadata():
    assert generate_field_id("CRM", "Public", "Customers", "aadhaar_number") == "crm.public.customers.aadhaar_number"


def test_pii_detection_uses_column_context_regex_and_masks():
    engine = PiiDetectionEngine()

    aadhaar = engine.detect_field("aadhaar_no", ["XXXX XXXX 1234"])
    pan = engine.detect_field("pan_id", ["ABCPD1234F"])
    ifsc = engine.detect_field("branch_ifsc", ["HDFC0001234"])

    assert aadhaar[0].pii_type == "AADHAAR"
    assert aadhaar[0].is_masked is True
    assert pan[0].pii_type == "PAN"
    assert pan[0].confidence_score >= 0.97
    assert ifsc[0].pii_type == "IFSC"


def test_mask_ratio_and_context_confidence_adjustments():
    engine = PiiDetectionEngine()

    masked = engine.detect_field("aadhaar_number", ["XXXX-XXXX-1234"], table_name="customer_kyc")
    neutral = engine.detect_field("pan_id", ["ABCPD1234F"], table_name="logs")
    boosted = engine.detect_field("pan_id", ["ABCPD1234F"], table_name="customer_kyc")
    lowered = engine.detect_field("transaction_id", ["ABCPD1234F"], table_name="events")

    assert mask_ratio("*********123") > 0.7
    assert masked[0].is_masked is True
    assert boosted[0].confidence_score > neutral[0].confidence_score
    assert lowered[0].confidence_score < neutral[0].confidence_score


def test_aadhaar_validation_rejects_bad_checksum_and_accepts_valid_value():
    engine = PiiDetectionEngine()

    invalid = engine.detect_field("generic_id", ["2345 6789 0123"])
    valid = engine.detect_field("aadhaar_number", ["9999 9999 0019"])

    assert is_valid_aadhaar("999999990019") is True
    assert invalid == []
    assert valid[0].pii_type == "AADHAAR"
    assert "verhoeff_checksum" in valid[0].evidence


def test_pan_and_ifsc_validation_reject_invalid_structures():
    engine = PiiDetectionEngine()

    invalid_pan = engine.detect_field("tax_ref", ["ABCZE1234F"])
    invalid_ifsc = engine.detect_field("bank_ref", ["HDFC1001234"])

    assert invalid_pan == []
    assert invalid_ifsc == []


def test_masking_and_api_exposure_change_dynamic_score():
    masked = score_risk(pii_type="PAN", sensitivity_score=0.85, is_masked=True, exposure_type="INTERNAL", row_count=100)
    public = score_risk(pii_type="PAN", sensitivity_score=0.85, is_masked=False, exposure_type="PUBLIC", row_count=100)

    assert masked.sensitivity_score < public.sensitivity_score
    assert public.exposure_score == 0.1
    assert public.risk_category == "HIGH"


def test_risk_override_for_aadhaar_public_and_pan_partner():
    aadhaar = score_risk(pii_type="Aadhaar", sensitivity_score=0.9, is_masked=True, exposure_type="PUBLIC")
    pan = score_risk(pii_type="PAN", sensitivity_score=0.85, is_masked=False, exposure_type="PARTNER")

    assert aadhaar.risk_category == "CRITICAL"
    assert pan.risk_category == "HIGH"


def test_volume_based_scoring_adds_high_volume_weight():
    low = score_risk(pii_type="IFSC", sensitivity_score=0.7, is_masked=False, exposure_type="INTERNAL", row_count=100)
    high = score_risk(pii_type="IFSC", sensitivity_score=0.7, is_masked=False, exposure_type="INTERNAL", row_count=150000)

    assert high.volume_score == 0.03
    assert high.sensitivity_score > low.sensitivity_score


def test_raid_agent_metadata_first_output_and_external_api_risk():
    metadata = {
        "source_system": "crm",
        "source_inventory": {
            "tables": [{
                "qualified_name": "public.customers",
                "columns": ["customer_id", "aadhaar_number", "pan_id", "ifsc_code"],
            }]
        },
        "profiling": {"public.customers": {"row_count": 1000}},
    }
    sample_data = {
        "public.customers": [
            {"aadhaar_number": "9999 9999 0019", "pan_id": "ABCPD1234F", "ifsc_code": "HDFC0001234"}
        ]
    }
    api_payloads = [{
        "api_path": "/api/v1/customer",
        "http_method": "POST",
        "service_name": "customer-service",
        "exposure_type": "PUBLIC",
        "request_count": 12000,
        "response_count": 11000,
        "request_window_minutes": 60,
        "last_accessed": datetime.now(timezone.utc).isoformat(),
        "payload": {"aadhaar_number": "XXXX XXXX 0123", "name": "Asha"},
    }]

    result = RaidAgentService().analyze(metadata=metadata, sample_data=sample_data, api_payloads=api_payloads)

    aadhaar = next(item for item in result["detected_pii"] if item["pii_type"] == "Aadhaar")
    inventory = next(item for item in result["inventory_summary"] if item["pii_type"] == "Aadhaar")
    assert aadhaar["field_id"] == "crm.public.customers.aadhaar_number"
    assert aadhaar["risk"] == "CRITICAL"
    assert inventory["schema"] == "public"
    assert inventory["pii_id"] == "PII-000101"
    assert inventory["table"] == "customers"
    assert inventory["column"] == "aadhaar_number"
    assert inventory["risk_score"] >= 90
    assert inventory["match_count"] == 1
    assert inventory["api_exposure_summary"] == "1 PUBLIC"
    assert inventory["api_exposure"][0]["path"] == "/api/v1/customer"
    assert inventory["api_exposure"][0]["method"] == "POST"
    assert inventory["api_exposure"][0]["authenticated"] is True
    assert inventory["protection_status"] in {"Unprotected", "Masked", "Encrypted", "Tokenized", "Masked + Encrypted"}
    assert result["pii_api_mapping"][0]["api_path"] == "/api/v1/customer"
    assert result["pii_api_mapping"][0]["exposure_type"] == "PUBLIC"
    assert result["pii_api_mapping"][0]["request_count"] == 12000
    assert result["pii_api_mapping"][0]["request_rate"] == 200
    assert result["api_exposure_alerts"]
    assert "hashed_value" in result["pii_detection_events"][0]
    assert "detected_value" not in result["pii_detection_events"][0]
    assert all("9999 9999 0019" not in str(event) for event in result["pii_detection_events"])
    assert result["pii_detection_events"][0]["hashed_value"] == hash_value("999999990019")
    assert "Public API exposure" in aadhaar["risk_factors"]
    assert "confidence_factors" in aadhaar
    assert aadhaar["request_rate"] == 200
    assert result["summary"]["inventory_records"] == 3
    assert result["summary"]["detection_events"] == 3


def test_ifsc_internal_only_is_medium_and_anomaly_detection_flags_spike():
    metadata = {
        "source_system": "banking",
        "source_inventory": {
            "tables": [{"qualified_name": "core.branches", "columns": ["ifsc_code"]}]
        },
    }

    result = RaidAgentService().analyze(metadata=metadata)
    assert result["detected_pii"][0]["pii_type"] == "IFSC"
    assert result["detected_pii"][0]["risk"] == "MEDIUM"

    anomalies = detect_pii_anomalies([{"field_id": f"old.{index}"} for index in range(101)], result["pii_field_catalog"] * 160)
    assert anomalies[0]["type"] == "PII_FIELD_SPIKE"


def test_real_anomaly_detection_compares_same_field_density():
    metadata = {
        "source_system": "crm",
        "source_inventory": {
            "tables": [{"qualified_name": "public.customers", "columns": ["pan_id"]}]
        },
        "profiling": {
            "public.customers": {
                "row_count": 1000,
                "column_profiles": {"pan_id": {"distinct_count": 900}},
            }
        },
    }
    previous = [{
        "field_id": "crm.public.customers.pan_id",
        "pii_count": 300,
        "pii_density": 0.3,
    }]

    result = RaidAgentService().analyze(metadata=metadata, historical_catalog=previous)

    assert result["pii_risk_assessment"][0]["anomaly_flag"] is True
    assert result["anomalies"][0]["message"] == "PII spike detected"


def test_anomaly_suppressed_when_previous_count_is_small():
    previous = [{"field_id": "crm.public.customers.pan_id", "pii_count": 100, "pii_density": 0.1}]
    current = [{"field_id": "crm.public.customers.pan_id", "pii_count": 200, "pii_density": 0.2}]

    assert detect_pii_anomalies(previous, current) == []


def test_anomaly_detection_flags_exposure_change_and_new_pii_type():
    previous = [{
        "field_id": "crm.public.customers.pan_id",
        "pii_type": "PAN",
        "exposure_type": "INTERNAL",
        "pii_count": 200,
        "pii_density": 0.2,
    }]
    current = [
        {
            "field_id": "crm.public.customers.pan_id",
            "pii_type": "PAN",
            "exposure_type": "PUBLIC",
            "pii_count": 210,
            "pii_density": 0.21,
        },
        {
            "field_id": "crm.public.customers.aadhaar_number",
            "pii_type": "Aadhaar",
            "exposure_type": "INTERNAL",
        },
    ]

    anomalies = detect_pii_anomalies(previous, current)

    assert {item["type"] for item in anomalies} >= {"EXPOSURE_TYPE_CHANGE", "NEW_PII_TYPE"}


def test_retention_violation_adds_recommendation():
    old_access = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    metadata = {
        "source_system": "crm",
        "source_inventory": {
            "tables": [{
                "qualified_name": "public.customers",
                "columns": [{
                    "name": "pan_id",
                    "retention_period_days": 30,
                    "last_accessed": old_access,
                }],
            }]
        },
    }

    result = RaidAgentService().analyze(metadata=metadata)

    record = result["detected_pii"][0]
    assert record["retention_violation"] is True
    assert "Retention policy violation" in record["recommendations"]


def test_sampling_limit_and_risk_decay_are_reported():
    old_access = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    metadata = {
        "source_system": "crm",
        "source_inventory": {
            "tables": [{"qualified_name": "public.customers", "columns": ["pan_id"]}]
        },
    }
    samples = [{"pan_id": "ABCPD1234F"} for _ in range(SAMPLE_LIMIT + 5)]

    result = RaidAgentService().analyze(
        metadata=metadata,
        sample_data={"public.customers": samples},
        api_payloads=[{
            "api_path": "/partner/kyc",
            "exposure_type": "PARTNER",
            "request_count": 720,
            "request_window_minutes": 60,
            "last_accessed": old_access,
            "payload": {"pan_id": "ABCPD1234F"},
        }],
    )

    assert result["summary"]["sampling_applied"] is True
    assert result["detected_pii"][0]["sampling_applied"] is True
    assert result["detected_pii"][0]["request_rate"] == 12
    assert risk_decay(old_access) == 0.06
