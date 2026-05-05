from __future__ import annotations

import asyncio

from app.core.scanner import ScanService
from app.core.inventory_intelligence import build_inventory_intelligence_report
from app.detectors.engine import DetectionEngine
from app.pii_engine.index import build_pii_index
from app.risk.engine import classify_columns, generate_heatmap
from app.search_engine.service import FederatedSearchService


def test_hybrid_aadhaar_and_pan_detection():
    engine = DetectionEngine()
    source = __import__("app.core.models", fromlist=["SourceLocation"]).SourceLocation(file="x.csv", column="id", row=0)
    findings = engine.detect("Aadhaar 2345 6789 O123 and PAN ABCDE1234F", source, context="aadhaar pan")
    types = {item.type for item in findings}
    assert "aadhaar" in types
    assert "pan" in types
    assert any(item.method == "fuzzy" for item in findings if item.type == "aadhaar")


def test_scan_service_csv_report_shape():
    csv_bytes = b"name,id_number,email,ifsc\nRavi,234567890123,ravi@example.com,HDFC0001234\n"
    report = asyncio.run(ScanService().scan_bytes("sample.csv", csv_bytes))
    assert report["summary"]["findings"] >= 2
    assert report["risk_heatmap"]["high"] >= 1
    assert report["raid"]["risks"]
    assert report["pii_index"]
    assert "value" not in report["pii_index"][0]
    assert report["compliance_status"]
    assert "source_vs_pii" in report["risk_heatmap"]
    assert "IFSC" in report["data_intelligence"]["what"]


def test_heatmap_contract():
    findings = [{"type": "aadhaar", "source": {"file": "a.csv", "column": "id"}}]
    risks = classify_columns(findings)
    heatmap = generate_heatmap(risks, findings)
    assert heatmap["high"] == 1
    assert heatmap["table_level"]["high"] == 1


def test_ifsc_detection_and_hashed_index_search():
    engine = DetectionEngine()
    source = __import__("app.core.models", fromlist=["SourceLocation"]).SourceLocation(file="bank.csv", column="ifsc", row=0)
    findings = [item.to_dict() for item in engine.detect("IFSC HDFC0001234", source, context="ifsc")]
    assert any(item["type"] == "ifsc" for item in findings)

    index = build_pii_index(findings)
    assert index[0]["value_hash"]
    assert "HDFC0001234" not in str(index)

    result = FederatedSearchService().search("IFSC", index)
    assert result["total_matches"] == 1
    assert result["groups"][0]["records"][0]["pii_type"] == "ifsc"


def test_inventory_report_builds_without_upload_or_source_choice():
    payload = {
        "overview": {"run_id": "run-1"},
        "source_inventory": {
            "source_type": "postgresql",
            "tables": [
                {
                    "qualified_name": "public.customers",
                    "dataset_owner": "Data Office",
                    "data_steward": "Security",
                    "ownership_status": "resolved",
                }
            ],
        },
        "profiling": {"public.customers": {"sample_size": 10}},
        "column_intelligence": {
            "tables": {
                "public.customers": [
                    {
                        "column": "aadhaar_number",
                        "pii_detected": True,
                        "pii_type": "AADHAAR",
                        "masking_status": "NOT_MASKED",
                        "confidence_score": 0.9,
                        "classification": "Sensitive",
                        "risk": "HIGH",
                    }
                ]
            }
        },
    }
    report = build_inventory_intelligence_report(payload)
    assert report["summary"]["status"] == "hydrated_from_scan_outputs"
    assert report["pii_index"][0]["source_type"] == "postgresql"
    assert report["compliance_status"][0]["compliance_status"] == "VIOLATION"
    assert report["data_intelligence"]["what"] == ["AADHAAR"]
    assert report["pii_findings"] == []


def test_search_filters_free_text_terms_from_hydrated_report_samples():
    payload = {
        "overview": {"run_id": "run-2"},
        "source_inventory": {
            "source_type": "postgresql",
            "tables": [{"qualified_name": "public.customers", "source_type": "postgresql"}],
        },
        "profiling": {
            "public.customers": {
                "column_profiles": {
                    "full_name": {
                        "value_distribution": [
                            {"value": "Asha Sharma", "count": 1},
                            {"value": "Priya Nair", "count": 1},
                        ]
                    },
                    "email": {
                        "value_distribution": [
                            {"value": "asha.sharma@example.com", "count": 1},
                        ]
                    },
                }
            }
        },
        "column_intelligence": {
            "tables": {
                "public.customers": [
                    {
                        "column": "full_name",
                        "pii_detected": True,
                        "pii_type": "NAME",
                        "masking_status": "NOT_MASKED",
                        "confidence_score": 1.0,
                    },
                    {
                        "column": "email",
                        "pii_detected": True,
                        "pii_type": "EMAIL",
                        "masking_status": "NOT_MASKED",
                        "confidence_score": 0.9,
                    },
                ]
            }
        },
    }
    report = build_inventory_intelligence_report(payload)
    result = FederatedSearchService().search("priya", report["pii_index"])
    assert result["total_matches"] == 1
    assert result["groups"][0]["records"][0]["pii_type"] == "name"

    missing = FederatedSearchService().search("meera", report["pii_index"])
    assert missing["total_matches"] == 0


def test_search_matches_name_plus_identifier_on_same_hydrated_row():
    payload = {
        "overview": {"run_id": "run-3"},
        "source_inventory": {
            "source_type": "postgresql",
            "tables": [{
                "qualified_name": "kyc.customers",
                "source_type": "postgresql",
                "primary_key": ["id"],
            }],
        },
        "profiling": {
            "kyc.customers": {
                "sample_records": [
                    {
                        "id": "1",
                        "name": "Jane Doe",
                        "aadhaar": "444455556666",
                        "pan": "ABCDE1234F",
                        "ifsc_code": "HDFC0001234",
                    },
                    {
                        "id": "2",
                        "name": "John Doe",
                        "aadhaar": "555566667777",
                        "pan": "PQRSX9876L",
                        "ifsc_code": "ICIC0005678",
                    },
                ],
            }
        },
        "column_intelligence": {
            "tables": {
                "kyc.customers": [
                    {
                        "column": "name",
                        "pii_detected": True,
                        "pii_type": "NAME",
                        "masking_status": "NOT_MASKED",
                        "confidence_score": 1.0,
                    },
                    {
                        "column": "aadhaar",
                        "pii_detected": True,
                        "pii_type": "AADHAAR",
                        "masking_status": "NOT_MASKED",
                        "confidence_score": 0.9,
                    },
                    {
                        "column": "pan",
                        "pii_detected": True,
                        "pii_type": "PAN",
                        "masking_status": "NOT_MASKED",
                        "confidence_score": 0.9,
                    },
                    {
                        "column": "ifsc_code",
                        "pii_detected": True,
                        "pii_type": "IFSC",
                        "masking_status": "NOT_MASKED",
                        "confidence_score": 0.9,
                    },
                ]
            }
        },
    }
    report = build_inventory_intelligence_report(payload)
    result = FederatedSearchService().search("Jane+444455556666", report["pii_index"])
    assert result["total_matches"] == 1
    record = result["groups"][0]["records"][0]
    assert record["pii_type"] == "aadhaar"
    assert record["metadata"]["row_data"]["name"] == "Jane Doe"
    assert record["metadata"]["row_data"]["pan"] == "ABCDE1234F"

    wrong_person = FederatedSearchService().search("John+444455556666", report["pii_index"])
    assert wrong_person["total_matches"] == 0
