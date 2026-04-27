import unittest

from backend.services.document_validation import validate_document_alignment


class DocumentValidationTest(unittest.TestCase):
    def test_detects_masking_and_required_field_gaps(self):
        source_inventory = {
            "tables": [
                {
                    "qualified_name": "public.customers",
                    "columns": [
                        {"name": "email", "type": "TEXT", "nullable": True},
                    ],
                }
            ]
        }
        profiling = {
            "public.customers": {
                "column_profiles": {
                    "email": {"null_pct": 0.2},
                }
            }
        }
        column_intelligence = {
            "tables": {
                "public.customers": [
                    {"column": "email", "masking_status": "NOT_MASKED"},
                ]
            }
        }
        document_context = {
            "document_insights": [
                {
                    "doc_id": "PRD-1",
                    "rules": [
                        {"field": "email", "masking": "MASKED", "required": True},
                    ],
                }
            ],
            "expected_schema": [],
            "relationships": [],
        }

        alignment, violations = validate_document_alignment(
            source_inventory,
            profiling,
            column_intelligence,
            document_context,
        )

        self.assertTrue(any(item["status"] == "mismatched" for item in alignment))
        self.assertTrue(any(item["type"] == "compliance_gap" for item in violations))
        self.assertTrue(any(item["type"] == "quality_gap" for item in violations))


if __name__ == "__main__":
    unittest.main()
