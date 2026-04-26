import unittest

from services.risk_engine import issues_to_risks


class RiskEngineTest(unittest.TestCase):
    def test_unmasked_pii_issue_becomes_critical_risk(self):
        result = issues_to_risks([
            {
                "type": "quality",
                "description": "public.customers.email contains unmasked EMAIL PII.",
                "severity": "high",
                "owner": "postgres",
            }
        ])

        self.assertEqual(len(result["risks"]), 1)
        risk = result["risks"][0]
        self.assertEqual(risk["severity"], "critical")
        self.assertIn("DPDP", risk["compliance_mapping"])
        self.assertIn("security", risk["impact"])


if __name__ == "__main__":
    unittest.main()
