import unittest

import pandas as pd

from services.profiling_engine import profile_dataframe


class ProfilingEngineTest(unittest.TestCase):
    def test_profile_dataframe_emits_column_metrics(self):
        df = pd.DataFrame({
            "email": ["a@example.com", "b@example.com", None],
            "amount": [10, 20, 1000],
        })

        profile = profile_dataframe(df)

        self.assertEqual(profile["email"]["null_pct"], 0.3333)
        self.assertEqual(profile["email"]["inferred_type"], "text")
        self.assertTrue(any(item["pattern"] == "email" for item in profile["email"]["patterns"]))
        self.assertGreater(profile["amount"]["unique_ratio"], 0)


if __name__ == "__main__":
    unittest.main()
