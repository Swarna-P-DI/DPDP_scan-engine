import tempfile
import unittest
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go

from backend.services.clustered_heatmap import (
    build_plotly_heatmap,
    metadata_from_pii_findings,
    pii_source_matrix,
    plot_clustered_heatmap,
    prepare_numeric_matrix,
)


class ClusteredHeatmapTest(unittest.TestCase):
    def test_prepare_numeric_matrix_fills_missing_values(self):
        matrix = pd.DataFrame(
            {
                "AADHAAR": [3, None, 1],
                "PAN": [None, 2, 0],
            },
            index=["source_a", "source_b", "source_c"],
        )

        prepared = prepare_numeric_matrix(matrix)

        self.assertEqual(prepared.loc["source_a", "PAN"], 0)
        self.assertEqual(prepared.loc["source_b", "AADHAAR"], 0)

    def test_plot_clustered_heatmap_writes_interactive_html(self):
        matrix = pd.DataFrame(
            {
                "AADHAAR": [3, 2, 1],
                "PAN": [3, 0, 1],
                "IFSC": [0, 2, 1],
            },
            index=["postgres.users", "mongo.profiles", "vault.tokens"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "clustered_heatmap.html"
            plot_clustered_heatmap(matrix, output_path, method="average", metric="euclidean")
            self.assertTrue(output_path.exists())
            self.assertGreater(output_path.stat().st_size, 0)

    def test_build_plotly_heatmap_attaches_cell_metadata(self):
        matrix = pd.DataFrame({"AADHAAR": [3]}, index=["postgres.users"])
        metadata = {
            ("postgres.users", "AADHAAR"): {
                "dataset_name": "customer_warehouse",
                "pii_type": "AADHAAR",
                "risk_score": 3,
                "sample_data": "123456789012",
                "source": "scan",
            }
        }

        figure = build_plotly_heatmap(matrix, metadata=metadata, dataset_name="fallback")

        self.assertIsInstance(figure, go.Figure)
        self.assertEqual(figure.data[0].type, "heatmap")
        self.assertEqual(figure.data[0].colorscale[0][1], "rgb(255,255,204)")
        self.assertEqual(figure.data[0].customdata[0][0][0], "postgres.users")
        self.assertEqual(figure.data[0].customdata[0][0][1], "AADHAAR")
        self.assertEqual(figure.data[0].customdata[0][0][3], "customer_warehouse")
        self.assertEqual(figure.data[0].customdata[0][0][4], "AADHAAR")

    def test_pii_source_matrix_accepts_findings(self):
        matrix = pii_source_matrix([
            {"table": "source_a", "pii_type": "AADHAAR", "risk": "High compliance risk"},
            {"table": "source_a", "pii_type": "PAN", "risk": "Moderate compliance risk"},
            {"table": "source_b", "pii_type": "AADHAAR", "masking": "Protected sensitive data"},
        ])

        self.assertEqual(matrix.loc["source_a", "AADHAAR"], 3.0)
        self.assertEqual(matrix.loc["source_a", "PAN"], 2.0)
        self.assertEqual(matrix.loc["source_b", "AADHAAR"], 1.0)

    def test_metadata_from_pii_findings_masks_samples(self):
        metadata = metadata_from_pii_findings([
            {
                "table": "source_a",
                "column": "aadhaar_number",
                "pii_type": "AADHAAR",
                "risk": "High compliance risk",
                "sample_data": "123456789012",
            }
        ])

        cell = metadata[("source_a", "AADHAAR")]
        self.assertEqual(cell["column_name"], "aadhaar_number")
        self.assertEqual(cell["pii_type"], "AADHAAR")
        self.assertIn("*", cell["sample_data"])


if __name__ == "__main__":
    unittest.main()
