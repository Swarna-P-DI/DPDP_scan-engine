from __future__ import annotations

from typing import Any

import pandas as pd


def profile_dataframe(df: pd.DataFrame) -> dict[str, Any]:
    row_count = int(len(df))
    profiles: dict[str, Any] = {}
    for column in df.columns:
        series = df[column]
        non_null = series.dropna()
        null_pct = round(float(series.isna().mean() * 100), 4) if row_count else 0.0
        unique_pct = round(float(non_null.nunique(dropna=True) / len(non_null) * 100), 4) if len(non_null) else 0.0
        inferred_type = str(pd.api.types.infer_dtype(non_null, skipna=True)) if len(non_null) else "empty"
        stats: dict[str, Any] = {
            "null_pct": null_pct,
            "unique_pct": unique_pct,
            "inferred_type": inferred_type,
            "non_null_count": int(len(non_null)),
        }
        numeric = pd.to_numeric(series, errors="coerce")
        if numeric.notna().any():
            stats["numeric"] = {
                "min": float(numeric.min()),
                "max": float(numeric.max()),
                "mean": round(float(numeric.mean()), 4),
            }
        else:
            lengths = non_null.astype(str).str.len()
            stats["text"] = {
                "min_length": int(lengths.min()) if len(lengths) else 0,
                "max_length": int(lengths.max()) if len(lengths) else 0,
                "avg_length": round(float(lengths.mean()), 4) if len(lengths) else 0.0,
            }
        profiles[str(column)] = stats
    return {"row_count": row_count, "column_count": int(len(df.columns)), "columns": profiles}
