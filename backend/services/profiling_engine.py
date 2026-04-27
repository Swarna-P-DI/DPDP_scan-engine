import re
from collections import Counter
from typing import Any, Dict, List

import pandas as pd


PATTERN_RULES = {
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "phone": re.compile(r"^(?:\+?91[-\s]?)?[6-9]\d{9}$"),
    "aadhaar": re.compile(r"^\d{4}[\s-]?\d{4}[\s-]?\d{4}$"),
    "pan": re.compile(r"^[A-Z]{5}\d{4}[A-Z]$"),
    "date_iso": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
    "masked": re.compile(r".*[*xX#]{2,}.*"),
}


def _infer_type(series: pd.Series) -> str:
    values = series.dropna()
    if values.empty:
        return "unknown"
    if pd.api.types.is_bool_dtype(series):
        return "boolean"
    if pd.api.types.is_numeric_dtype(series):
        return "numeric"
    if pd.api.types.is_datetime64_any_dtype(series):
        return "datetime"

    as_text = values.astype(str).str.strip()
    numeric_ratio = pd.to_numeric(as_text, errors="coerce").notna().mean()
    date_like = as_text.str.match(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}$|^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}$").mean()
    date_ratio = pd.to_datetime(as_text, errors="coerce").notna().mean() if date_like >= 0.5 else 0
    if numeric_ratio >= 0.8:
        return "numeric"
    if date_ratio >= 0.8:
        return "datetime"
    return "text"


def _detect_patterns(series: pd.Series) -> List[Dict[str, Any]]:
    values = series.dropna().astype(str).str.strip()
    sample_count = len(values)
    if sample_count == 0:
        return []

    detected = []
    for name, pattern in PATTERN_RULES.items():
        hits = int(values.map(lambda value: bool(pattern.match(value))).sum())
        ratio = hits / sample_count
        if hits and ratio >= 0.2:
            detected.append({
                "pattern": name,
                "hits": hits,
                "sample_count": sample_count,
                "ratio": round(ratio, 4),
            })
    return detected


def _value_distribution(series: pd.Series, limit: int = 10) -> List[Dict[str, Any]]:
    values = series.dropna().astype(str)
    total = len(values)
    if total == 0:
        return []
    counts = Counter(values)
    return [
        {
            "value": value,
            "count": count,
            "ratio": round(count / total, 4),
        }
        for value, count in counts.most_common(limit)
    ]


def _detect_anomalies(series: pd.Series, inferred_type: str) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    values = series.dropna()
    if values.empty:
        return anomalies

    if inferred_type == "numeric":
        numeric = pd.to_numeric(values, errors="coerce").dropna()
        if numeric.empty:
            return anomalies
        q1 = numeric.quantile(0.25)
        q3 = numeric.quantile(0.75)
        iqr = q3 - q1
        if iqr > 0:
            low = q1 - 1.5 * iqr
            high = q3 + 1.5 * iqr
            outliers = numeric[(numeric < low) | (numeric > high)]
            if not outliers.empty:
                anomalies.append({
                    "type": "numeric_outlier",
                    "count": int(len(outliers)),
                    "lower_bound": round(float(low), 4),
                    "upper_bound": round(float(high), 4),
                    "examples": [str(value) for value in outliers.head(5).tolist()],
                })

        if (numeric < 0).any():
            anomalies.append({
                "type": "negative_value",
                "count": int((numeric < 0).sum()),
                "examples": [str(value) for value in numeric[numeric < 0].head(5).tolist()],
            })

    if inferred_type == "text":
        text = values.astype(str).str.strip()
        lengths = text.str.len()
        if not lengths.empty:
            median = lengths.median()
            long_values = text[lengths > max(median * 3, 120)]
            if not long_values.empty:
                anomalies.append({
                    "type": "unusually_long_text",
                    "count": int(len(long_values)),
                    "examples": long_values.head(3).tolist(),
                })

    return anomalies


def profile_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
    column_profiles = {}
    row_count = len(df)

    for column in df.columns:
        series = df[column]
        non_null = series.dropna()
        inferred_type = _infer_type(series)
        null_pct = round(float(series.isna().mean()), 4) if row_count else 0
        unique_ratio = round(float(non_null.nunique() / len(non_null)), 4) if len(non_null) else 0

        column_profiles[column] = {
            "null_pct": null_pct,
            "unique_ratio": unique_ratio,
            "inferred_type": inferred_type,
            "patterns": _detect_patterns(series),
            "value_distribution": _value_distribution(series),
            "anomalies": _detect_anomalies(series, inferred_type),
        }

    return column_profiles
