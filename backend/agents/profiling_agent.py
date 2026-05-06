import logging
import pandas as pd
from sqlalchemy import text

from backend.services.profiling_engine import profile_dataframe
from backend.services.quality import compute_quality_score
from backend.services.scan_evidence import build_dq_report
from backend.utils.db import get_engine

logger = logging.getLogger(__name__)


def validate_rules(df):
    issues = []

    for column in df.columns:
        lowered = column.lower()
        series = df[column]

        if lowered.endswith("_amount") or lowered in {"amount", "price", "quantity"}:
            numeric = pd.to_numeric(series, errors="coerce")
            if (numeric < 0).any():
                issues.append(f"{column} contains negative values")

        if "email" in lowered:
            invalid_email = series.dropna().astype(str).str.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$") == False
            if invalid_email.any():
                issues.append(f"{column} contains invalid email formats")

    return issues


def _sample_records(df):
    records = []
    for row in df.head(500).to_dict(orient="records"):
        records.append({
            key: None if pd.isna(value) else str(value)
            for key, value in row.items()
        })
    return records


def profiling_agent(state):
    logger.info("Profiling Agent")

    engine = get_engine()
    profiling = {}

    for table in list(state["schema"].keys()):
        quoted_table = ".".join(
            engine.dialect.identifier_preparer.quote(part)
            for part in table.split(".")
        )
        df = pd.read_sql(text(f"SELECT * FROM {quoted_table} LIMIT 500"), engine)

        issues = validate_rules(df)
        null_percentages = df.isnull().mean().to_dict()
        high_null_columns = [
            column for column, pct in null_percentages.items()
            if pct >= 0.2
        ]
        sample_values = {
            column: (
                df[column]
                .dropna()
                .astype(str)
                .drop_duplicates()
                .head(50)
                .tolist()
            )
            for column in df.columns
        }
        sample_sufficiency = {
            "status": "SUFFICIENT" if len(df) >= 30 else "INSUFFICIENT",
            "threshold": 30,
            "message": None if len(df) >= 30 else "Insufficient data for reliable profiling"
        }
        column_profiles = profile_dataframe(df)

        profiling[table] = {
            "row_count": len(df),
            "sample_size": len(df),
            "sample_sufficiency": sample_sufficiency,
            "column_count": len(df.columns),
            "null_count": int(df.isnull().sum().sum()),
            "null_count_by_column": df.isnull().sum().astype(int).to_dict(),
            "null_percentage": null_percentages,
            "duplicate_count": int(df.duplicated().sum()),
            "duplicate_ratio": round(float(df.duplicated().mean()), 4) if len(df) else 0,
            "unique_counts": df.nunique().to_dict(),
            "data_types": df.dtypes.astype(str).to_dict(),
            "numeric_stats": df.describe().to_dict() if not df.empty else {},
            "column_profiles": column_profiles,
            "high_null_columns": high_null_columns,
            "sample_records": _sample_records(df),
            "sample_values": sample_values,
            "issues": issues
        }

    quality_score = compute_quality_score(profiling)
    dq_report = build_dq_report(profiling, quality_score)

    return {
        "profiling": profiling,
        "profiling_insights": dq_report["summary"],
        "dq_report": dq_report
    }
