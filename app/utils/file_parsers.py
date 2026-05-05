from __future__ import annotations

import io
import json
from typing import Any

import pandas as pd

from app.core.models import ParsedInput


SUPPORTED_EXTENSIONS = {".csv", ".json", ".pdf"}


def parse_upload(file_name: str, content: bytes) -> ParsedInput:
    suffix = "." + file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{suffix}'. Supported: CSV, JSON, PDF.")
    if suffix == ".csv":
        df = pd.read_csv(io.BytesIO(content))
        return ParsedInput(file_name=file_name, file_type="csv", dataframe=df, raw_record_count=len(df))
    if suffix == ".json":
        payload = json.loads(content.decode("utf-8"))
        df = _json_to_dataframe(payload)
        return ParsedInput(file_name=file_name, file_type="json", dataframe=df, raw_record_count=len(df))
    pages = _extract_pdf_pages(content)
    return ParsedInput(file_name=file_name, file_type="pdf", text_pages=pages, raw_record_count=len(pages))


def _json_to_dataframe(payload: Any) -> pd.DataFrame:
    if isinstance(payload, list):
        return pd.json_normalize(payload)
    if isinstance(payload, dict):
        records = payload.get("records")
        if isinstance(records, list):
            return pd.json_normalize(records)
        return pd.json_normalize(payload)
    return pd.DataFrame([{"value": payload}])


def _extract_pdf_pages(content: bytes) -> list[dict[str, Any]]:
    try:
        import pdfplumber
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            return [
                {"page": index + 1, "text": page.extract_text() or ""}
                for index, page in enumerate(pdf.pages)
            ]
    except Exception:
        try:
            import fitz
            with fitz.open(stream=content, filetype="pdf") as doc:
                return [
                    {"page": index + 1, "text": page.get_text("text") or ""}
                    for index, page in enumerate(doc)
                ]
        except Exception as exc:
            raise ValueError(f"PDF parsing failed: {exc}") from exc
