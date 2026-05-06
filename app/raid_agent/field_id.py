from __future__ import annotations

import re


def generate_field_id(source_system: str, schema_name: str, table_name: str, column_name: str) -> str:
    """Create a stable metadata-first field identifier."""
    parts = [source_system, schema_name, table_name, column_name]
    normalized = [_normalize_part(part) for part in parts]
    if any(not part for part in normalized):
        raise ValueError("source_system, schema_name, table_name, and column_name are required")
    return ".".join(normalized)


def split_qualified_table(qualified_name: str, default_schema: str = "public") -> tuple[str, str]:
    text = str(qualified_name or "").strip()
    if "." not in text:
        return _normalize_part(default_schema), _normalize_part(text)
    schema_name, table_name = text.split(".", 1)
    return _normalize_part(schema_name), _normalize_part(table_name)


def _normalize_part(value: object) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9_]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text
