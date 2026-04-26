import json
import os
from pathlib import Path
from typing import Any, Dict, List


DOCUMENT_INSIGHTS_DIR = "storage/document_insights"
TEMPLATES_DIR = "storage/templates"
ASSEMBLER_DIR = "storage/assembler"


def _load_json_files(directory: str) -> List[Dict[str, Any]]:
    path = Path(directory)
    if not path.exists():
        return []

    payloads: List[Dict[str, Any]] = []
    for file_path in sorted(path.glob("*.json")):
        try:
            with open(file_path, encoding="utf-8") as handle:
                data = json.load(handle)
            payloads.append({
                "file_name": file_path.name,
                "payload": data,
            })
        except Exception as exc:
            payloads.append({
                "file_name": file_path.name,
                "payload": {},
                "error": str(exc),
            })
    return payloads


def adapt_source_inventory(source_inventory: Dict[str, Any]) -> Dict[str, Any]:
    tables = []
    for table in source_inventory.get("tables", []):
        tables.append({
            "table": table.get("qualified_name"),
            "dataset_owner": table.get("dataset_owner") or table.get("owner"),
            "data_steward": table.get("data_steward"),
            "columns": [
                {
                    "name": column.get("name"),
                    "data_type": str(column.get("type")),
                    "nullable": bool(column.get("nullable", True)),
                    "primary_key": bool(column.get("primary_key")),
                }
                for column in table.get("columns", [])
            ],
        })
    return {
        "database": source_inventory.get("database"),
        "source_type": source_inventory.get("source_type"),
        "tables": tables,
    }


def adapt_document_insights(directory: str | None = None) -> List[Dict[str, Any]]:
    items = _load_json_files(directory or os.environ.get("DOCUMENT_INSIGHTS_DIR", DOCUMENT_INSIGHTS_DIR))
    normalized = []
    for item in items:
        payload = item.get("payload") or {}
        doc_id = payload.get("doc_id") or Path(item["file_name"]).stem
        rules = payload.get("rules") or payload.get("entities") or payload.get("insights") or []
        normalized.append({
            "doc_id": doc_id,
            "document_type": payload.get("document_type") or payload.get("type") or "document_insight",
            "rules": rules if isinstance(rules, list) else [],
            "source_file": item["file_name"],
            "error": item.get("error"),
        })
    return normalized


def adapt_templates(directory: str | None = None) -> List[Dict[str, Any]]:
    items = _load_json_files(directory or os.environ.get("TEMPLATES_DIR", TEMPLATES_DIR))
    normalized = []
    for item in items:
        payload = item.get("payload") or {}
        template_id = payload.get("template_id") or Path(item["file_name"]).stem
        expected_schema = payload.get("expected_schema") or payload.get("schema") or payload.get("fields") or []
        normalized.append({
            "template_id": template_id,
            "expected_schema": expected_schema if isinstance(expected_schema, list) else [],
            "source_file": item["file_name"],
            "error": item.get("error"),
        })
    return normalized


def adapt_assembler_relationships(directory: str | None = None) -> List[Dict[str, Any]]:
    items = _load_json_files(directory or os.environ.get("ASSEMBLER_DIR", ASSEMBLER_DIR))
    relationships = []
    for item in items:
        payload = item.get("payload") or {}
        for relationship in payload.get("relationships", []) or []:
            if not isinstance(relationship, dict):
                continue
            relationships.append({
                "doc_id": payload.get("doc_id") or Path(item["file_name"]).stem,
                "from_table": relationship.get("from_table") or relationship.get("source"),
                "to_table": relationship.get("to_table") or relationship.get("target"),
                "field": relationship.get("field"),
                "relationship_type": relationship.get("relationship_type") or relationship.get("type") or "expected",
                "source_file": item["file_name"],
            })
    return relationships


def normalize_document_context(source_inventory: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "structured": adapt_source_inventory(source_inventory),
        "document_insights": adapt_document_insights(),
        "expected_schema": adapt_templates(),
        "relationships": adapt_assembler_relationships(),
    }
