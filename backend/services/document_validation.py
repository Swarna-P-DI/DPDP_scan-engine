from typing import Any, Dict, List, Tuple


def _normalize_field_name(value: str) -> str:
    return str(value or "").strip().lower()


def _structured_columns(source_inventory: Dict[str, Any], profiling: Dict[str, Any], column_intelligence: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    catalog: Dict[str, Dict[str, Any]] = {}
    intelligence_by_table = (column_intelligence or {}).get("tables", {})

    for table in source_inventory.get("tables", []):
        table_name = table.get("qualified_name")
        table_profile = profiling.get(table_name, {})
        column_profiles = table_profile.get("column_profiles", {})
        intelligence_lookup = {
            _normalize_field_name(item.get("column")): item
            for item in intelligence_by_table.get(table_name, [])
        }
        for column in table.get("columns", []):
            column_name = column.get("name")
            key = _normalize_field_name(column_name)
            catalog[f"{table_name}.{key}"] = {
                "table": table_name,
                "field": column_name,
                "nullable": bool(column.get("nullable", True)),
                "data_type": str(column.get("type")),
                "profile": column_profiles.get(column_name, {}),
                "classification": intelligence_lookup.get(key, {}),
            }
            catalog[key] = catalog[f"{table_name}.{key}"]
    return catalog


def _infer_status(expected: Any, actual: Any) -> str:
    if expected == actual:
        return "matched"
    if actual in (None, "", [], {}):
        return "missing"
    return "mismatched"


def validate_document_alignment(
    source_inventory: Dict[str, Any],
    profiling: Dict[str, Any],
    column_intelligence: Dict[str, Any],
    document_context: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    catalog = _structured_columns(source_inventory, profiling, column_intelligence)
    actual_relationships = {
        (
            str(table.get("qualified_name")),
            str((fk.get("referred_schema") or table.get("schema") or "") + "." + str(fk.get("referred_table"))).strip("."),
            _normalize_field_name((fk.get("columns") or [None])[0]),
        )
        for table in source_inventory.get("tables", [])
        for fk in table.get("foreign_keys", []) or []
    }
    alignment: List[Dict[str, Any]] = []
    violations: List[Dict[str, Any]] = []

    for item in document_context.get("document_insights", []):
        doc_id = item.get("doc_id")
        for rule in item.get("rules", []):
            if not isinstance(rule, dict):
                continue
            field_name = rule.get("field") or rule.get("column") or rule.get("name")
            key = _normalize_field_name(field_name)
            actual = catalog.get(key, {})
            expected_masking = rule.get("masking") or rule.get("expected_masking")
            actual_masking = actual.get("classification", {}).get("masking_status")
            if expected_masking:
                status = _infer_status(str(expected_masking).upper(), str(actual_masking or "").upper())
                alignment.append({
                    "doc_id": doc_id,
                    "field": field_name,
                    "expected": expected_masking,
                    "actual": actual_masking or "FIELD_NOT_FOUND",
                    "status": status,
                })
                if status != "matched":
                    violations.append({
                        "doc_id": doc_id,
                        "field": field_name,
                        "type": "compliance_gap",
                        "description": f"{field_name} must be {expected_masking} per {doc_id}, but actual masking is {actual_masking or 'missing'}.",
                        "expected": expected_masking,
                        "actual": actual_masking or "FIELD_NOT_FOUND",
                        "severity": "high" if str(expected_masking).upper() == "MASKED" and str(actual_masking).upper() == "NOT_MASKED" else "medium",
                        "table": actual.get("table"),
                    })

            if rule.get("required") is True:
                nullable = actual.get("nullable")
                status = _infer_status(False, nullable)
                alignment.append({
                    "doc_id": doc_id,
                    "field": field_name,
                    "expected": "required",
                    "actual": "nullable" if nullable else "required",
                    "status": status,
                })
                if status != "matched":
                    violations.append({
                        "doc_id": doc_id,
                        "field": field_name,
                        "type": "quality_gap",
                        "description": f"{field_name} is mandatory in {doc_id}, but source metadata marks it nullable.",
                        "expected": "required",
                        "actual": "nullable" if nullable else "required",
                        "severity": "medium",
                        "table": actual.get("table"),
                    })

            expected_type = rule.get("data_type") or rule.get("expected_type")
            if expected_type:
                actual_type = actual.get("data_type")
                status = _infer_status(str(expected_type).lower(), str(actual_type or "").lower())
                alignment.append({
                    "doc_id": doc_id,
                    "field": field_name,
                    "expected": expected_type,
                    "actual": actual_type or "FIELD_NOT_FOUND",
                    "status": status,
                })
                if status != "matched":
                    violations.append({
                        "doc_id": doc_id,
                        "field": field_name,
                        "type": "schema_gap",
                        "description": f"{field_name} is expected to be {expected_type} in {doc_id}, but actual type is {actual_type or 'missing'}.",
                        "expected": expected_type,
                        "actual": actual_type or "FIELD_NOT_FOUND",
                        "severity": "medium",
                        "table": actual.get("table"),
                    })

    for template in document_context.get("expected_schema", []):
        template_id = template.get("template_id")
        for field in template.get("expected_schema", []):
            if not isinstance(field, dict):
                continue
            field_name = field.get("field") or field.get("name") or field.get("column")
            key = _normalize_field_name(field_name)
            actual = catalog.get(key, {})
            if not actual:
                alignment.append({
                    "doc_id": template_id,
                    "field": field_name,
                    "expected": "present",
                    "actual": "missing",
                    "status": "missing",
                })
                violations.append({
                    "doc_id": template_id,
                    "field": field_name,
                    "type": "schema_gap",
                    "description": f"{field_name} is required by template {template_id} but was not found in the scanned source inventory.",
                    "expected": "present",
                    "actual": "missing",
                    "severity": "high" if field.get("required") else "medium",
                    "table": None,
                })
                continue

            expected_type = field.get("data_type") or field.get("type")
            if expected_type:
                status = _infer_status(str(expected_type).lower(), str(actual.get("data_type") or "").lower())
                alignment.append({
                    "doc_id": template_id,
                    "field": field_name,
                    "expected": expected_type,
                    "actual": actual.get("data_type"),
                    "status": status,
                })
                if status != "matched":
                    violations.append({
                        "doc_id": template_id,
                        "field": field_name,
                        "type": "schema_gap",
                        "description": f"{field_name} is typed as {expected_type} in template {template_id}, but actual type is {actual.get('data_type')}.",
                        "expected": expected_type,
                        "actual": actual.get("data_type"),
                        "severity": "medium",
                        "table": actual.get("table"),
                    })

            if field.get("required") is True:
                null_pct = float((actual.get("profile") or {}).get("null_pct", 0))
                status = "matched" if null_pct == 0 else "mismatched"
                alignment.append({
                    "doc_id": template_id,
                    "field": field_name,
                    "expected": "no_nulls",
                    "actual": f"{round(null_pct * 100, 2)}% nulls",
                    "status": status,
                })
                if status != "matched":
                    violations.append({
                        "doc_id": template_id,
                        "field": field_name,
                        "type": "quality_gap",
                        "description": f"{field_name} is mandatory in template {template_id}, but sampled data shows {round(null_pct * 100, 2)}% nulls.",
                        "expected": "no_nulls",
                        "actual": f"{round(null_pct * 100, 2)}% nulls",
                        "severity": "high" if null_pct >= 0.2 else "medium",
                        "table": actual.get("table"),
                    })

    for relationship in document_context.get("relationships", []):
        expected_key = (
            str(relationship.get("from_table") or ""),
            str(relationship.get("to_table") or ""),
            _normalize_field_name(relationship.get("field")),
        )
        status = "matched" if expected_key in actual_relationships else "missing"
        alignment.append({
            "doc_id": relationship.get("doc_id"),
            "field": relationship.get("field"),
            "expected": f"{relationship.get('from_table')} -> {relationship.get('to_table')}",
            "actual": "present" if status == "matched" else "missing",
            "status": status,
        })
        if status != "matched":
            violations.append({
                "doc_id": relationship.get("doc_id"),
                "field": relationship.get("field"),
                "type": "schema_gap",
                "description": (
                    f"Assembler expects relationship {relationship.get('from_table')} -> "
                    f"{relationship.get('to_table')} on {relationship.get('field')}, but it was not found in source metadata."
                ),
                "expected": f"{relationship.get('from_table')} -> {relationship.get('to_table')}",
                "actual": "missing",
                "severity": "medium",
                "table": relationship.get("from_table"),
            })

    return alignment, violations
