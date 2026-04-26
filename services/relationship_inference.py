def _normalize_type(data_type):
    text = str(data_type or "").lower()
    if any(token in text for token in ("int", "serial", "bigint", "smallint")):
        return "integer"
    if any(token in text for token in ("numeric", "decimal", "float", "double", "real")):
        return "numeric"
    if any(token in text for token in ("date", "time")):
        return "datetime"
    if any(token in text for token in ("char", "text", "uuid", "json")):
        return "string"
    return text or "unknown"


def _overlap_ratio(left_values, right_values):
    left = {str(value).strip().lower() for value in left_values if str(value).strip()}
    right = {str(value).strip().lower() for value in right_values if str(value).strip()}
    if not left or not right:
        return 0.0
    intersection = len(left & right)
    baseline = min(len(left), len(right))
    return intersection / baseline if baseline else 0.0


def infer_relationships(source_inventory, profiling):
    tables = source_inventory.get("tables", [])
    table_columns = {}

    for table in tables:
        table_name = table.get("qualified_name")
        table_columns[table_name] = {
            column.get("name"): column
            for column in table.get("columns", [])
        }

    relationships = []
    seen = set()
    table_names = list(table_columns.keys())

    for index, from_table in enumerate(table_names):
        from_profile = profiling.get(from_table, {})
        from_samples = from_profile.get("sample_values", {})
        for to_table in table_names[index + 1:]:
            to_profile = profiling.get(to_table, {})
            to_samples = to_profile.get("sample_values", {})

            shared_columns = set(table_columns[from_table]).intersection(table_columns[to_table])
            for column_name in shared_columns:
                from_column = table_columns[from_table][column_name]
                to_column = table_columns[to_table][column_name]
                type_match = _normalize_type(from_column.get("type")) == _normalize_type(to_column.get("type"))
                overlap = _overlap_ratio(
                    from_samples.get(column_name, []),
                    to_samples.get(column_name, [])
                )

                signals = ["name_match"]
                score = 0.45
                if type_match:
                    signals.append("type_match")
                    score += 0.2
                if overlap >= 0.3:
                    signals.append("value_overlap")
                    score += min(0.35, overlap * 0.5)

                if not type_match or overlap < 0.1:
                    continue

                confidence = round(min(0.99, score), 2)
                pair_key = (from_table, column_name, to_table, column_name)
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                relationships.append({
                    "type": "foreign_key_candidate",
                    "from_table": from_table,
                    "from_column": column_name,
                    "to_table": to_table,
                    "to_column": column_name,
                    "confidence": confidence,
                    "method": " + ".join(signals)
                })

    relationships.sort(
        key=lambda item: (
            -item.get("confidence", 0),
            item.get("from_table", ""),
            item.get("from_column", "")
        )
    )
    return relationships
