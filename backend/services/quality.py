def compute_quality_score(profiling: dict):
    scores = []

    for stats in profiling.values():
        row_count = stats.get("row_count", 0)
        column_count = stats.get("column_count", 0)
        null_count = stats.get("null_count", 0)
        duplicate_ratio = stats.get("duplicate_ratio", 0)
        issues = stats.get("issues", [])

        if row_count == 0 or column_count == 0:
            scores.append(0)
            continue

        total_cells = row_count * column_count
        completeness = max(1 - (null_count / total_cells), 0)
        uniqueness = max(1 - duplicate_ratio, 0)
        validity = 1.0 if not issues else 0.7

        score = (
            completeness * 0.45 +
            uniqueness * 0.30 +
            validity * 0.25
        ) * 100

        scores.append(score)

    return round(sum(scores) / len(scores), 2) if scores else 0
