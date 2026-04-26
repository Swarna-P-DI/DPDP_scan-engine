def _normalized_text(value):
    return str(value or "").strip().lower()


def deduplicate_recommendations(items):
    deduped = []
    seen = set()

    for item in items or []:
        if not isinstance(item, dict):
            continue
        key = (
            _normalized_text(item.get("action")),
            _normalized_text(item.get("owner")),
            _normalized_text(item.get("priority"))
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped


def deduplicate_issues(items):
    deduped = []
    seen = set()

    for item in items or []:
        if not isinstance(item, dict):
            continue
        key = (
            _normalized_text(item.get("description") or item.get("issue")),
            _normalized_text(item.get("table")),
            _normalized_text(item.get("column"))
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped


def deduplicate_strings(items):
    deduped = []
    seen = set()

    for item in items or []:
        key = _normalized_text(item)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped


def clean_findings(findings):
    cleaned = dict(findings or {})
    cleaned["gaps"] = deduplicate_issues(cleaned.get("gaps", []))
    cleaned["recommendations"] = deduplicate_recommendations(cleaned.get("recommendations", []))
    cleaned["data_issues"] = deduplicate_strings(cleaned.get("data_issues", []))
    cleaned["impact"] = deduplicate_strings(cleaned.get("impact", []))
    return cleaned


def clean_raid(raid):
    cleaned = dict(raid or {})
    cleaned["risks"] = deduplicate_issues(cleaned.get("risks", []))
    cleaned["issues"] = deduplicate_issues(cleaned.get("issues", []))
    cleaned["assumptions"] = deduplicate_issues(cleaned.get("assumptions", []))
    cleaned["dependencies"] = deduplicate_issues(cleaned.get("dependencies", []))
    cleaned["recommendations"] = deduplicate_recommendations(cleaned.get("recommendations", []))
    return cleaned
