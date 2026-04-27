import math
import re


HASH_PATTERNS = [
    re.compile(r"^[a-fA-F0-9]{32}$"),
    re.compile(r"^[a-fA-F0-9]{40}$"),
    re.compile(r"^[a-fA-F0-9]{64}$"),
    re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
]


def _entropy(value):
    if not value:
        return 0
    probabilities = [value.count(char) / len(value) for char in set(value)]
    return -sum(probability * math.log2(probability) for probability in probabilities)


def is_hash_or_token(value):
    value = str(value).strip()
    if any(pattern.match(value) for pattern in HASH_PATTERNS):
        return True
    if len(value) >= 24 and re.match(r"^[A-Za-z0-9+/=_-]+$", value) and _entropy(value) >= 3.5:
        return True
    return False


def value_masking_status(value):
    value = str(value).strip()
    if not value:
        return "UNKNOWN"

    if is_hash_or_token(value):
        return "MASKED"

    if re.fullmatch(r"[*xX#]{3,}", value):
        return "MASKED"

    if any(mask in value for mask in ("*", "x", "X", "#")):
        visible_chars = len(re.sub(r"[*xX#\s@._+-]", "", value))
        masked_chars = len(re.findall(r"[*xX#]", value))
        if masked_chars >= visible_chars:
            return "PARTIALLY_MASKED"

    return "NOT_MASKED"


def column_masking_status(values):
    usable_values = [str(value).strip() for value in values if value is not None and str(value).strip()]
    if not usable_values:
        return "UNKNOWN"

    statuses = [value_masking_status(value) for value in usable_values]
    masked = statuses.count("MASKED")
    partially_masked = statuses.count("PARTIALLY_MASKED")
    not_masked = statuses.count("NOT_MASKED")
    total = len(statuses)

    if masked / total >= 0.9:
        return "MASKED"
    if not_masked / total >= 0.5:
        return "NOT_MASKED"
    if (masked + partially_masked) / total >= 0.5:
        return "PARTIALLY_MASKED"
    return "NOT_MASKED"
