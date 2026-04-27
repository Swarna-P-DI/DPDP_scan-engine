from typing import Any, Dict, List


REQUIRED_FINAL_KEYS = [
    "metadata",
    "profiling",
    "classification",
    "unstructured_results",
    "document_alignment",
    "risks",
    "prioritized_risks",
    "recommendations",
    "tasks",
    "monitoring",
    "summary",
]


def validate_final_output(output: Dict[str, Any]) -> Dict[str, Any]:
    missing: List[str] = [key for key in REQUIRED_FINAL_KEYS if key not in output]
    return {
        "valid": not missing,
        "missing_keys": missing,
        "required_keys": REQUIRED_FINAL_KEYS,
    }
