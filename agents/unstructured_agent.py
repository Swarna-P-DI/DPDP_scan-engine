import logging
import os
from pathlib import Path

from services.unstructured_scanner import scan_document

logger = logging.getLogger(__name__)

UNSTRUCTURED_DIR = "storage/unstructured"


def unstructured_agent(state):
    logger.info("Unstructured Scanner Agent")
    results = []
    source_dir = Path(os.environ.get("UNSTRUCTURED_SCAN_DIR", UNSTRUCTURED_DIR))
    if not source_dir.exists():
        return {"unstructured_results": []}

    for file_path in source_dir.rglob("*"):
        if file_path.suffix.lower() not in {".txt", ".log", ".json", ".pdf"}:
            continue
        try:
            results.append(scan_document(str(file_path)))
        except Exception as exc:
            results.append({
                "source_type": "unstructured",
                "file_name": str(file_path),
                "chunks": [],
                "findings": [],
                "error": str(exc),
            })
    return {"unstructured_results": results}
