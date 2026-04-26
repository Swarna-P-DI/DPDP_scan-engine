import json
import re
import asyncio
from pathlib import Path
from typing import Any, Dict, Iterable, List

from services.pii_detector import detect_pii


def chunk_text(text: str, chunk_size: int = 2000, overlap: int = 200) -> List[str]:
    text = str(text or "")
    if not text:
        return []
    chunks = []
    step = max(chunk_size - overlap, 1)
    for start in range(0, len(text), step):
        chunks.append(text[start:start + chunk_size])
    return chunks


def _flatten_json(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_json(child, next_prefix)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _flatten_json(child, f"{prefix}[{index}]")
    else:
        yield prefix, value


def scan_text(text: str, source_name: str = "inline_text") -> Dict[str, Any]:
    chunks = []
    for index, chunk in enumerate(chunk_text(text)):
        tokens = re.split(r"[\s,;|]+", chunk)
        detected_pii = []
        confidence_score = 0.0
        for label in ("content", "email", "phone", "aadhaar", "pan", "account"):
            result = detect_pii(label, tokens)
            if result.get("pii_detected"):
                confidence_score = max(confidence_score, float(result.get("confidence_score", 0)))
                detected_pii.append({
                    "source": source_name,
                    "field": label,
                    "pii_type": result.get("pii_type"),
                    "sensitivity": result.get("sensitivity"),
                    "confidence_score": result.get("confidence_score"),
                    "detection_sources": result.get("detection_sources", []),
                    "evidence": result.get("evidence"),
                })
        chunks.append({
            "chunk_id": f"{Path(source_name).name or 'text'}-{index}",
            "detected_pii": detected_pii,
            "confidence_score": round(confidence_score, 2),
        })
    return {
        "source_type": "unstructured",
        "file_name": source_name,
        "chunks": chunks,
        "findings": [finding for chunk in chunks for finding in chunk["detected_pii"]],
    }


def scan_json(payload: Any, source_name: str = "json_document") -> Dict[str, Any]:
    chunks = []
    parsed = json.loads(payload) if isinstance(payload, str) else payload
    for index, (path, value) in enumerate(_flatten_json(parsed)):
        result = detect_pii(path, [value])
        detected_pii = []
        confidence_score = 0.0
        if result.get("pii_detected"):
            confidence_score = float(result.get("confidence_score", 0))
            detected_pii.append({
                "source": source_name,
                "field": path,
                "pii_type": result.get("pii_type"),
                "sensitivity": result.get("sensitivity"),
                "confidence_score": result.get("confidence_score"),
                "detection_sources": result.get("detection_sources", []),
                "evidence": result.get("evidence"),
            })
        chunks.append({
            "chunk_id": f"{Path(source_name).name or 'json'}-{index}",
            "detected_pii": detected_pii,
            "confidence_score": round(confidence_score, 2),
        })
    return {
        "source_type": "unstructured",
        "file_name": source_name,
        "chunks": chunks,
        "findings": [finding for chunk in chunks for finding in chunk["detected_pii"]],
    }


def extract_text(path: str) -> str:
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    if suffix == ".pdf":
        try:
            import pdfplumber
            with pdfplumber.open(str(file_path)) as pdf:
                return "\n".join(page.extract_text() or "" for page in pdf.pages)
        except Exception:
            try:
                from pypdf import PdfReader
            except Exception:
                from PyPDF2 import PdfReader
            reader = PdfReader(str(file_path))
            return "\n".join(page.extract_text() or "" for page in reader.pages)
    return file_path.read_text(encoding="utf-8", errors="ignore")


def scan_document(path: str) -> Dict[str, Any]:
    file_path = Path(path)
    if file_path.suffix.lower() == ".json":
        return scan_json(json.loads(file_path.read_text(encoding="utf-8")), str(file_path))
    return scan_text(extract_text(str(file_path)), str(file_path))


async def scan_document_async(path: str) -> Dict[str, Any]:
    return await asyncio.to_thread(scan_document, path)
