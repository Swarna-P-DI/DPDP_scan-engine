import logging

from backend.services.document_adapters import normalize_document_context
from backend.services.document_validation import validate_document_alignment

logger = logging.getLogger(__name__)


def document_insights_agent(state):
    logger.info("Document Insights Agent")
    document_context = normalize_document_context(state.get("source_inventory") or {})
    document_alignment, document_violations = validate_document_alignment(
        state.get("source_inventory") or {},
        state.get("profiling") or {},
        state.get("column_intelligence") or {},
        document_context,
    )
    return {
        "document_context": document_context,
        "document_alignment": document_alignment,
        "document_violations": document_violations,
    }
