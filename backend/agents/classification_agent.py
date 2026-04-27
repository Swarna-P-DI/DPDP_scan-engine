import logging

from backend.services.column_intelligence import build_column_intelligence

logger = logging.getLogger(__name__)


def classification_agent(state):
    logger.info("PII Detection and Classification Agent")
    return {
        "column_intelligence": build_column_intelligence(
            state["source_inventory"],
            state["profiling"]
        )
    }
