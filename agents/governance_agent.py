import logging

from services.governance_insights import build_ai_insights
from services.relationship_inference import infer_relationships

logger = logging.getLogger(__name__)


def governance_agent(state):
    logger.info("Governance Intelligence Agent")

    relationship_inference = infer_relationships(
        state.get("source_inventory") or {},
        state.get("profiling") or {}
    )
    ai_insights = build_ai_insights(
        state.get("column_intelligence") or {},
        state.get("raid") or {},
        state.get("gap_analysis") or {},
        relationship_inference,
        state.get("profiling") or {}
    )

    return {
        "relationship_inference": relationship_inference,
        "ai_insights": ai_insights
    }
