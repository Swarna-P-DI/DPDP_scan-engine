import logging
import uuid
from typing import Any, Dict, List, Optional, TypedDict

from langgraph.graph import StateGraph

from agents.classification_agent import classification_agent
from agents.data_agent import data_agent
from agents.document_insights_agent import document_insights_agent
from agents.gap_analysis_agent import gap_analysis_agent
from agents.governance_agent import governance_agent
from agents.profiling_agent import profiling_agent
from agents.raid_agent import raid_agent
from agents.risk_agent import risk_agent
from agents.unstructured_agent import unstructured_agent
from services.column_intelligence import build_traceability
from services.data_scoring import compute_data_readiness_score
from services.deduplication import clean_findings, clean_raid, deduplicate_recommendations
from services.diff import compute_diff
from services.dpdp_compliance import build_dpdp_compliance_summary
from services.export import export_json, export_pdf
from services.final_formatter import format_report
from services.ingestion import build_ingestion_metadata
from services.monitoring import record_scan_history, scheduled_scan_descriptor
from services.output_validation import validate_final_output
from services.quality import compute_quality_score
from services.report_generator import build_report
from services.scan_evidence import build_score_explanation, public_profiling
from services.task_store import create_tasks
from services.versioning import get_latest_run, save_run

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class GraphState(TypedDict):
    source_inventory: Dict[str, Any]
    schema: Dict[str, List[str]]
    schema_analysis: Optional[Dict[str, Any]]
    profiling: Dict[str, Any]
    profiling_insights: Optional[str]
    dq_report: Optional[dict]
    column_intelligence: Dict[str, Any]
    gap_analysis: Dict[str, Any]
    risks: List[Dict[str, Any]]
    prioritized_risks: List[Dict[str, Any]]
    tasks: List[Dict[str, Any]]
    unstructured_results: List[Dict[str, Any]]
    document_context: Dict[str, Any]
    document_alignment: List[Dict[str, Any]]
    document_violations: List[Dict[str, Any]]
    raid: Dict[str, Any]
    relationship_inference: List[Dict[str, Any]]
    ai_insights: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    final_output: Dict[str, Any]


DEFAULT_STATE: GraphState = {
    "source_inventory": {},
    "schema": {},
    "schema_analysis": None,
    "profiling": {},
    "profiling_insights": None,
    "dq_report": None,
    "column_intelligence": {},
    "gap_analysis": {},
    "risks": [],
    "prioritized_risks": [],
    "tasks": [],
    "unstructured_results": [],
    "document_context": {},
    "document_alignment": [],
    "document_violations": [],
    "raid": {},
    "relationship_inference": [],
    "ai_insights": [],
    "recommendations": [],
    "final_output": {},
}


def initialize_state(state):
    next_state = dict(DEFAULT_STATE)
    next_state.update(state or {})
    return next_state


def _collect_recommendations(data_findings, raid):
    recommendations = []

    if isinstance(data_findings, dict):
        recommendations.extend(data_findings.get("recommendations", []))

    if isinstance(raid, dict):
        recommendations.extend(raid.get("recommendations", []))

    seen = set()
    deduped = []
    for item in recommendations:
        key = item.get("action") if isinstance(item, dict) else str(item)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def aggregator(state):
    logger.info("Aggregating Results")
    state = initialize_state(state)

    run_id = str(uuid.uuid4())
    quality_score = compute_quality_score(state["profiling"])
    scoring = compute_data_readiness_score(
        quality_score,
        state.get("gap_analysis"),
        state["source_inventory"],
        state.get("column_intelligence") or {},
        state["profiling"]
    )
    cleaned_findings = clean_findings(state.get("gap_analysis") or {})
    cleaned_raid = clean_raid(state.get("raid") or {})
    traceability = build_traceability(state.get("column_intelligence") or {}, run_id)
    public_profile = public_profiling(state["profiling"])
    dpdp_compliance = build_dpdp_compliance_summary(
        state.get("column_intelligence") or {},
        state.get("raid") or {}
    )

    score_explanation = build_score_explanation(
        scoring,
        state.get("dq_report"),
        state.get("gap_analysis"),
        state.get("raid")
    )

    ingestion = build_ingestion_metadata(
        state["source_inventory"],
        state["schema"],
        state["profiling"]
    )

    previous = get_latest_run()
    diff = compute_diff(
        {
            "source_inventory": state["source_inventory"],
            "schema": state["schema"],
            "scores": scoring
        },
        previous
    )

    workflow = [
        "source_inventory",
        "profiling",
        "pii_detection",
        "classification",
        "document_insights",
        "assembler_alignment",
        "data_quality",
        "data_findings",
        "risk_engine",
        "raid",
        "governance",
        "aggregator"
    ]

    issues = (cleaned_findings or {}).get("gaps", [])
    risk_records = state.get("risks") or (cleaned_raid or {}).get("risks", [])
    prioritized_risks = state.get("prioritized_risks") or cleaned_raid.get("prioritized_risks", risk_records)
    tasks = state.get("tasks") or []
    recommendation_records = deduplicate_recommendations(
        state.get("recommendations") or _collect_recommendations(cleaned_findings, cleaned_raid)
    )

    standardized = {
        "metadata": {
            "run_id": run_id,
            "source_inventory": state["source_inventory"],
            "ingestion": ingestion,
            "dataset_owner": "Data Engineering / Data Steward",
            "data_steward": "Data Engineering / Data Steward",
            "monitoring_schedule": scheduled_scan_descriptor(),
        },
        "profiling": public_profile,
        "classification": state.get("column_intelligence"),
        "unstructured_results": state.get("unstructured_results", []),
        "document_context": state.get("document_context", {}),
        "document_alignment": state.get("document_alignment", []),
        "issues": issues,
        "risks": risk_records,
        "prioritized_risks": prioritized_risks,
        "recommendations": recommendation_records,
        "tasks": tasks,
        "monitoring": {},
        "scores": scoring,
        "summary": {
            "tables_scanned": len(state.get("schema", {})),
            "issues": len(issues),
            "risks": len(risk_records),
            "pii_columns": (state.get("column_intelligence") or {}).get("summary", {}).get("pii_columns", 0),
            "document_alignment_gaps": len(state.get("document_violations", [])),
            "final_score": scoring.get("final_score"),
        },
    }

    report_input = {
        "source_inventory": state["source_inventory"],
        "schema_analysis": state.get("schema_analysis"),
        "scores": scoring,
        "profiling": public_profile,
        "dq_report": state.get("dq_report"),
        "column_intelligence": state.get("column_intelligence"),
        "dpdp_compliance": dpdp_compliance,
        "gap_analysis": cleaned_findings,
        "raid": cleaned_raid,
        "relationship_inference": state.get("relationship_inference", []),
        "ai_insights": state.get("ai_insights", []),
        "recommendations": recommendation_records,
        "document_alignment": state.get("document_alignment", []),
        "traceability": traceability,
        "run_id": run_id
    }

    report = build_report(report_input, ingestion, diff, workflow)
    monitoring_snapshot = {
        "source_inventory": state["source_inventory"],
        "schema": state["schema"],
        "column_intelligence": state.get("column_intelligence"),
        "scores": scoring,
        "risks": risk_records,
        "issues_count": len(issues),
        "document_alignment": state.get("document_alignment", []),
    }
    run_id = save_run(monitoring_snapshot, run_id=run_id)
    monitoring = record_scan_history(
        run_id,
        monitoring_snapshot,
        scope=state["source_inventory"].get("database", "default")
    )
    create_tasks(tasks)
    standardized["monitoring"] = monitoring

    try:
        json_path = export_json(run_id, report)
        pdf_path = export_pdf(run_id, report)
    except Exception:
        json_path = None
        pdf_path = None

    formatted_report = format_report({
        "source_inventory": state["source_inventory"],
        "schema": state["schema"],
        "schema_analysis": state.get("schema_analysis"),
        "profiling": public_profile,
        "column_intelligence": state.get("column_intelligence"),
        "dpdp_compliance": dpdp_compliance,
        "dq_report": state.get("dq_report"),
        "gap_analysis": cleaned_findings,
        "raid": cleaned_raid,
        "relationship_inference": state.get("relationship_inference", []),
        "ai_insights": state.get("ai_insights", []),
            "recommendations": recommendation_records,
            "traceability": traceability,
            "scores": scoring
    })

    final_output = {
            "source_inventory": state["source_inventory"],
            "schema": state["schema"],
            "schema_analysis": state.get("schema_analysis"),
            "profiling": public_profile,
            "dq_report": state.get("dq_report"),
            "profiling_insights": state.get("profiling_insights"),
            "column_intelligence": state.get("column_intelligence"),
            "dpdp_compliance": dpdp_compliance,
            "gap_analysis": cleaned_findings,
            "raid": cleaned_raid,
            "relationship_inference": state.get("relationship_inference", []),
            "ai_insights": state.get("ai_insights", []),
            "recommendations": recommendation_records,
            "tasks": tasks,
            "quality_score": quality_score,
            "scores": scoring,
            "score_explanation": score_explanation,
            "formatted_report": formatted_report,
            "report": report,
            "run_id": run_id,
            "exports": {
                "json": json_path,
                "pdf": pdf_path
            },
            "ingestion": ingestion,
            "diff": diff,
            "workflow": workflow,
            "mapping": state.get("schema_analysis"),
            "traceability": traceability,
            "metadata": standardized["metadata"],
            "classification": standardized["classification"],
            "issues": standardized["issues"],
            "risks": standardized["risks"],
            "prioritized_risks": standardized["prioritized_risks"],
            "tasks": standardized["tasks"],
            "unstructured_results": standardized["unstructured_results"],
            "document_context": standardized["document_context"],
            "document_alignment": standardized["document_alignment"],
            "summary": standardized["summary"],
            "monitoring": monitoring,
            "standardized_output": standardized
        }
    final_output["validation"] = validate_final_output(final_output)
    return {"final_output": final_output}


builder = StateGraph(GraphState)

builder.add_node("initialize", initialize_state)
builder.add_node("source_inventory", data_agent)
builder.add_node("profiling", profiling_agent)
builder.add_node("classification", classification_agent)
builder.add_node("document_insights", document_insights_agent)
builder.add_node("unstructured_scanner", unstructured_agent)
builder.add_node("data_findings", gap_analysis_agent)
builder.add_node("risk_engine", risk_agent)
builder.add_node("raid", raid_agent)
builder.add_node("governance", governance_agent)
builder.add_node("aggregator", aggregator)

builder.set_entry_point("initialize")
builder.add_edge("initialize", "source_inventory")
builder.add_edge("source_inventory", "profiling")
builder.add_edge("profiling", "classification")
builder.add_edge("classification", "document_insights")
builder.add_edge("document_insights", "unstructured_scanner")
builder.add_edge("unstructured_scanner", "data_findings")
builder.add_edge("data_findings", "risk_engine")
builder.add_edge("risk_engine", "raid")
builder.add_edge("raid", "governance")
builder.add_edge("governance", "aggregator")

graph = builder.compile()


if __name__ == "__main__":
    result = graph.invoke({})

    from pprint import pprint
    pprint(result["final_output"])
