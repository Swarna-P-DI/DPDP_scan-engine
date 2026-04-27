def build_report(final_output, ingestion, diff, workflow):
    return {
        "overview": {
            "summary": "DPDP-aware data discovery, profiling, quality, and RAID report",
            "run_id": final_output.get("run_id"),
            "scores": final_output["scores"]
        },
        "ingestion": ingestion,
        "workflow": workflow,
        "source_inventory": {
            "source_type": final_output["source_inventory"].get("source_type"),
            "database": final_output["source_inventory"].get("database"),
            "tables": final_output["source_inventory"].get("tables", [])
        },
        "schema_analysis": final_output.get("schema_analysis"),
        "profiling": final_output["profiling"],
        "dq_report": final_output.get("dq_report"),
        "column_intelligence": final_output.get("column_intelligence"),
        "dpdp_compliance": final_output.get("dpdp_compliance"),
        "data_findings": final_output["gap_analysis"],
        "raid": final_output["raid"],
        "relationship_inference": final_output.get("relationship_inference", []),
        "document_alignment": final_output.get("document_alignment", []),
        "ai_insights": final_output.get("ai_insights", []),
        "traceability": final_output.get("traceability", []),
        "recommendations": final_output.get("recommendations", []),
        "changes": diff
    }
