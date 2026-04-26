import json
import os

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

REPORT_DIR = "storage/reports"
os.makedirs(REPORT_DIR, exist_ok=True)


def export_json(run_id, report):
    path = f"{REPORT_DIR}/{run_id}.json"

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    return path


def _paragraph(content, style):
    text = json.dumps(content, indent=2, default=str) if not isinstance(content, str) else content
    return Paragraph(text.replace("\n", "<br/>"), style)


def _build_context(report):
    overview = report.get("overview", {})
    scores = overview.get("scores", {})
    dq_report = report.get("dq_report", {})
    column_intelligence = report.get("column_intelligence", {})
    dpdp = report.get("dpdp_compliance", {})
    findings = report.get("data_findings", {})
    raid = report.get("raid", {})
    ai_insights = report.get("ai_insights", [])
    relationships = report.get("relationship_inference", [])

    pii_columns = column_intelligence.get("summary", {}).get("pii_columns", 0)
    unmasked_pii = column_intelligence.get("summary", {}).get("unmasked_pii_columns", 0)
    high_risk = column_intelligence.get("summary", {}).get("high_risk_columns", 0)

    return {
        "summary": (
            f"Run {overview.get('run_id', 'N/A')} scanned "
            f"{len(report.get('source_inventory', {}).get('tables', []))} table(s) in "
            f"{report.get('source_inventory', {}).get('database', 'the source system')}. "
            f"Final score is {scores.get('final_score', 'N/A')} with a quality score of "
            f"{scores.get('quality_score', scores.get('data_quality', 'N/A'))}."
        ),
        "risk_overview": (
            f"{high_risk} high-risk column(s), {pii_columns} PII column(s), and "
            f"{unmasked_pii} unmasked PII column(s) were detected. "
            f"DPDP status is {dpdp.get('status', 'UNKNOWN')}."
        ),
        "quality_summary": dq_report.get(
            "summary",
            "Data quality findings were generated from profiling results."
        ),
        "insights": [item.get("insight") for item in ai_insights if item.get("insight")],
        "pii_findings": [
            (
                f"{table}.{column.get('column')} is classified as {column.get('pii_type')} "
                f"with masking status {column.get('masking_status')}."
            )
            for table, columns in column_intelligence.get("tables", {}).items()
            for column in columns
            if column.get("pii_detected")
        ],
        "risks": [item.get("description") for item in raid.get("risks", []) if item.get("description")],
        "issues": [item.get("description") or item.get("issue") for item in raid.get("issues", [])],
        "recommendations": [item.get("action") for item in report.get("recommendations", []) if item.get("action")],
        "relationships": [
            f"{item.get('from_table')} -> {item.get('to_table')} ({item.get('method', item.get('type', 'relationship'))})"
            for item in relationships
        ],
        "impact": findings.get("impact", []),
    }


def export_pdf(run_id, report):
    path = f"{REPORT_DIR}/{run_id}.pdf"

    doc = SimpleDocTemplate(path)
    styles = getSampleStyleSheet()
    context = _build_context(report)
    content = [Paragraph("Data Governance Scan Report", styles["Title"])]

    sections = [
        ("Executive Summary", context["summary"]),
        ("Risk Overview", context["risk_overview"]),
        ("Quality Summary", context["quality_summary"]),
        ("AI Insights", context["insights"] or ["No AI insights available for this run."]),
        ("PII Findings", context["pii_findings"] or ["No PII findings were identified."]),
        ("Relationship Signals", context["relationships"] or ["No relationship signals were identified."]),
        ("Open Risks", context["risks"] or ["No RAID risks were recorded."]),
        ("Open Issues", context["issues"] or ["No RAID issues were recorded."]),
        ("Business Impact", context["impact"] or ["No additional impact statement was provided."]),
        ("Recommendations", context["recommendations"] or ["No recommendations were generated."]),
    ]

    for title, body in sections:
        content.append(Spacer(1, 12))
        content.append(Paragraph(title, styles["Heading2"]))
        if isinstance(body, list):
            for item in body:
                content.append(_paragraph(f"- {item}", styles["BodyText"]))
        else:
            content.append(_paragraph(body, styles["BodyText"]))

    doc.build(content)
    return path
