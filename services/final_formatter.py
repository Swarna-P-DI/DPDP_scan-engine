def format_report(output):
    return f"""
================= DATA SCAN REPORT =================

SOURCE INVENTORY
{output['source_inventory']}

SCHEMA
{output['schema']}

SCHEMA ANALYSIS
{output['schema_analysis']}

DATA PROFILING
{output['profiling']}

COLUMN INTELLIGENCE
{output['column_intelligence']}

DPDP COMPLIANCE
{output['dpdp_compliance']}

DATA QUALITY REPORT
{output['dq_report']}

DATA FINDINGS
{output['gap_analysis']}

RAID ANALYSIS
{output['raid']}

RELATIONSHIP INFERENCE
{output.get('relationship_inference', [])}

AI INSIGHTS
{output.get('ai_insights', [])}

RECOMMENDATIONS
{output['recommendations']}

TRACEABILITY
{output['traceability']}

SCORES
{output['scores']}

====================================================
"""
