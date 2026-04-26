def compact_source_inventory(source_inventory):
    tables = []
    for table in source_inventory.get("tables", []):
        columns = table.get("columns", [])
        tables.append({
            "table": table.get("qualified_name"),
            "owner": table.get("owner", "unknown"),
            "column_count": len(columns),
            "columns": [column.get("name") for column in columns],
            "nullable_columns": [
                column.get("name") for column in columns
                if column.get("nullable")
            ],
            "primary_key": table.get("primary_key", []),
            "foreign_keys": table.get("foreign_keys", []),
            "unique_indexes": [
                index for index in table.get("indexes", [])
                if index.get("unique")
            ]
        })

    return {
        "source_type": source_inventory.get("source_type"),
        "database": source_inventory.get("database"),
        "table_count": len(tables),
        "tables": tables
    }


def build_schema_analysis(source_inventory):
    tables = []
    relationships = []
    unknown_owners = []

    for table in source_inventory.get("tables", []):
        qualified_name = table.get("qualified_name")
        column_names = [column.get("name") for column in table.get("columns", [])]
        tables.append({
            "name": qualified_name,
            "description": f"{qualified_name} contains {len(column_names)} columns.",
            "columns": column_names
        })

        if table.get("owner") in (None, "", "unknown"):
            unknown_owners.append(qualified_name)

        for fk in table.get("foreign_keys", []):
            referred_schema = fk.get("referred_schema") or table.get("schema")
            referred_table = fk.get("referred_table")
            relationships.append({
                "from_table": qualified_name,
                "to_table": f"{referred_schema}.{referred_table}" if referred_schema else referred_table,
                "type": "explicit",
                "reason": f"Foreign key on {fk.get('columns', [])} references {fk.get('referred_columns', [])}."
            })

    model_type = "transactional"
    table_names = " ".join(table.get("name", "").lower() for table in tables)
    if any(token in table_names for token in ("fact", "dim", "aggregate", "summary")):
        model_type = "analytical"
    if relationships and model_type == "analytical":
        model_type = "hybrid"

    return {
        "tables": tables,
        "relationships": relationships,
        "model_type": model_type,
        "ownership_observations": [
            f"{len(unknown_owners)} table(s) have unknown ownership."
        ] if unknown_owners else ["All scanned tables have an owner from source metadata."],
        "inventory_risks": [
            f"Unknown ownership for: {', '.join(unknown_owners)}"
        ] if unknown_owners else []
    }


def compact_profiling(profiling):
    compact = {}

    for table, stats in profiling.items():
        null_percentage = stats.get("null_percentage", {})
        compact[table] = {
            "row_count": stats.get("row_count"),
            "column_count": stats.get("column_count"),
            "null_count": stats.get("null_count"),
            "high_null_columns": stats.get("high_null_columns", []),
            "top_null_percentages": dict(
                sorted(
                    null_percentage.items(),
                    key=lambda item: item[1],
                    reverse=True
                )[:10]
            ),
            "duplicate_count": stats.get("duplicate_count"),
            "duplicate_ratio": stats.get("duplicate_ratio"),
            "issues": stats.get("issues", []),
            "data_types": stats.get("data_types", {}),
            "unique_counts": stats.get("unique_counts", {})
        }

    return compact


def public_profiling(profiling):
    return {
        table: {
            key: value
            for key, value in stats.items()
            if key != "sample_values"
        }
        for table, stats in profiling.items()
    }


def build_dq_report(profiling, quality_score):
    table_wise_issues = []
    recommendations = []

    for table, stats in profiling.items():
        sample_sufficiency = stats.get("sample_sufficiency", {})
        if sample_sufficiency.get("status") == "INSUFFICIENT":
            table_wise_issues.append({
                "table": table,
                "issue": sample_sufficiency.get("message", "Insufficient data for reliable profiling"),
                "severity": "medium"
            })
            recommendations.append(f"Increase profiling sample size for {table} before relying on quality conclusions.")

        for column in stats.get("high_null_columns", []):
            pct = stats.get("null_percentage", {}).get(column, 0)
            severity = "high" if pct >= 0.5 else "medium"
            table_wise_issues.append({
                "table": table,
                "issue": f"{column} has {round(pct * 100, 2)}% null values",
                "severity": severity
            })
            recommendations.append(f"Review completeness rules and upstream capture for {table}.{column}.")

        if stats.get("duplicate_count", 0) > 0:
            severity = "high" if stats.get("duplicate_ratio", 0) >= 0.1 else "medium"
            table_wise_issues.append({
                "table": table,
                "issue": f"{stats.get('duplicate_count')} duplicate sampled rows found",
                "severity": severity
            })
            recommendations.append(f"Define or enforce uniqueness rules for {table}.")

        for issue in stats.get("issues", []):
            table_wise_issues.append({
                "table": table,
                "issue": issue,
                "severity": "high"
            })
            recommendations.append(f"Fix invalid values detected in {table}: {issue}.")

    if not recommendations:
        recommendations.append("Continue periodic profiling to detect drift in completeness, uniqueness, and validity.")

    return {
        "summary": f"Profiled {len(profiling)} table(s). Data quality score is {quality_score}.",
        "quality_dimensions": {
            "completeness": "Measured with cell-level null counts and high-null column detection.",
            "uniqueness": "Measured with duplicate sampled-row counts and ratios.",
            "consistency": "Measured with reusable column-pattern checks.",
            "accuracy": "Flagged where domain-like rules identify invalid values.",
            "integrity": "Supported by source primary key and foreign key metadata."
        },
        "table_wise_issues": table_wise_issues,
        "overall_score": quality_score,
        "recommendations": recommendations
    }


def build_score_explanation(scoring, dq_report, data_findings, raid):
    issue_count = len((dq_report or {}).get("table_wise_issues", []))
    finding_count = len((data_findings or {}).get("gaps", []))
    risk_count = len((raid or {}).get("risks", []))
    return (
        f"Final score is {scoring.get('final_score')} after applying a "
        f"{scoring.get('risk_penalty', 0)} point risk penalty to the quality score. "
        f"The scan found {issue_count} data quality issue(s), {finding_count} finding(s), "
        f"and {risk_count} RAID risk(s). Prioritize high-severity ownership, integrity, "
        "and validity fixes before expanding downstream use."
    )


def build_data_findings_and_raid(source_inventory, schema_analysis, profiling, dq_report, column_intelligence=None):
    findings = {
        "coverage": "Good",
        "gaps": [],
        "data_issues": [],
        "impact": [],
        "recommendations": []
    }
    raid = {
        "risks": [],
        "assumptions": [],
        "issues": [],
        "dependencies": [],
        "recommendations": []
    }

    table_lookup = {
        table.get("qualified_name"): table
        for table in source_inventory.get("tables", [])
    }

    for table_name, table in table_lookup.items():
        owner = table.get("owner", "unknown")

        if owner == "unknown":
            findings["gaps"].append({
                "type": "ownership",
                "description": f"{table_name} does not have a resolved data owner in source metadata.",
                "evidence": "tableowner was unavailable or unknown",
                "owner": "unknown",
                "severity": "medium"
            })
            raid["risks"].append({
                "description": f"Ownership is unclear for {table_name}.",
                "severity": "medium",
                "evidence": "Unknown table owner",
                "owner": "unknown"
            })
            raid["recommendations"].append({
                "action": f"Assign a named data owner for {table_name}.",
                "priority": "medium",
                "owner": "data governance"
            })

        if not table.get("primary_key"):
            findings["gaps"].append({
                "type": "integrity",
                "description": f"{table_name} has no primary key in source metadata.",
                "evidence": "primary_key is empty",
                "owner": owner,
                "severity": "medium"
            })

        table_profile = profiling.get(table_name, {})
        sample_sufficiency = table_profile.get("sample_sufficiency", {})
        if sample_sufficiency.get("status") == "INSUFFICIENT":
            findings["gaps"].append({
                "type": "profiling",
                "description": sample_sufficiency.get("message", "Insufficient data for reliable profiling"),
                "evidence": f"sample_size={table_profile.get('sample_size')}, threshold={sample_sufficiency.get('threshold')}",
                "owner": owner,
                "severity": "medium"
            })
            raid["issues"].append({
                "type": "data",
                "description": f"Low sample size for {table_name}.",
                "severity": "medium",
                "impact": "Profiling confidence is reduced and rare data quality defects may be missed.",
                "owner": owner
            })
            raid["issues"].append({
                "type": "metadata",
                "description": f"Primary key is not defined for {table_name}.",
                "severity": "medium",
                "impact": "Uniqueness and downstream joins may be ambiguous.",
                "owner": owner
            })

    for issue in dq_report.get("table_wise_issues", []):
        table = issue.get("table")
        owner = table_lookup.get(table, {}).get("owner", "unknown")
        severity = issue.get("severity", "medium")
        description = issue.get("issue", "Data quality issue")

        findings["gaps"].append({
            "type": "quality",
            "description": description,
            "evidence": "profiling metric exceeded quality threshold",
            "owner": owner,
            "severity": severity
        })
        findings["data_issues"].append(f"{table}: {description}")
        raid["issues"].append({
            "type": "quality",
            "description": description,
            "severity": severity,
            "impact": "May reduce reliability of reporting, analytics, or downstream processing.",
            "owner": owner
        })
        if severity == "high":
            raid["risks"].append({
                "description": f"High severity quality issue in {table}: {description}",
                "severity": "high",
                "evidence": "Data profiling result",
                "owner": owner
            })

    for recommendation in dq_report.get("recommendations", []):
        findings["recommendations"].append({
            "action": recommendation,
            "type": "data_fix",
            "priority": "medium",
            "owner": "data owner"
        })

    for table_name, columns in (column_intelligence or {}).get("tables", {}).items():
        owner = table_lookup.get(table_name, {}).get("owner", "unknown")
        for column in columns:
            if column.get("pii_detected") and column.get("masking_status") == "NOT_MASKED":
                description = (
                    f"{table_name}.{column.get('column')} contains unmasked "
                    f"{column.get('pii_type')} PII."
                )
                findings["gaps"].append({
                    "type": "quality",
                    "description": description,
                    "evidence": column.get("evidence"),
                    "owner": owner,
                    "severity": "high"
                })
                findings["data_issues"].append(description)
                findings["recommendations"].append({
                    "action": f"Apply masking or tokenization to {table_name}.{column.get('column')}.",
                    "type": "data_fix",
                    "priority": "high",
                    "owner": owner
                })
                raid["risks"].append({
                    "description": description,
                    "severity": "high",
                    "evidence": column.get("evidence"),
                    "owner": owner
                })
                raid["issues"].append({
                    "type": "quality",
                    "description": description,
                    "severity": "high",
                    "impact": "Potential DPDP non-compliance and personal data exposure.",
                    "owner": owner
                })
                raid["recommendations"].append({
                    "action": f"Mask, tokenize, or restrict access to {table_name}.{column.get('column')}.",
                    "priority": "high",
                    "owner": owner
                })
            elif column.get("pii_detected") and column.get("masking_status") == "PARTIALLY_MASKED":
                raid["risks"].append({
                    "description": f"{table_name}.{column.get('column')} contains partially masked {column.get('pii_type')} PII.",
                    "severity": "medium",
                    "evidence": column.get("evidence"),
                    "owner": owner
                })

    if schema_analysis.get("relationships"):
        raid["dependencies"].append({
            "description": "Relationship integrity depends on upstream enforcement of discovered foreign keys.",
            "dependency_type": "upstream_data"
        })
    else:
        raid["assumptions"].append({
            "description": "No explicit relationships were found in source metadata.",
            "validation_needed": "Confirm whether joins are enforced outside the database."
        })

    high_count = sum(1 for gap in findings["gaps"] if gap.get("severity") == "high")
    medium_count = sum(1 for gap in findings["gaps"] if gap.get("severity") == "medium")
    if high_count:
        findings["coverage"] = "Weak"
    elif medium_count:
        findings["coverage"] = "Moderate"

    if findings["gaps"]:
        findings["impact"].append(
            "Open metadata, ownership, integrity, or quality findings should be resolved before broad downstream consumption."
        )
    else:
        findings["impact"].append("No major profiling or metadata gaps were detected in the sampled scan.")

    raid["recommendations"].extend([
        {
            "action": item.get("action"),
            "priority": item.get("priority", "medium"),
            "owner": item.get("owner", "data owner")
        }
        for item in findings["recommendations"]
    ])

    return findings, raid
