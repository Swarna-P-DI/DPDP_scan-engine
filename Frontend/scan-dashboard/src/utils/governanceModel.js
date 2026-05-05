const severityRank = { high: 3, medium: 2, low: 1 };
const riskRank = { HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

const normalizeText = (value) => String(value || "").trim();
const displayOwner = (value) => {
  const lowered = normalizeText(value).toLowerCase();
  if (!lowered || lowered === "unknown" || lowered === "postgres" || lowered === "system") {
    return "Data Engineering / Data Steward";
  }
  return "Data Engineering / Data Steward";
};

const normalizeSeverity = (value) => {
  const lowered = normalizeText(value).toLowerCase();
  return lowered === "high" || lowered === "medium" || lowered === "low" ? lowered : "low";
};

export const normalizeRisk = (value) => {
  const upper = normalizeText(value).toUpperCase();
  return upper in riskRank ? upper : "LOW";
};

const dedupe = (items, buildKey) => {
  const seen = new Set();
  return (items || []).filter((item) => {
    const key = buildKey(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

const recommendationCategory = (action) => {
  const lowered = normalizeText(action).toLowerCase();
  if (lowered.includes("mask")) return "masking";
  if (lowered.includes("owner")) return "ownership";
  if (lowered.includes("access")) return "access";
  if (lowered.includes("sample")) return "quality";
  return "governance";
};

export const riskTone = (value) => {
  const risk = normalizeRisk(value);
  if (risk === "HIGH") return "high";
  if (risk === "MEDIUM") return "medium";
  return "low";
};

export const severityTone = (value) => normalizeSeverity(value);

export const maskingNarrative = (status, recommendation) => {
  if (status === "MASKED") return "Column is masked and currently aligned with control expectations.";
  if (status === "PARTIALLY_MASKED") {
    return recommendation && recommendation !== "NONE"
      ? `Column is only partially masked. Recommended next control: ${recommendation.replaceAll("_", " ")}.`
      : "Column is only partially masked and should be reviewed for re-identification risk.";
  }
  if (status === "NOT_MASKED") {
    return recommendation && recommendation !== "NONE"
      ? `Column contains unmasked sensitive data and should use ${recommendation.replaceAll("_", " ")}.`
      : "Column contains unmasked sensitive data and requires remediation.";
  }
  return "Masking is not applicable or could not be determined from the sampled values.";
};

const buildIssue = (item, defaults = {}) => ({
  description: item.description || item.issue || defaults.description || "Issue detected",
  table: item.table || defaults.table || "",
  column: item.column || defaults.column || "",
  severity: normalizeSeverity(item.severity || defaults.severity),
  owner: displayOwner(item.owner || defaults.owner || "unassigned"),
  source: defaults.source || item.source || "scan",
  evidence: item.evidence || defaults.evidence || "",
  impact: item.impact || defaults.impact || "",
  type: item.type || defaults.type || "governance",
});

export const buildGovernanceModel = (data) => {
  const sourceTables = data?.source_inventory?.tables || [];
  const profiling = data?.profiling || {};
  const intelligenceTables = data?.column_intelligence?.tables || {};
  const relationshipSource = data?.relationship_inference?.length
    ? data.relationship_inference
    : data?.schema_analysis?.relationships || [];

  const columns = sourceTables.flatMap((table) => {
    const profile = profiling[table.qualified_name] || {};
    const intelligence = intelligenceTables[table.qualified_name] || [];

    return (table.columns || []).map((column) => {
      const detected = intelligence.find((item) => item.column === column.name) || {};
      const risk = normalizeRisk(detected.risk);
      return {
        table: table.qualified_name,
        owner: displayOwner(table.owner || "unknown"),
        column: column.name,
        dataType: column.type,
        nullable: Boolean(column.nullable),
        primaryKey: Boolean(column.primary_key),
        piiDetected: Boolean(detected.pii_detected),
        piiType: detected.pii_type || "None",
        piiConfidence: detected.pii_confidence || "none",
        detectedBy: detected.detected_by || "rule_engine",
        maskingStatus: detected.masking_status || "NOT_APPLICABLE",
        recommendedMasking: detected.recommended_masking || "NONE",
        maskingNarrative: maskingNarrative(detected.masking_status, detected.recommended_masking),
        classification: detected.classification || "Public",
        tags: detected.tags || [],
        risk,
        riskTone: riskTone(risk),
        evidence: detected.evidence || "No evidence available",
        rowCount: profile.row_count ?? 0,
        sampleSize: profile.sample_size ?? 0,
        uniqueCount: profile.unique_counts?.[column.name] ?? null,
        nullPercentage: profile.null_percentage?.[column.name] ?? 0,
        nullCount: profile.null_count_by_column?.[column.name] ?? 0,
        dataProfileType: profile.data_types?.[column.name] || column.type,
        numericStats: profile.numeric_stats?.[column.name] || null,
        sampleSufficiency: profile.sample_sufficiency || null,
        highNull: (profile.high_null_columns || []).includes(column.name),
      };
    });
  });

  const tables = sourceTables.map((table) => {
    const tableColumns = columns.filter((item) => item.table === table.qualified_name);
    const highRiskCount = tableColumns.filter((item) => item.risk === "HIGH").length;
    const mediumRiskCount = tableColumns.filter((item) => item.risk === "MEDIUM").length;
    const piiCount = tableColumns.filter((item) => item.piiDetected).length;
    const unmaskedPiiCount = tableColumns.filter(
      (item) => item.piiDetected && item.maskingStatus === "NOT_MASKED"
    ).length;
    const sample = profiling[table.qualified_name] || {};

    return {
      table: table.qualified_name,
      schema: table.schema,
      owner: displayOwner(table.owner || "unknown"),
      rowCount: sample.row_count ?? 0,
      sampleSize: sample.sample_size ?? 0,
      columnCount: (table.columns || []).length,
      primaryKeys: table.primary_key || [],
      foreignKeyCount: (table.foreign_keys || []).length,
      uniqueIndexCount: (table.indexes || []).filter((index) => index.unique).length,
      piiCount,
      unmaskedPiiCount,
      highRiskCount,
      mediumRiskCount,
      risk: highRiskCount ? "HIGH" : mediumRiskCount ? "MEDIUM" : "LOW",
      profileIssueCount: (sample.issues || []).length,
      sampleSufficiency: sample.sample_sufficiency || null,
    };
  }).sort((left, right) => riskRank[right.risk] - riskRank[left.risk]);

  const recommendations = dedupe(
    [
      ...(data?.recommendations || []),
      ...(data?.gap_analysis?.recommendations || []),
      ...(data?.raid?.recommendations || []),
    ].map((item) => ({
      action: item.action || item,
      owner: displayOwner(item.owner || "data owner"),
      priority: item.priority || "medium",
      type: item.type || "governance",
    })),
    (item) => `${item.action}|${item.owner}|${item.priority}`.toLowerCase()
  ).map((item) => ({
    ...item,
    category: recommendationCategory(item.action),
    summary: `Recommended action for ${item.owner}: ${item.action}`,
  }));

  const risks = dedupe(
    [
      ...(data?.raid?.risks || []).map((item) => ({
        description: item.description,
        severity: normalizeSeverity(item.severity),
        owner: displayOwner(item.owner || "unassigned"),
        evidence: item.evidence || "",
        source: "raid",
      })),
      ...columns
        .filter((item) => item.risk === "HIGH")
        .map((item) => ({
          description: `${item.table}.${item.column} requires immediate governance attention.`,
          severity: "high",
          owner: item.owner,
          evidence: item.evidence,
          source: "column_intelligence",
        })),
    ],
    (item) => `${item.description}|${item.owner}`.toLowerCase()
  ).sort((left, right) => severityRank[right.severity] - severityRank[left.severity]);

  const issues = dedupe(
    [
      ...(data?.dq_report?.table_wise_issues || []).map((item) =>
        buildIssue(item, {
          source: "data_quality",
          type: "quality",
          description: item.issue,
          impact: "May reduce data trust or profiling confidence.",
        })
      ),
      ...(data?.gap_analysis?.gaps || []).map((item) =>
        buildIssue(item, {
          source: "gap_analysis",
          table: item.table || "",
        })
      ),
      ...(data?.raid?.issues || []).map((item) =>
        buildIssue(item, {
          source: "raid",
        })
      ),
    ],
    (item) => `${item.description}|${item.table}|${item.column}|${item.type}`.toLowerCase()
  ).sort((left, right) => severityRank[right.severity] - severityRank[left.severity]);

  let aiInsights = dedupe(
    (data?.ai_insights || []).map((item) => ({
      type: item.type || "insight",
      insight: item.insight,
      severity: normalizeSeverity(item.severity),
    })),
    (item) => `${item.type}|${item.insight}`.toLowerCase()
  );

  if (!aiInsights.length) {
    aiInsights = dedupe(
      [
        columns.filter((item) => item.piiDetected && item.maskingStatus === "NOT_MASKED").length >= 2
          ? {
              type: "risk_pattern",
              insight: "Customer PII exists in multiple columns without masking, increasing exposure risk.",
              severity: "high",
            }
          : null,
        Object.values(profiling).some(
          (item) => item.sample_sufficiency?.status === "INSUFFICIENT"
        )
          ? {
              type: "data_quality",
              insight: "Low sample size reduces confidence in profiling and scoring.",
              severity: "medium",
            }
          : null,
      ].filter(Boolean),
      (item) => `${item.type}|${item.insight}`.toLowerCase()
    );
  }

  const relationships = relationshipSource.map((item) => ({
    type: item.type || "relationship",
    fromTable: item.from_table,
    fromColumn: item.from_column || "",
    toTable: item.to_table,
    toColumn: item.to_column || "",
    confidence: item.confidence ?? null,
    method: item.method || item.reason || "metadata",
  }));

  const summary = {
    runId: data?.run_id || data?.overview?.run_id || "N/A",
    database: data?.source_inventory?.database || data?.ingestion?.database || "Unknown",
    finalScore: data?.scores?.final_score ?? 0,
    qualityScore: data?.quality_score ?? data?.scores?.quality_score ?? 0,
    coverage: data?.gap_analysis?.coverage || "Unknown",
    tableCount: tables.length,
    piiColumns: data?.column_intelligence?.summary?.pii_columns ?? columns.filter((item) => item.piiDetected).length,
    unmaskedPiiColumns:
      data?.column_intelligence?.summary?.unmasked_pii_columns ??
      columns.filter((item) => item.piiDetected && item.maskingStatus === "NOT_MASKED").length,
    highRiskColumns:
      data?.column_intelligence?.summary?.high_risk_columns ??
      columns.filter((item) => item.risk === "HIGH").length,
    recommendationCount: recommendations.length,
    issueCount: issues.length,
    relationshipCount: relationships.length,
    modelType: data?.schema_analysis?.model_type || "Unknown",
    complianceStatus: data?.dpdp_compliance?.status || "Unknown",
  };

  return {
    summary,
    tables,
    columns,
    piiFindings: columns.filter((item) => item.piiDetected),
    risks,
    issues,
    recommendations,
    aiInsights,
    relationships,
    scoreDrivers: data?.scores?.score_drivers || [],
    workflow: data?.workflow || [],
    diff: data?.diff || {},
    impacts: dedupe(data?.gap_analysis?.impact || [], (item) => normalizeText(item).toLowerCase()),
    assumptions: data?.raid?.assumptions || [],
    dependencies: data?.raid?.dependencies || [],
    scoreExplanation: data?.score_explanation || "",
    raw: data,
  };
};
