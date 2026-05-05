import { buildGovernanceModel } from "./governanceModel";

const normalizeText = (value) => String(value || "").trim();

const mapOwner = (owner) => {
  const lowered = normalizeText(owner).toLowerCase();
  if (!lowered || lowered === "unknown" || lowered === "postgres") {
    return "Data Engineering / Data Steward";
  }
  return "Data Engineering / Data Steward";
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

const businessRiskLabel = (value) => {
  const lowered = normalizeText(value).toLowerCase();
  if (lowered === "high") return "High compliance risk";
  if (lowered === "medium") return "Moderate compliance risk";
  return "Low compliance risk";
};

const businessMaskingLabel = (value) => {
  if (value === "NOT_MASKED") return "Unprotected sensitive data";
  if (value === "PARTIALLY_MASKED") return "Partially protected sensitive data";
  if (value === "MASKED") return "Protected sensitive data";
  return "Masking not applicable";
};

const businessStatusLabel = (value) => {
  if (value === "ACTION_REQUIRED") return "Immediate remediation required";
  return normalizeText(value) || "Status unavailable";
};

const executiveNarrative = (model) => {
  if (model.summary.unmaskedPiiColumns > 0) {
    return "This scan identified unmasked personal data in customer tables, posing a high compliance risk under DPDP. Immediate remediation is required before further data usage.";
  }
  if (model.summary.highRiskColumns > 0) {
    return "This scan identified sensitive data exposures that require governance review before broader downstream usage.";
  }
  return "This scan did not identify critical personal-data exposure, but governance controls should continue to be monitored.";
};

const unifiedRecommendations = (model) => {
  const hasMasking = model.recommendations.some((item) => item.category === "masking");
  const hasQuality = model.issues.some((item) => item.source === "data_quality" || item.type === "profiling");
  const list = [];

  if (hasMasking) {
    list.push({
      title: "Apply masking controls",
      priority: "high",
      owner: "Data Engineering / Data Steward",
      action: "Apply masking or tokenization to protect sensitive data and restrict unauthorized access",
      category: "critical",
    });
  }

  if (hasQuality) {
    list.push({
      title: "Improve profiling coverage",
      priority: "medium",
      owner: "Data Engineering / Data Steward",
      action: "Increase sample coverage and resolve profiling limitations before relying on downstream quality conclusions",
      category: "improvement",
    });
  }

  list.push({
    title: "Maintain governance ownership",
    priority: "medium",
    owner: "Data Engineering / Data Steward",
    action: "Confirm accountable owners for sensitive datasets, remediation tracking, and access control decisions",
    category: "improvement",
  });

  return dedupe(list, (item) => `${item.action}|${item.owner}|${item.priority}`.toLowerCase());
};

const buildPrioritizedFindings = (model) => {
  const critical = [];
  const improvements = [];
  const observations = [];

  model.piiFindings.forEach((item) => {
    if (item.maskingStatus === "NOT_MASKED") {
      critical.push({
        title: `${item.table}.${item.column}`,
        severity: "critical",
        summary: `${item.table}.${item.column} contains ${item.piiType} and is currently unprotected sensitive data.`,
        impact: "Potential DPDP non-compliance and exposure of personal data",
        owner: "Assigned Owner: Data Engineering / Data Steward",
      });
    }
  });

  model.issues.forEach((item) => {
    const entry = {
      title: item.table || item.type || "Finding",
      severity: item.severity === "high" ? "critical" : "improvement",
      summary: item.description,
      impact: item.severity === "high"
        ? "Potential DPDP non-compliance and exposure of personal data"
        : "May reduce profiling confidence and decision-making quality",
      owner: `Assigned Owner: ${mapOwner(item.owner)}`,
    };

    if (entry.severity === "critical") {
      critical.push(entry);
    } else {
      improvements.push(entry);
    }
  });

  model.relationships.forEach((item) => {
    observations.push({
      title: `${item.fromTable} -> ${item.toTable}`,
      severity: "observation",
      summary: `Relationship signal detected through ${item.method}.`,
      impact: "Useful for lineage validation and access review",
      owner: "Assigned Owner: Data Engineering / Data Steward",
    });
  });

  return {
    critical: dedupe(critical, (item) => item.summary.toLowerCase()),
    improvements: dedupe(improvements, (item) => item.summary.toLowerCase()),
    observations: dedupe(observations, (item) => item.summary.toLowerCase()),
  };
};

export const buildReportContext = (rawData, rawStatus) => {
  const model = buildGovernanceModel(rawData);
  const prioritizedFindings = buildPrioritizedFindings(model);
  const recommendations = unifiedRecommendations(model);

  const piiFindings = model.piiFindings.map((item) => ({
    table: item.table,
    column: item.column,
    piiType: item.piiType,
    masking: businessMaskingLabel(item.maskingStatus),
    risk: businessRiskLabel(item.risk),
    owner: `Assigned Owner: ${mapOwner(item.owner)}`,
    recommendation: item.recommendedMasking === "NONE"
      ? "Existing protection is acceptable"
      : `Recommended control: ${item.recommendedMasking.replaceAll("_", " ")}`,
    impact: item.maskingStatus === "NOT_MASKED"
      ? "Potential DPDP non-compliance and exposure of personal data"
      : "Lower residual exposure, but continued monitoring is recommended",
  }));

  const risks = dedupe(
    model.risks.map((item) => ({
      summary: item.description,
      risk: businessRiskLabel(item.severity),
      owner: `Assigned Owner: ${mapOwner(item.owner)}`,
      impact: "Potential DPDP non-compliance and exposure of personal data",
    })),
    (item) => item.summary.toLowerCase()
  );

  const issues = dedupe(
    model.issues.map((item) => ({
      summary: item.description,
      category: item.type,
      priority: item.severity === "high" ? "Critical action" : "Improvement",
      owner: `Assigned Owner: ${mapOwner(item.owner)}`,
      impact: item.severity === "high"
        ? "Potential DPDP non-compliance and exposure of personal data"
        : "May reduce data reliability, profiling confidence, or governance clarity",
    })),
    (item) => `${item.summary}|${item.category}`.toLowerCase()
  );

  return {
    rawStatus,
    rawData,
    model,
    summary: {
      runId: model.summary.runId,
      database: model.summary.database,
      finalScore: model.summary.finalScore,
      qualityScore: model.summary.qualityScore,
      complianceStatus: businessStatusLabel(model.summary.complianceStatus),
      coverage: model.summary.coverage,
      executiveNarrative: executiveNarrative(model),
      statusNarrative: `${model.summary.highRiskColumns} high-risk columns and ${model.summary.unmaskedPiiColumns} unprotected sensitive columns were identified.`,
    },
    piiFindings,
    risks,
    issues,
    recommendations,
    aiInsights: model.aiInsights,
    prioritizedFindings,
    dataQualityInsights: {
      summary: rawData?.dq_report?.summary || "Profiling insights were generated from sampled source data.",
      dimensions: rawData?.dq_report?.quality_dimensions || {},
      issues: (rawData?.dq_report?.table_wise_issues || []).map((item) => ({
        table: item.table,
        issue: item.issue,
        severity: businessRiskLabel(item.severity),
      })),
    },
    flow: [
      "Executive Summary",
      "Risk Overview",
      "PII Exposure",
      "Data Quality Insights",
      "AI Insights",
      "Recommendations",
      "Appendix",
    ],
    appendix: {
      workflow: model.workflow,
      relationships: model.relationships,
      tables: model.tables,
      columns: model.columns,
    },
  };
};
