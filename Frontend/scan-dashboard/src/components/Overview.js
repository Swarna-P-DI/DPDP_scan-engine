import SummaryCard from "./SummaryCard";

export default function Overview({ data, model }) {
  const owners = new Set((data?.source_inventory?.tables || []).map((item) => item.owner).filter(Boolean));

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>Governance Summary</h2>
          <p>Immediate risk posture, compliance visibility, and remediation focus for the latest scan.</p>
        </div>
      </div>

      <div className="summary-grid hierarchy-grid">
        <SummaryCard label="Final Score" value={model.summary.finalScore} helper="Overall readiness after governance penalties." tone="neutral" />
        <SummaryCard label="High Risk Columns" value={model.summary.highRiskColumns} helper="Columns with the strongest exposure signal." tone="danger" />
        <SummaryCard label="Unmasked PII" value={model.summary.unmaskedPiiColumns} helper="Sensitive columns currently needing control action." tone="warning" />
        <SummaryCard label="Compliance Status" value={model.summary.complianceStatus} helper="DPDP-aligned control status from the scan." tone="accent" />
      </div>

      <div className="diagnostic-band">
        <div className="diagnostic-card">
          <span>Database</span>
          <strong>{model.summary.database}</strong>
          <p>{model.summary.tableCount} tables scanned across a {model.summary.modelType} model.</p>
        </div>
        <div className="diagnostic-card">
          <span>Owners</span>
          <strong>{owners.size || 0}</strong>
          <p>{model.summary.recommendationCount} deduplicated recommendations are ready for action.</p>
        </div>
        <div className="diagnostic-card">
          <span>Coverage</span>
          <strong>{model.summary.coverage}</strong>
          <p>{model.summary.issueCount} distinct issues remain open after cleanup.</p>
        </div>
      </div>

      {model.scoreExplanation ? <p className="insight-text">{model.scoreExplanation}</p> : null}

      {/* <div className="workflow-list">
        {model.workflow.map((step) => (
          <span key={step}>{step}</span>
        ))}
      </div> */}
    </section>
  );
}
