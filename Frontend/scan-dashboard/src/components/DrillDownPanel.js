import ActionButtons from "./ActionButtons";
import RiskBadge from "./RiskBadge";

const Stat = ({ label, value }) => (
  <div className="detail-stat">
    <span>{label}</span>
    <strong>{value}</strong>
  </div>
);

export default function DrillDownPanel({ column, relatedRecommendations, onCreateAction }) {
  if (!column) {
    return (
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Column Drill-Down</h2>
            <p>Select a column to review its controls, evidence, and suggested actions.</p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2>{column.column}</h2>
          <p>{column.table}</p>
        </div>
        <RiskBadge value={column.risk} />
      </div>

      <div className="detail-grid">
        <Stat label="Classification" value={column.classification} />
        <Stat label="PII Type" value={column.piiType} />
        <Stat label="Masking" value={column.maskingStatus.replaceAll("_", " ")} />
        <Stat label="Recommended" value={column.recommendedMasking.replaceAll("_", " ")} />
      </div>

      <div className="detail-copy">
        <p><strong>Detection logic:</strong> {column.detectedBy.replaceAll("_", " ")} with {column.piiConfidence} confidence.</p>
        <p><strong>Evidence:</strong> {column.evidence}</p>
        <p><strong>Control narrative:</strong> {column.maskingNarrative}</p>
      </div>

      <div className="detail-grid">
        <Stat label="Rows Profiled" value={column.rowCount} />
        <Stat label="Sample Size" value={column.sampleSize} />
        <Stat label="Null %" value={`${Math.round((column.nullPercentage || 0) * 100)}%`} />
        <Stat label="Unique Values" value={column.uniqueCount ?? "N/A"} />
      </div>

      {column.numericStats ? (
        <div className="mini-table">
          <h3>Numeric Profile</h3>
          <div className="stat-chip-row">
            {Object.entries(column.numericStats).map(([key, value]) => (
              <span className="stat-chip" key={key}>{key}: {Number(value).toFixed ? Number(value).toFixed(2) : value}</span>
            ))}
          </div>
        </div>
      ) : null}

      <ActionButtons
        context={{
          label: `Column: ${column.table}.${column.column}`,
          summary: column.maskingNarrative,
          severity: column.risk.toLowerCase(),
          table: column.table,
          column: column.column,
          owner: column.owner,
          issueType: column.piiDetected ? "pii_exposure" : "column_review",
        }}
        onCreateAction={onCreateAction}
      />

      {relatedRecommendations?.length ? (
        <div className="mini-table">
          <h3>Related Recommendations</h3>
          <ul className="compact-list">
            {relatedRecommendations.map((item, index) => (
              <li key={`${item.action}-${index}`}>{item.action}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
