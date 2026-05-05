import ActionButtons from "./ActionButtons";
import RiskBadge from "./RiskBadge";

export default function GapAnalysis({ data, model, onCreateAction, onInspect }) {
  if (!data) return null;

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>Findings And Impact</h2>
          <p>Coverage: <strong>{data.coverage || "Unknown"}</strong>. Duplicate gaps and recommendations have been collapsed for easier review.</p>
        </div>
      </div>

      <div className="issue-list">
        {(model.issues || []).map((issue, index) => (
          <article className="issue-item" key={`${issue.description}-${index}`}>
            <div className="insight-meta">
              <strong>{issue.type}</strong>
              <RiskBadge mode="severity" value={issue.severity} />
            </div>
            <span>{issue.table || issue.owner || "scan-wide"} | {issue.source}</span>
            <p>{issue.description}</p>
            {issue.impact ? <p className="subtle-copy">{issue.impact}</p> : null}
            <div className="inline-actions">
              <button
                className="ghost-action"
                onClick={() => onInspect?.(issue)}
                type="button"
              >
                View Details
              </button>
            </div>
            <ActionButtons
              compact
              context={{
                label: `Finding: ${issue.description}`,
                summary: issue.description,
                severity: issue.severity,
                table: issue.table,
                column: issue.column,
                owner: issue.owner,
                issueType: issue.type,
              }}
              onCreateAction={onCreateAction}
            />
          </article>
        ))}
      </div>

      <div className="split-grid">
        <div className="list-card">
          <h3>Impact</h3>
          <ul className="compact-list">
            {model.impacts.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
          </ul>
        </div>
        <div className="list-card">
          <h3>Recommendations</h3>
          <ul className="compact-list">
            {model.recommendations.map((item, index) => (
              <li key={`${item.action}-${index}`}>{item.summary}</li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
