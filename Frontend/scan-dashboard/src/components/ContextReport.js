import RiskBadge from "./RiskBadge";

const Section = ({ title, children, defaultOpen = true }) => (
  <details className="report-section" open={defaultOpen}>
    <summary>{title}</summary>
    <div className="report-section-body">{children}</div>
  </details>
);

export default function ContextReport({ context }) {
  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>Contextual Report</h2>
          <p>Client-ready governance narrative generated from the scan payload without exposing raw JSON.</p>
        </div>
      </div>

      <Section title="Executive Summary">
        <div className="summary-grid report-summary-grid">
          <div className="summary-tile">
            <span>Database</span>
            <strong>{context.summary.database}</strong>
          </div>
          <div className="summary-tile">
            <span>Final Score</span>
            <strong>{context.summary.finalScore}</strong>
          </div>
          <div className="summary-tile">
            <span>Compliance</span>
            <strong>{context.summary.complianceStatus}</strong>
          </div>
          <div className="summary-tile">
            <span>Coverage</span>
            <strong>{context.summary.coverage}</strong>
          </div>
        </div>
        <p className="insight-text">{context.summary.executiveNarrative}</p>
      </Section>

      <Section title="Risk Overview">
        <div className="issue-list">
          {context.risks.map((item, index) => (
            <article className="issue-item" key={`${item.summary}-${index}`}>
              <div className="insight-meta">
                <strong>{item.owner}</strong>
                <RiskBadge mode="severity" value={item.risk.includes("High") ? "high" : item.risk.includes("Moderate") ? "medium" : "low"} />
              </div>
              <p>{item.summary}</p>
              <span>Impact: {item.impact}</span>
            </article>
          ))}
        </div>
      </Section>

      <Section title="PII Exposure">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Table</th>
                <th>Column</th>
                <th>Exposure</th>
                <th>Risk</th>
                <th>Assigned Owner</th>
              </tr>
            </thead>
            <tbody>
              {context.piiFindings.map((item) => (
                <tr key={`${item.table}.${item.column}`}>
                  <td>{item.table}</td>
                  <td>{item.column}</td>
                  <td>{item.masking}</td>
                  <td>{item.risk}</td>
                  <td>{item.owner}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Data Quality Insights">
        <p className="insight-text">{context.dataQualityInsights.summary}</p>
        <div className="issue-list">
          {context.dataQualityInsights.issues.map((item, index) => (
            <article className="issue-item" key={`${item.table}-${index}`}>
              <div className="insight-meta">
                <strong>{item.table}</strong>
                <RiskBadge mode="severity" value={item.severity.includes("High") ? "high" : item.severity.includes("Moderate") ? "medium" : "low"} />
              </div>
              <p>{item.issue}</p>
            </article>
          ))}
        </div>
      </Section>

      <Section title="AI Insights">
        <div className="insight-list">
          {context.aiInsights.map((item, index) => (
            <article className="insight-card" key={`${item.type}-${index}`}>
              <div className="insight-meta">
                <strong>{item.type.replaceAll("_", " ")}</strong>
                <RiskBadge mode="severity" value={item.severity} />
              </div>
              <p>{item.insight}</p>
            </article>
          ))}
        </div>
      </Section>

      <Section title="Recommendations" defaultOpen={false}>
        <div className="prioritized-sections">
          <div className="list-card">
            <h3>Critical Actions</h3>
            <ul className="compact-list">
              {context.prioritizedFindings.critical.map((item, index) => (
                <li key={`${item.summary}-${index}`}>{item.summary} Impact: {item.impact}</li>
              ))}
            </ul>
          </div>
          <div className="list-card">
            <h3>Improvements</h3>
            <ul className="compact-list">
              {context.prioritizedFindings.improvements.map((item, index) => (
                <li key={`${item.summary}-${index}`}>{item.summary}</li>
              ))}
            </ul>
          </div>
          <div className="list-card">
            <h3>Observations</h3>
            <ul className="compact-list">
              {context.prioritizedFindings.observations.map((item, index) => (
                <li key={`${item.summary}-${index}`}>{item.summary}</li>
              ))}
            </ul>
          </div>
          <div className="list-card">
            <h3>Unified Actions</h3>
            <ul className="compact-list">
              {context.recommendations.map((item, index) => (
                <li key={`${item.action}-${index}`}>{item.action}</li>
              ))}
            </ul>
          </div>
        </div>
      </Section>
    </section>
  );
}
