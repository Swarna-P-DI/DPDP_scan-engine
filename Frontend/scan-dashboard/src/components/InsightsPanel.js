import RiskBadge from "./RiskBadge";

export default function InsightsPanel({ insights }) {
  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>AI Insights</h2>
          <p>Contextual signals blended across classification, RayIN analysis, and scan findings.</p>
        </div>
      </div>

      <div className="insight-list">
        {(insights || []).length ? (
          insights.map((item, index) => (
            <article className="insight-card" key={`${item.type}-${index}`}>
              <div className="insight-meta">
                <strong>{item.type.replaceAll("_", " ")}</strong>
                <RiskBadge mode="severity" value={item.severity} />
              </div>
              <p>{item.insight}</p>
            </article>
          ))
        ) : (
          <article className="insight-card">
            <p>No AI insights were generated for this run.</p>
          </article>
        )}
      </div>
    </section>
  );
}
