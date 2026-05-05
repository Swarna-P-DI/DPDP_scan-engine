import ActionButtons from "./ActionButtons";
import RiskBadge from "./RiskBadge";

const RaidSection = ({ title, items, renderBody }) => (
  <details className="report-section" open>
    <summary>{title}</summary>
    <div className="report-section-body">
      {items.length ? items.map(renderBody) : <p className="muted-copy">No entries in this section.</p>}
    </div>
  </details>
);

export default function Raid({ data, model, onCreateAction, onInspect }) {
  if (!data) return null;

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>RayIN : RAID Master</h2>
          <p>Structured risk, issue, assumption, and dependency review for governance operations.</p>
        </div>
      </div>

      <RaidSection
        title="Risks"
        items={model.risks}
        renderBody={(item, index) => (
          <article className="issue-item" key={`${item.description}-${index}`}>
            <div className="insight-meta">
              <strong>{item.owner}</strong>
              <RiskBadge mode="severity" value={item.severity} />
            </div>
            <p>{item.description}</p>
            {item.evidence ? <span>{item.evidence}</span> : null}
            <div className="inline-actions">
              <button
                className="ghost-action"
                onClick={() => onInspect?.(item)}
                type="button"
              >
                View Details
              </button>
            </div>
            <ActionButtons
              compact
              context={{
                label: `Risk: ${item.description}`,
                summary: item.description,
                severity: item.severity,
                table: item.table,
                column: item.column,
                owner: item.owner,
                issueType: "risk",
              }}
              onCreateAction={onCreateAction}
            />
          </article>
        )}
      />

      <RaidSection
        title="Assumptions"
        items={model.assumptions}
        renderBody={(item, index) => (
          <article className="issue-item" key={`${item.description}-${index}`}>
            <strong>{item.description}</strong>
            {item.validation_needed ? <p>{item.validation_needed}</p> : null}
          </article>
        )}
      />

      <RaidSection
        title="Dependencies"
        items={model.dependencies}
        renderBody={(item, index) => (
          <article className="issue-item" key={`${item.description}-${index}`}>
            <strong>{item.dependency_type || "dependency"}</strong>
            <p>{item.description}</p>
          </article>
        )}
      />
    </section>
  );
}
