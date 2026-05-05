export default function RelationshipGraph({ relationships }) {
  if (!relationships?.length) {
    return (
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Relationships</h2>
            <p>No inferred or explicit relationships were available in this run.</p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>Relationship Map</h2>
          <p>Shared keys and inferred joins across scanned tables.</p>
        </div>
      </div>

      <div className="relationship-list">
        {relationships.map((item, index) => (
          <div className="relationship-edge" key={`${item.fromTable}-${item.toTable}-${index}`}>
            <div className="relationship-node">
              <strong>{item.fromTable}</strong>
              <span>{item.fromColumn || "source"}</span>
            </div>
            <div className="relationship-arrow">
              <span>{item.type.replaceAll("_", " ")}</span>
              <strong>{item.confidence ? `${Math.round(item.confidence * 100)}%` : "linked"}</strong>
            </div>
            <div className="relationship-node">
              <strong>{item.toTable}</strong>
              <span>{item.toColumn || "target"}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
