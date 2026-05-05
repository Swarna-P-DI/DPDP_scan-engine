export default function RunHistory({ diff }) {
  if (!diff) return null;

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2>Run Diff</h2>
          <p>Changes compared with the previous saved run.</p>
        </div>
      </div>
      <div className="issue-list">
        {diff.message ? (
          <article className="issue-item">
            <p>{diff.message}</p>
          </article>
        ) : (
          <>
            <article className="issue-item">
              <strong>New Tables</strong>
              <p>{(diff.new_tables || []).length ? diff.new_tables.join(", ") : "No new tables detected."}</p>
            </article>
            <article className="issue-item">
              <strong>Removed Tables</strong>
              <p>{(diff.removed_tables || []).length ? diff.removed_tables.join(", ") : "No tables were removed."}</p>
            </article>
            <article className="issue-item">
              <strong>Score Change</strong>
              <p>
                Previous: {diff.score_change?.previous ?? "N/A"} | Current: {diff.score_change?.current ?? "N/A"}
              </p>
            </article>
          </>
        )}
      </div>
    </section>
  );
}
