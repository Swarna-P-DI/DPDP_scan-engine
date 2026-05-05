import RiskBadge from "./RiskBadge";

export default function DataQuality({ data, profiling }) {
  const tables = Object.entries(profiling || {});
  const issues = data?.table_wise_issues || [];

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>Data Quality</h2>
          <p>{data?.summary || "Profiling and quality dimensions from the latest scan."}</p>
        </div>
        <strong className="score-badge">{data?.overall_score ?? "N/A"}</strong>
      </div>

      <div className="dimension-grid">
        {Object.entries(data?.quality_dimensions || {}).map(([key, value]) => (
          <div className="dimension" key={key}>
            <span>{key.replaceAll("_", " ")}</span>
            <p>{value}</p>
          </div>
        ))}
      </div>

      <h3>Diagnostic Table View</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Table</th>
              <th>Rows</th>
              <th>Columns</th>
              <th>Nulls</th>
              <th>Duplicates</th>
              <th>Sample Confidence</th>
              <th>Issues</th>
            </tr>
          </thead>
          <tbody>
            {tables.map(([table, stats]) => (
              <tr key={table}>
                <td>{table}</td>
                <td>{stats.row_count}</td>
                <td>{stats.column_count}</td>
                <td>{stats.null_count}</td>
                <td>{stats.duplicate_count}</td>
                <td>{stats.sample_sufficiency?.status || "UNKNOWN"}</td>
                <td>{(stats.issues || []).join(", ") || "None"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {issues.length > 0 && (
        <>
          <h3>Quality Issues</h3>
          <div className="issue-list">
            {issues.map((issue, index) => (
              <article className="issue-item" key={`${issue.table}-${index}`}>
                <div className="insight-meta">
                  <strong>{issue.table || "Dataset"}</strong>
                  <RiskBadge mode="severity" value={issue.severity} />
                </div>
                <p>{issue.issue}</p>
              </article>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
