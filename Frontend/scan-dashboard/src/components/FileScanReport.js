import RiskBadge from "./RiskBadge";
import SummaryCard from "./SummaryCard";

const formatMs = (value) => `${Number(value || 0).toFixed(4)} ms`;

function EmptyPanel({ label }) {
  return <p className="muted-copy">No {label} returned for this file scan.</p>;
}

function FileScanOverview({ data }) {
  const summary = data?.summary || {};
  const heatmap = data?.risk_heatmap || {};
  const latency = data?.latency_stats || {};

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>File Scan Summary</h2>
          <p>{data?.metadata?.file || "Uploaded file"} scanned with the SCAN + RAID PII intelligence engine.</p>
        </div>
        <RiskBadge value={heatmap.high ? "HIGH" : heatmap.medium ? "MEDIUM" : "LOW"} />
      </div>

      <div className="summary-grid hierarchy-grid">
        <SummaryCard label="Findings" value={summary.findings ?? 0} helper="Detected PII values across the uploaded file." tone="neutral" />
        <SummaryCard label="High Risk" value={summary.high_risk_findings ?? 0} helper="Aadhaar and PAN findings." tone="danger" />
        <SummaryCard label="Medium Risk" value={summary.medium_risk_findings ?? 0} helper="Phone and email findings." tone="warning" />
        <SummaryCard label="Latency Target" value={latency.within_target ? "Met" : "Review"} helper={`Max ${formatMs(latency.max_ms)} against 1 ms target.`} tone="accent" />
      </div>

      <div className="diagnostic-band">
        <div className="diagnostic-card">
          <span>File Type</span>
          <strong>{data?.metadata?.file_type || "N/A"}</strong>
          <p>CSV, JSON, and PDF uploads are supported.</p>
        </div>
        <div className="diagnostic-card">
          <span>Table Level Heatmap</span>
          <strong>{heatmap.table_level?.high ?? 0} high</strong>
          <p>{heatmap.table_level?.medium ?? 0} medium and {heatmap.table_level?.low ?? 0} low-risk columns.</p>
        </div>
        <div className="diagnostic-card">
          <span>Dataset Heatmap</span>
          <strong>{heatmap.high ?? 0} high</strong>
          <p>{heatmap.medium ?? 0} medium and {heatmap.low ?? 0} low-risk detections.</p>
        </div>
      </div>
    </section>
  );
}

function FileProfiling({ data }) {
  const profiling = data?.profiling || {};
  const columns = Object.entries(profiling.columns || {});

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>Structured Profiling</h2>
          <p>Null percentage, uniqueness, type inference, and basic column statistics from the uploaded file.</p>
        </div>
        <strong className="score-badge">{profiling.row_count ?? 0}</strong>
      </div>

      {columns.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Column</th>
                <th>Null %</th>
                <th>Unique %</th>
                <th>Inferred Type</th>
                <th>Non Null</th>
                <th>Statistics</th>
              </tr>
            </thead>
            <tbody>
              {columns.map(([column, stats]) => (
                <tr key={column}>
                  <td>{column}</td>
                  <td>{stats.null_pct}</td>
                  <td>{stats.unique_pct}</td>
                  <td>{stats.inferred_type}</td>
                  <td>{stats.non_null_count}</td>
                  <td>
                    {stats.numeric
                      ? `min ${stats.numeric.min}, max ${stats.numeric.max}, mean ${stats.numeric.mean}`
                      : `length ${stats.text?.min_length ?? 0}-${stats.text?.max_length ?? 0}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyPanel label="structured profiling columns" />
      )}
    </section>
  );
}

function PiiFindings({ data }) {
  const findings = data?.pii_findings || [];
  const columnRisks = data?.column_risks || [];

  return (
    <>
      <section className="panel panel-wide">
        <div className="panel-header">
          <div>
            <h2>PII Findings</h2>
            <p>Detected entities with method, confidence, source, row/page, and measured latency.</p>
          </div>
        </div>

        {findings.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Entity</th>
                  <th>Value</th>
                  <th>Method</th>
                  <th>Confidence</th>
                  <th>Source</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((item, index) => (
                  <tr key={`${item.type}-${item.value}-${index}`}>
                    <td>{item.type}</td>
                    <td>{item.value}</td>
                    <td>{item.method}</td>
                    <td>{Math.round(Number(item.confidence || 0) * 100)}%</td>
                    <td>
                      {item.source?.file}
                      {item.source?.column ? ` / ${item.source.column}` : ""}
                      {item.source?.row !== undefined ? ` / row ${item.source.row}` : ""}
                      {item.source?.page !== undefined ? ` / page ${item.source.page}` : ""}
                    </td>
                    <td>{formatMs(item.latency_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyPanel label="PII findings" />
        )}
      </section>

      <section className="panel panel-wide">
        <div className="panel-header">
          <div>
            <h2>Column Risk Classification</h2>
            <p>Column-level risk derived from the detected PII entity types.</p>
          </div>
        </div>

        {columnRisks.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>File</th>
                  <th>Column</th>
                  <th>PII Detected</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {columnRisks.map((item) => (
                  <tr key={`${item.file}-${item.column}`}>
                    <td>{item.file}</td>
                    <td>{item.column}</td>
                    <td>{(item.pii_detected || []).join(", ")}</td>
                    <td><RiskBadge value={item.risk} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyPanel label="column risks" />
        )}
      </section>
    </>
  );
}

function FileRaid({ data }) {
  const raid = data?.raid || {};
  const sections = [
    ["Risks", raid.risks, "risk"],
    ["Issues", raid.issues, "issue"],
    ["Assumptions", raid.assumptions, "description"],
    ["Dependencies", raid.dependencies, "description"],
    ["Recommendations", raid.recommendations, "recommendation"],
  ];

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>RayIN : RAID Master</h2>
          <p>Rule-based risks, assumptions, issues, dependencies, and recommendations for the uploaded file.</p>
        </div>
      </div>

      {sections.map(([title, items = [], primary]) => (
        <details className="report-section" open key={title}>
          <summary>{title}</summary>
          <div className="report-section-body issue-list">
            {items.length ? items.map((item, index) => (
              <article className="issue-item" key={`${title}-${index}`}>
                <div className="insight-meta">
                  <strong>{item[primary] || item.description || title}</strong>
                  {item.severity || item.priority ? <RiskBadge mode="severity" value={item.severity || item.priority} /> : null}
                </div>
                {item.validation_needed ? <p>{item.validation_needed}</p> : null}
                {item.owner ? <span>{item.owner}</span> : null}
              </article>
            )) : <EmptyPanel label={title.toLowerCase()} />}
          </div>
        </details>
      ))}
    </section>
  );
}

function FileReportJson({ data }) {
  const latency = data?.latency_stats || {};

  return (
    <>
      <section className="panel panel-wide">
        <div className="panel-header">
          <div>
            <h2>Latency Records</h2>
            <p>Per-detection timing captured by the backend scanner.</p>
          </div>
          <strong className="score-badge">{formatMs(latency.avg_ms)}</strong>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Entity</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              {(latency.records || []).map((item, index) => (
                <tr key={`${item.entity}-${index}`}>
                  <td>{item.entity}</td>
                  <td>{formatMs(item.latency_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel panel-wide">
        <div className="panel-header">
          <div>
            <h2>PDF-Ready JSON</h2>
            <p>Full structured report returned by the SCAN + RAID endpoint.</p>
          </div>
        </div>
        <pre className="json-preview">{JSON.stringify(data, null, 2)}</pre>
      </section>
    </>
  );
}

export default function FileScanReport({ data, section }) {
  if (section === "quality") return <FileProfiling data={data} />;
  if (section === "gaps") return <PiiFindings data={data} />;
  if (section === "raid") return <FileRaid data={data} />;
  if (section === "report") return <FileReportJson data={data} />;
  return <FileScanOverview data={data} />;
}
