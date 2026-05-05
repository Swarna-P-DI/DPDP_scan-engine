import { useMemo, useState } from "react";
import InteractiveHeatmap from "./InteractiveHeatmap";
import RiskBadge from "./RiskBadge";

const clampText = (value, fallback = "N/A") => {
  const text = String(value ?? "").trim();
  return text || fallback;
};

const getRaidText = (item) =>
  item?.risk || item?.issue || item?.description || item?.recommendation || item?.action || "Entry";

const statusClass = (status) => {
  const value = complianceRisk(status).toLowerCase();
  if (value === "high") return "risk-high";
  if (value === "medium") return "risk-medium";
  return "risk-low";
};

const complianceRisk = (status) => {
  const value = String(status || "").toUpperCase();
  if (value === "VIOLATION") return "HIGH";
  if (value === "RISK") return "MEDIUM";
  return "LOW";
};

const riskForSeverity = (value) => {
  const lowered = String(value || "").toLowerCase();
  if (lowered.includes("high") || lowered.includes("critical")) return "HIGH";
  if (lowered.includes("medium")) return "MEDIUM";
  return "LOW";
};

function MiniTable({ columns, rows, emptyLabel = "No records returned." }) {
  if (!rows?.length) return <p className="muted-copy">{emptyLabel}</p>;
  return (
    <div className="table-wrap compact-table">
      <table>
        <thead>
          <tr>
            {columns.map((column) => <th key={column.key}>{column.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={row.id || rowIndex}>
              {columns.map((column) => (
                <td key={column.key}>{column.render ? column.render(row) : clampText(row[column.key])}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function JsonPanel({ data }) {
  return <pre className="json-preview compact-json">{JSON.stringify(data || {}, null, 2)}</pre>;
}

function JsonScalar({ value }) {
  const type = value === null ? "null" : typeof value;
  return <span className={`json-token json-${type}`}>{JSON.stringify(value)}</span>;
}

function JsonTree({ data, label = "report", level = 0 }) {
  if (data === null || typeof data !== "object") return <JsonScalar value={data} />;
  const entries = Array.isArray(data) ? data.map((value, index) => [index, value]) : Object.entries(data);
  return (
    <details className="json-tree-node" open={level < 1}>
      <summary>
        <span className="json-key">{label}</span>
        <span className="json-count">{Array.isArray(data) ? `${data.length} item(s)` : `${entries.length} field(s)`}</span>
      </summary>
      <div className="json-tree-children">
        {entries.map(([key, value]) => (
          <div className="json-tree-row" key={key}>
            <span className="json-key">{key}</span>
            <span className="json-separator">:</span>
            {value !== null && typeof value === "object" ? (
              <JsonTree data={value} label={Array.isArray(value) ? "array" : "object"} level={level + 1} />
            ) : (
              <JsonScalar value={value} />
            )}
          </div>
        ))}
      </div>
    </details>
  );
}

function downloadJson(data) {
  const blob = new Blob([JSON.stringify(data || {}, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `intelligence-report-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function ReportView({ report }) {
  const [mode, setMode] = useState("formatted");
  const reportPayload = useMemo(() => ({
    ...report,
    heatmap: report?.risk_heatmap,
  }), [report]);

  return (
    <div className="report-viewer">
      <div className="report-toolbar">
        <div className="segmented-control inline-segments">
          <button className={mode === "formatted" ? "active" : ""} onClick={() => setMode("formatted")} type="button">Formatted View</button>
          <button className={mode === "json" ? "active" : ""} onClick={() => setMode("json")} type="button">JSON View</button>
        </div>
        <button className="ghost-action" onClick={() => downloadJson(reportPayload)} type="button">Download JSON</button>
      </div>
      {mode === "formatted" ? (
        <div className="report-document">
          <section>
            <h3>Metadata</h3>
            <JsonTree data={reportPayload.metadata || {}} label="metadata" />
          </section>
          <section>
            <h3>PII Summary</h3>
            <JsonTree data={reportPayload.pii_summary || {}} label="pii_summary" />
          </section>
          <section>
            <h3>RayIN : RAID Master</h3>
            <RaidStructuredView raid={reportPayload.raid || {}} compact />
          </section>
          <section>
            <h3>Compliance Status</h3>
            <JsonTree data={reportPayload.compliance_status || []} label="compliance_status" />
          </section>
          <section>
            <h3>Heatmap</h3>
            <JsonTree data={reportPayload.heatmap || {}} label="heatmap" />
          </section>
          <section>
            <h3>Data Intelligence</h3>
            <JsonTree data={reportPayload.data_intelligence || {}} label="data_intelligence" />
          </section>
          <section>
            <h3>PII Index</h3>
            <JsonTree data={reportPayload.pii_index || []} label="pii_index" />
          </section>
        </div>
      ) : (
        <div className="json-document">
          <JsonTree data={reportPayload} label="report" />
        </div>
      )}
    </div>
  );
}

function RaidItem({ item, section }) {
  const text = getRaidText(item);
  const severity = item?.severity || item?.priority || "";
  return (
    <li className="raid-list-item">
      <div>
        <p>{text}</p>
        <span>{clampText(item?.source_id || item?.location || item?.owner || item?.status, "No source attached")}</span>
      </div>
      {section === "risks" && <RiskBadge value={riskForSeverity(severity)} />}
    </li>
  );
}

function RaidStructuredView({ raid, compact = false, dense = false }) {
  const [activeSection, setActiveSection] = useState("risks");
  const sections = [
    ["risks", "Risks"],
    ["issues", "Issues"],
    ["assumptions", "Assumptions"],
    ["dependencies", "Dependencies"],
    ["recommendations", "Recommendations"],
  ];

  if (dense) {
    const activeItems = raid?.[activeSection] || [];
    const activeTitle = sections.find(([key]) => key === activeSection)?.[1] || "Risks";
    return (
      <div className="rayin-workbench">
        <div className="rayin-section-tabs">
          {sections.map(([key, title]) => {
            const count = (raid?.[key] || []).length;
            return (
              <button className={activeSection === key ? "active" : ""} key={key} onClick={() => setActiveSection(key)} type="button">
                <span>{title}</span>
                <strong>{count}</strong>
              </button>
            );
          })}
        </div>
        <section className="rayin-detail-panel">
          <div className="rayin-detail-header">
            <div>
              <p className="eyebrow">RayIN : RAID Master</p>
              <h3>{activeTitle}</h3>
            </div>
            <span className="action-required-badge">{activeItems.length} item(s)</span>
          </div>
          {activeItems.length ? (
            <ul className="rayin-detail-list">
              {activeItems.map((item, index) => <RaidItem item={item} key={`${activeSection}-${index}`} section={activeSection} />)}
            </ul>
          ) : (
            <p className="muted-copy">No {activeTitle.toLowerCase()} recorded.</p>
          )}
        </section>
      </div>
    );
  }

  return (
    <div className={`${compact ? "raid-section-grid compact-raid" : "raid-section-grid"} ${dense ? "dense-raid" : ""}`}>
      {sections.map(([key, title]) => {
        const items = raid?.[key] || [];
        return (
          <section className="raid-section-card" key={key}>
            <div className="raid-section-header">
              <h3>{title}</h3>
              <span>{items.length}</span>
            </div>
            {items.length ? (
              <ul className="raid-list">
                {items.map((item, index) => <RaidItem item={item} key={`${key}-${index}`} section={key} />)}
              </ul>
            ) : (
              <p className="muted-copy">No {title.toLowerCase()} recorded.</p>
            )}
          </section>
        );
      })}
    </div>
  );
}

export default function CoreIntelligence({
  report,
  logs,
  searchQuery,
  searchResult,
  summaryPrompt,
  summaryResult,
  onSearchQueryChange,
  onSearch,
  onSummaryPromptChange,
  onSummarize,
}) {
  const [view, setView] = useState("operations");
  const summary = report?.summary || {};
  const piiSummary = report?.pii_summary || {};
  const intelligence = report?.data_intelligence || {};
  const raid = report?.raid || {};
  const compliance = report?.compliance_status || [];
  const heatmapCells = report?.risk_heatmap?.source_vs_pii?.cells || [];
  const piiIndex = report?.pii_index || [];
  const metadata = report?.metadata || {};

  const searchRows = useMemo(
    () => (searchResult?.groups || []).flatMap((group) =>
      (group.records || []).map((record, index) => ({
        id: `${group.identity_key}-${index}`,
        identity: group.identity_key,
        rank: group.rank,
        ...record,
      }))
    ),
    [searchResult]
  );

  return (
    <>
      <section className="panel panel-wide intelligence-hero">
        <div className="panel-header compact-header">
          <div>
            <h2>Core RayIN Intelligence</h2>
            <p>Backend scan outputs, metadata inventory, PII index, compliance, search, logs, and reports.</p>
          </div>
          <span className="action-required-badge">{summary.status || "latest scan outputs"}</span>
        </div>

        <div className="summary-grid compact-summary">
          <div className="summary-card tone-neutral">
            <span>Run</span>
            <strong>{clampText(metadata.run_id || metadata.source, "latest")}</strong>
            <p>{clampText(metadata.engine, "Core backend intelligence")}</p>
          </div>
          <div className="summary-card tone-danger">
            <span>PII Indexed</span>
            <strong>{piiSummary.total ?? piiIndex.length ?? 0}</strong>
            <p>{Object.entries(piiSummary.by_type || {}).map(([key, value]) => `${key}: ${value}`).join(" | ") || "No PII indexed"}</p>
          </div>
          <div className="summary-card tone-warning">
            <span>Exposure</span>
            <strong>{piiSummary.exposure?.unprotected ?? 0}</strong>
            <p>{piiSummary.exposure?.masked ?? 0} masked, {piiSummary.exposure?.encrypted ?? 0} encrypted.</p>
          </div>
          <div className="summary-card tone-accent">
            <span>Compliance</span>
            <strong>{compliance.filter((item) => item.compliance_status === "VIOLATION").length}</strong>
            <p>{compliance.length} source-level compliance records.</p>
          </div>
        </div>

        <div className="stat-chip-row compact-chip-row">
          <span className="stat-chip">What: {(intelligence.what || []).join(", ") || "None"}</span>
          <span className="stat-chip">Where: {(intelligence.where || []).slice(0, 3).join(", ") || "None"}</span>
          <span className="stat-chip">How: {(intelligence.how || []).join(", ") || "None"}</span>
        </div>
      </section>

      <section className="panel panel-wide compact-workbench">
        <div className="segmented-control sticky-segments">
          {[
            ["operations", "Operations"],
            ["search", "Search"],
            ["compliance", "Compliance"],
            ["heatmap", "Heatmap"],
            ["raid", "RayIN : RAID Master"],
            ["logs", "Logs"],
            ["report", "Report"],
          ].map(([id, label]) => (
            <button className={view === id ? "active" : ""} key={id} onClick={() => setView(id)} type="button">
              {label}
            </button>
          ))}
        </div>

        {view === "operations" && (
          <div className="compact-grid-2">
            <div>
              <h3>PII Location Index</h3>
              <MiniTable
                columns={[
                  { key: "pii_type", label: "Type" },
                  { key: "source_id", label: "Source" },
                  { key: "location", label: "Location" },
                  { key: "masked", label: "Masked", render: (row) => row.masked ? "Yes" : "No" },
                  { key: "encrypted", label: "Encrypted", render: (row) => row.encrypted ? "Yes" : "No" },
                ]}
                rows={piiIndex.slice(0, 50)}
              />
            </div>
            <div>
              <h3>PII Summary</h3>
              <JsonPanel data={{ pii_summary: piiSummary, data_intelligence: intelligence }} />
            </div>
          </div>
        )}

        {view === "search" && (
          <div className="compact-grid-2">
            <div>
              <h3>Federated Search</h3>
              <div className="query-row">
                <input
                  className="query-input"
                  onChange={(event) => onSearchQueryChange(event.target.value)}
                  onKeyDown={(event) => event.key === "Enter" && onSearch()}
                  placeholder="Name + Aadhaar, PAN, IFSC, email"
                  value={searchQuery}
                />
                <button className="primary-action" onClick={onSearch} type="button">Search</button>
              </div>
              <p className="muted-copy">{searchResult ? `${searchResult.total_matches || 0} matching indexed record(s).` : "Search uses the backend PII index."}</p>
              <MiniTable
                columns={[
                  { key: "pii_type", label: "Type" },
                  { key: "source_id", label: "Source" },
                  { key: "location", label: "Location" },
                  {
                    key: "rank",
                    label: (
                      <span className="rank-header">
                        Rank
                        <span className="info-tooltip" tabIndex="0">i
                          <span className="tooltip-panel">
                            Rank represents relevance score of the result based on PII match strength, number of matching attributes, cross-source correlation, and data confidence.
                          </span>
                        </span>
                      </span>
                    ),
                  },
                ]}
                rows={searchRows}
                emptyLabel="No search results yet."
              />
            </div>
            <div>
              <h3>Grouped Results</h3>
              <JsonPanel data={searchResult || { query: searchQuery, groups: [] }} />
            </div>
          </div>
        )}

        {view === "compliance" && (
          <MiniTable
            columns={[
              { key: "source_id", label: "Source" },
              { key: "compliance_status", label: "Risk", render: (row) => <span className={`risk-badge ${statusClass(row.compliance_status)}`}>{complianceRisk(row.compliance_status)} risk</span> },
              { key: "issues", label: "Issues", render: (row) => (row.issues || []).slice(0, 3).join(" | ") },
              { key: "recommendations", label: "Recommendations", render: (row) => (row.recommendations || []).slice(0, 2).join(" | ") },
            ]}
            rows={compliance}
          />
        )}

        {view === "heatmap" && (
          <InteractiveHeatmap cells={heatmapCells} piiIndex={piiIndex} />
        )}

        {view === "raid" && (
          <RaidStructuredView dense raid={raid} />
        )}

        {view === "logs" && (
          <div className="compact-grid-2">
            <div>
              <h3>Summarize Logs</h3>
              <div className="query-row">
                <input
                  className="query-input"
                  onChange={(event) => onSummaryPromptChange(event.target.value)}
                  onKeyDown={(event) => event.key === "Enter" && onSummarize()}
                  placeholder="Summarize high-risk PII exposures"
                  value={summaryPrompt}
                />
                <button className="primary-action" onClick={onSummarize} type="button">Summarize</button>
              </div>
              <JsonPanel data={summaryResult || { prompt: summaryPrompt }} />
            </div>
            <div>
              <h3>Trace Events</h3>
              <MiniTable
                columns={[
                  { key: "timestamp", label: "Time" },
                  { key: "event", label: "Event" },
                  { key: "source", label: "Source" },
                  { key: "action", label: "Action" },
                  { key: "status", label: "Status" },
                ]}
                rows={(logs || []).slice(-50).reverse()}
                emptyLabel="No trace events yet."
              />
            </div>
          </div>
        )}

        {view === "report" && <ReportView report={report} />}
      </section>
    </>
  );
}
