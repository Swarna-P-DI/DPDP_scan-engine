import { useEffect, useMemo, useRef, useState } from "react";

const PLOTLY_CDN = "https://cdn.plot.ly/plotly-2.35.2.min.js";

const riskRank = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const riskColors = {
  LOW: "#fde047",
  MEDIUM: "#f59e0b",
  HIGH: "#ef4444",
};
const riskScale = [
  [0, "#fff7cc"],
  [1 / 3, riskColors.LOW],
  [2 / 3, riskColors.MEDIUM],
  [1, riskColors.HIGH],
];

const loadPlotly = () => {
  if (window.Plotly) return Promise.resolve(window.Plotly);
  const existing = document.querySelector(`script[src="${PLOTLY_CDN}"]`);
  if (existing) {
    return new Promise((resolve, reject) => {
      existing.addEventListener("load", () => resolve(window.Plotly));
      existing.addEventListener("error", reject);
    });
  }

  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = PLOTLY_CDN;
    script.async = true;
    script.onload = () => resolve(window.Plotly);
    script.onerror = reject;
    document.head.appendChild(script);
  });
};

const maskSample = (value) => {
  const text = String(value ?? "N/A");
  if (text === "N/A" || text.length <= 4) return text;
  const visible = Math.min(4, Math.max(1, Math.floor(text.length / 5)));
  return `${text.slice(0, visible)}${"*".repeat(Math.min(12, text.length - visible))}`;
};

const label = (value, fallback = "N/A") => {
  const text = String(value ?? "").trim();
  return text || fallback;
};

const truncateLabel = (value, maxLength = 30) => {
  const text = label(value);
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}...` : text;
};

const riskLevelFromScore = (score) => {
  if (Number(score) >= 3) return "HIGH";
  if (Number(score) >= 2) return "MEDIUM";
  if (Number(score) >= 1) return "LOW";
  return "LOW";
};

const riskReason = (selected) => {
  if (!selected) return "";
  const metadata = selected.metadata || {};
  const unprotected = Number(metadata.unprotected || 0);
  const encrypted = Number(metadata.encrypted || 0);
  const masked = Number(metadata.masked || 0);
  if (unprotected > 0 && encrypted === 0) {
    return `Unmasked ${selected.piiType} detected without confirmed encryption.`;
  }
  if (unprotected > 0) {
    return `Unmasked ${selected.piiType} detected in this source.`;
  }
  if (masked > 0 && encrypted === 0) {
    return `Masked ${selected.piiType} exists without confirmed encryption.`;
  }
  return `${selected.piiType} appears protected, but should remain monitored.`;
};

const buildMetadataIndex = (piiIndex = []) => {
  const index = new Map();
  piiIndex.forEach((entry) => {
    const source = label(entry.source_id || entry.table || entry.source, "unknown");
    const piiType = label(entry.pii_type || entry.piiType, "unknown");
    const key = `${source}|||${piiType}`;
    const current = index.get(key) || {};
    index.set(key, {
      ...current,
      ...entry,
      source_id: source,
      pii_type: piiType,
      sample_data: maskSample(entry.value_preview || entry.sample_data || entry.sample || current.sample_data),
    });
  });
  return index;
};

const buildHeatmapModel = (cells = [], piiIndex = []) => {
  const rows = [...new Set(cells.map((cell) => label(cell.source_id, "unknown")))].sort();
  const columns = [...new Set(cells.map((cell) => label(cell.pii_type, "unknown")))].sort();
  const metadataIndex = buildMetadataIndex(piiIndex);
  const cellIndex = new Map(cells.map((cell) => [`${label(cell.source_id, "unknown")}|||${label(cell.pii_type, "unknown")}`, cell]));

  const z = rows.map((row) =>
    columns.map((column) => {
      const cell = cellIndex.get(`${row}|||${column}`);
      return cell?.risk_score ?? 0;
    })
  );

  const customdata = rows.map((row) =>
    columns.map((column) => {
      const key = `${row}|||${column}`;
      const cell = cellIndex.get(key) || {};
      const metadata = metadataIndex.get(key) || {};
      const riskScore = cell.risk_score ?? 0;
      return {
        rowLabel: row,
        columnLabel: column,
        value: riskScore,
        datasetName: metadata.source_id || row,
        piiType: column,
        riskScore,
        riskLevel: cell.risk_level || "LOW",
        sampleData: metadata.sample_data || "N/A",
      metadata: {
        count: cell.count ?? 0,
        masked: cell.masked ?? 0,
        encrypted: cell.encrypted ?? 0,
        unprotected: cell.unprotected ?? 0,
        column: metadata.metadata?.column || metadata.column,
        table: metadata.source_id || row,
        location: metadata.location,
        source_type: metadata.source_type,
        hash: metadata.value_hash,
      },
      };
    })
  );

  return { rows, columns, z, customdata };
};

const applyHeatmapFilters = (model, { highOnly, piiType, sortSources }) => {
  let columnIndexes = model.columns.map((_, index) => index);
  if (piiType !== "ALL") {
    columnIndexes = columnIndexes.filter((index) => model.columns[index] === piiType);
  }

  let rows = model.rows.map((row, rowIndex) => ({
    row,
    rowIndex,
    maxRisk: Math.max(...columnIndexes.map((columnIndex) => model.z[rowIndex][columnIndex] || 0), 0),
  }));

  if (highOnly) {
    rows = rows.filter((item) => item.maxRisk >= 3);
  }

  if (sortSources) {
    rows = [...rows].sort((a, b) => b.maxRisk - a.maxRisk || a.row.localeCompare(b.row));
  }

  return {
    rows: rows.map((item) => item.row),
    columns: columnIndexes.map((index) => model.columns[index]),
    z: rows.map((item) => columnIndexes.map((columnIndex) => model.z[item.rowIndex][columnIndex])),
    customdata: rows.map((item) => columnIndexes.map((columnIndex) => model.customdata[item.rowIndex][columnIndex])),
  };
};

const selectionKey = (cell) => (
  cell ? `${cell.rowLabel}|||${cell.columnLabel}` : ""
);

const selectedCellOverlay = (visibleModel, selected) => {
  if (!selected) return null;
  return visibleModel.customdata.map((row) =>
    row.map((cell) => (
      selectionKey(cell) === selectionKey(selected) ? Number(cell.riskScore || 0) : null
    ))
  );
};

const selectedCellShape = (visibleModel, selected) => {
  if (!selected) return [];
  const columnIndex = visibleModel.columns.indexOf(selected.columnLabel);
  const rowIndex = visibleModel.rows.indexOf(selected.rowLabel);
  if (columnIndex < 0 || rowIndex < 0) return [];
  return [{
    type: "rect",
    xref: "x",
    yref: "y",
    x0: columnIndex - 0.5,
    x1: columnIndex + 0.5,
    y0: rowIndex - 0.5,
    y1: rowIndex + 0.5,
    line: {
      color: "#111827",
      width: 3,
    },
    fillcolor: "rgba(255, 255, 255, 0)",
    layer: "above",
  }];
};

function InfoMetric({ label: metricLabel, value }) {
  return (
    <div className="heatmap-info-metric">
      <span>{metricLabel}</span>
      <strong>{label(value)}</strong>
    </div>
  );
}

function InfoPanel({ selected }) {
  if (!selected) {
    return (
      <aside className="heatmap-info-card empty">
        <p className="heatmap-eyebrow">Data Similarity Heatmap</p>
        <h3>Select a cell</h3>
        <p className="muted-copy">Click any heatmap cell to inspect the row, column, risk score, PII type, sample preview, and metadata.</p>
      </aside>
    );
  }

  const metadata = selected.metadata || {};
  const riskLevel = selected.riskLevel || riskLevelFromScore(selected.riskScore);
  return (
    <aside className={`heatmap-info-card risk-panel-${riskLevel.toLowerCase()}`}>
      <p className="heatmap-eyebrow">Selected Cell</p>
      <h3>{selected.rowLabel} / {selected.columnLabel}</h3>
      <div className="heatmap-risk-strip">
        <span style={{ background: riskColors[riskLevel] }} />
        <strong>{riskLevel} Risk</strong>
      </div>
      <div className="heatmap-info-grid">
        <InfoMetric label="Source" value={selected.rowLabel} />
        <InfoMetric label="Table" value={metadata.table || selected.datasetName} />
        <InfoMetric label="Column" value={metadata.column || selected.columnLabel} />
        <InfoMetric label="PII Type" value={selected.piiType} />
        <InfoMetric label="Risk Score" value={selected.riskScore} />
        <InfoMetric label="Masked / Encrypted" value={`${metadata.masked ?? 0} masked / ${metadata.encrypted ?? 0} encrypted`} />
        <InfoMetric label="Count" value={metadata.count ?? 0} />
      </div>
      <div className="heatmap-risk-reason">
        <span>Why is this risky?</span>
        <p>{riskReason(selected)}</p>
      </div>
      <h4>Metadata</h4>
      <div className="heatmap-info-grid">
        {Object.entries(metadata).filter(([, value]) => value !== undefined && value !== "").map(([key, value]) => (
          <InfoMetric key={key} label={key.replaceAll("_", " ")} value={value} />
        ))}
      </div>
    </aside>
  );
}

export default function InteractiveHeatmap({ cells = [], piiIndex = [] }) {
  const chartRef = useRef(null);
  const [selected, setSelected] = useState(null);
  const [plotlyError, setPlotlyError] = useState("");
  const [highOnly, setHighOnly] = useState(false);
  const [sortSources, setSortSources] = useState(true);
  const [showLabels, setShowLabels] = useState(true);
  const [labelMode, setLabelMode] = useState("risk");
  const [piiType, setPiiType] = useState("ALL");
  const model = useMemo(() => buildHeatmapModel(cells, piiIndex), [cells, piiIndex]);
  const piiTypes = useMemo(() => model.columns, [model.columns]);
  const visibleModel = useMemo(
    () => applyHeatmapFilters(model, { highOnly, piiType, sortSources }),
    [model, highOnly, piiType, sortSources]
  );

  useEffect(() => {
    let cancelled = false;
    if (!chartRef.current || !visibleModel.rows.length || !visibleModel.columns.length) return undefined;

    loadPlotly()
      .then((Plotly) => {
        if (cancelled) return;
        const selectedZ = selectedCellOverlay(visibleModel, selected);

        Plotly.react(
          chartRef.current,
          [
            {
              type: "heatmap",
              x: visibleModel.columns,
              y: visibleModel.rows,
              z: visibleModel.z,
              customdata: visibleModel.customdata,
              hovertext: visibleModel.customdata.map((row) =>
                row.map((cell) =>
                  [
                    `<b>Source:</b> ${cell.rowLabel}`,
                    `<b>PII type:</b> ${cell.piiType}`,
                    `<b>Risk level:</b> ${cell.riskLevel}`,
                    `<b>Risk score:</b> ${cell.riskScore}`,
                    `<b>Count:</b> ${cell.metadata.count}`,
                    `<b>Masked / Unmasked:</b> ${cell.metadata.masked} / ${cell.metadata.unprotected}`,
                    `<b>Encrypted:</b> ${cell.metadata.encrypted}`,
                  ].join("<br>")
                )
              ),
              text: visibleModel.customdata.map((row) =>
                row.map((cell) => String(labelMode === "count" ? cell.metadata.count ?? 0 : cell.riskScore || ""))
              ),
              texttemplate: showLabels ? "%{text}" : "",
              textfont: { color: "#111827", size: 12 },
              colorscale: riskScale,
              zmin: 0,
              zmax: 3,
              xgap: 1,
              ygap: 1,
              colorbar: {
                title: "Risk Score",
                tickmode: "array",
                tickvals: [1, 2, 3],
                ticktext: ["Low", "Medium", "High"],
              },
              hovertemplate: "%{hovertext}<extra></extra>",
            },
            ...(selectedZ ? [{
              type: "heatmap",
              x: visibleModel.columns,
              y: visibleModel.rows,
              z: selectedZ,
              colorscale: riskScale,
              zmin: 0,
              zmax: 3,
              xgap: 0,
              ygap: 0,
              opacity: 0.98,
              showscale: false,
              hoverinfo: "skip",
            }] : []),
          ],
          {
            title: { text: "Data Similarity Heatmap", x: 0.02, xanchor: "left" },
            autosize: true,
            margin: { l: 120, r: 30, t: 74, b: 120 },
            paper_bgcolor: "#fbfcfd",
            plot_bgcolor: "#fbfcfd",
            font: { family: "Aptos, Segoe UI, sans-serif", color: "#162635" },
            dragmode: "zoom",
            xaxis: {
              title: "PII Types",
              tickangle: -35,
              automargin: true,
              tickmode: "array",
              tickvals: visibleModel.columns,
              ticktext: visibleModel.columns.map((item) => truncateLabel(item, 18)),
            },
            yaxis: {
              title: "Data Sources",
              automargin: true,
              autorange: "reversed",
              tickmode: "array",
              tickvals: visibleModel.rows,
              ticktext: visibleModel.rows.map((item) => truncateLabel(item, 32)),
            },
            shapes: selectedCellShape(visibleModel, selected),
          },
          {
            displaylogo: false,
            responsive: true,
            scrollZoom: true,
            modeBarButtonsToRemove: ["lasso2d", "select2d"],
          }
        );

        chartRef.current.removeAllListeners?.("plotly_click");
        chartRef.current.on("plotly_click", (event) => {
          const point = event?.points?.[0];
          if (!point?.customdata) return;
          setSelected((current) => (
            selectionKey(current) === selectionKey(point.customdata) ? null : point.customdata
          ));
        });

        setPlotlyError("");
      })
      .catch(() => setPlotlyError("Plotly could not be loaded. Check network access or bundle Plotly with the dashboard."));

    return () => {
      cancelled = true;
    };
  }, [visibleModel, selected, showLabels, labelMode]);

  if (!cells.length) {
    return <p className="muted-copy">No heatmap cells returned yet. Run or refresh a scan with PII findings.</p>;
  }

  return (
    <div className="interactive-heatmap">
      <div className="heatmap-toolbar">
        <div className="heatmap-control-group">
          <label>
            <input checked={highOnly} onChange={(event) => setHighOnly(event.target.checked)} type="checkbox" />
            Show only HIGH risk
          </label>
          <label>
            <input checked={sortSources} onChange={(event) => setSortSources(event.target.checked)} type="checkbox" />
            Sort sources by highest risk
          </label>
          <label>
            <input checked={showLabels} onChange={(event) => setShowLabels(event.target.checked)} type="checkbox" />
            Show cell labels
          </label>
        </div>
        <div className="heatmap-control-group">
          <select aria-label="Filter by PII type" onChange={(event) => setPiiType(event.target.value)} value={piiType}>
            <option value="ALL">All PII types</option>
            {piiTypes.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <select aria-label="Cell label mode" onChange={(event) => setLabelMode(event.target.value)} value={labelMode}>
            <option value="risk">Risk score</option>
            <option value="count">Count</option>
          </select>
        </div>
      </div>
      <div className="heatmap-legend" aria-label="Risk legend">
        <span><i style={{ background: riskColors.LOW }} /> Low Risk</span>
        <span><i style={{ background: riskColors.MEDIUM }} /> Medium Risk</span>
        <span><i style={{ background: riskColors.HIGH }} /> High Risk</span>
      </div>
      <div className="interactive-heatmap-layout">
        <div className="interactive-heatmap-chart">
          {plotlyError ? <p className="muted-copy">{plotlyError}</p> : <div ref={chartRef} className="plotly-heatmap" />}
          {!visibleModel.rows.length && <p className="muted-copy heatmap-empty-overlay">No cells match the current filters.</p>}
        </div>
        <InfoPanel selected={selected} />
      </div>
    </div>
  );
}
