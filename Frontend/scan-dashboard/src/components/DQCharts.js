import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export default function DQCharts({ profiling, dq }) {
  const chartData = Object.entries(profiling || {}).map(([table, stats]) => ({
    table,
    nulls: stats.null_count || 0,
    duplicates: stats.duplicate_count || 0,
    rows: stats.row_count || 0,
    severity: stats.sample_sufficiency?.status === "INSUFFICIENT" ? "medium" : "low",
    uniqueSignals: Object.keys(stats.unique_counts || {}).length,
  }));

  if (chartData.length === 0) return null;

  return (
    <>
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Table Risk Comparison</h2>
            <p>Nulls and duplicates by table with sample-confidence overlays.</p>
          </div>
          <strong className="score-badge">{dq?.overall_score ?? "N/A"}</strong>
        </div>

        <div className="chart-frame">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="table" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Legend />
              <Bar dataKey="nulls" name="Null Cells" radius={[4, 4, 0, 0]}>
                {chartData.map((entry) => (
                  <Cell
                    fill={entry.severity === "medium" ? "#d18a1c" : "#2f7d5a"}
                    key={`${entry.table}-nulls`}
                  />
                ))}
              </Bar>
              <Bar dataKey="duplicates" name="Duplicate Rows" fill="#b64940" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Coverage Signals</h2>
            <p>Row volume, unique-signal breadth, and profile readiness across tables.</p>
          </div>
        </div>
        <div className="chart-frame">
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="table" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Legend />
              <Line dataKey="rows" name="Rows Sampled" stroke="#0f6c7a" strokeWidth={3} />
              <Line dataKey="uniqueSignals" name="Unique Count Signals" stroke="#7648a7" strokeWidth={3} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>
    </>
  );
}
