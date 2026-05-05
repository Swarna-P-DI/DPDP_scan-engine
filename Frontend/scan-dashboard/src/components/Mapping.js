import { useEffect, useMemo, useState } from "react";

import ActionButtons from "./ActionButtons";
import ColumnTable from "./ColumnTable";
import DrillDownPanel from "./DrillDownPanel";
import RiskBadge from "./RiskBadge";

export default function Mapping({ model, onCreateAction, initialFocus }) {
  const [selectedTable, setSelectedTable] = useState(initialFocus?.table || model.tables[0]?.table || "");
  const [selectedColumn, setSelectedColumn] = useState(null);

  useEffect(() => {
    if (initialFocus?.table) {
      setSelectedTable(initialFocus.table);
    } else if (model.tables[0]?.table) {
      setSelectedTable(model.tables[0].table);
    }
  }, [initialFocus, model.tables]);

  const tableColumns = useMemo(
    () => model.columns.filter((item) => item.table === selectedTable),
    [model.columns, selectedTable]
  );

  useEffect(() => {
    if (initialFocus?.column) {
      setSelectedColumn(
        tableColumns.find((item) => item.column === initialFocus.column) || tableColumns[0] || null
      );
    } else {
      setSelectedColumn(tableColumns[0] || null);
    }
  }, [initialFocus, tableColumns]);

  const relatedRecommendations = useMemo(() => {
    if (!selectedColumn) return [];
    const needle = `${selectedColumn.table}.${selectedColumn.column}`.toLowerCase();
    return model.recommendations.filter((item) => item.action.toLowerCase().includes(needle));
  }, [model.recommendations, selectedColumn]);

  return (
    <>
      <section className="panel panel-wide">
        <div className="panel-header">
          <div>
            <h2>Inventory And Column Intelligence</h2>
            <p>Structured metadata, sensitive-column status, and drill-down controls.</p>
          </div>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Table</th>
                <th>Owner</th>
                <th>Rows</th>
                <th>Columns</th>
                <th>PII</th>
                <th>Unmasked PII</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {model.tables.map((item) => (
                <tr
                  className={selectedTable === item.table ? "selected-row" : ""}
                  key={item.table}
                  onClick={() => setSelectedTable(item.table)}
                >
                  <td>
                    <button className="table-link" type="button">
                      {item.table}
                    </button>
                  </td>
                  <td>{item.owner}</td>
                  <td>{item.rowCount}</td>
                  <td>{item.columnCount}</td>
                  <td>{item.piiCount}</td>
                  <td>{item.unmaskedPiiCount}</td>
                  <td><RiskBadge value={item.risk} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel panel-wide">
        <div className="panel-header">
          <div>
            <h2>Column Risk Table</h2>
            <p>Click a column to inspect its profiling, evidence, and recommended control path.</p>
          </div>
        </div>
        <ColumnTable
          columns={tableColumns}
          onSelectColumn={setSelectedColumn}
          selectedKey={selectedColumn ? `${selectedColumn.table}.${selectedColumn.column}` : ""}
        />
        <ActionButtons
          compact
          context={{
            label: `Table: ${selectedTable}`,
            summary: `Review ownership, access, and masking posture for ${selectedTable}.`,
            severity: model.tables.find((item) => item.table === selectedTable)?.risk?.toLowerCase() || "medium",
            table: selectedTable,
            owner: model.tables.find((item) => item.table === selectedTable)?.owner,
            issueType: "table_review",
          }}
          onCreateAction={onCreateAction}
        />
      </section>

      <DrillDownPanel
        column={selectedColumn}
        onCreateAction={onCreateAction}
        relatedRecommendations={relatedRecommendations}
      />
    </>
  );
}
