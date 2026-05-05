import RiskBadge from "./RiskBadge";

export default function ColumnTable({ columns, selectedKey, onSelectColumn }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Column</th>
            <th>Type</th>
            <th>PII</th>
            <th>Masked</th>
            <th>Recommended Control</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {(columns || []).map((item) => {
            const key = `${item.table}.${item.column}`;
            return (
              <tr
                className={selectedKey === key ? "selected-row" : ""}
                key={key}
                onClick={() => onSelectColumn?.(item)}
              >
                <td>
                  <button className="table-link" type="button">
                    {item.column}
                  </button>
                </td>
                <td>{item.dataType}</td>
                <td>{item.piiDetected ? item.piiType : "No"}</td>
                <td>{item.maskingStatus.replaceAll("_", " ")}</td>
                <td>{item.recommendedMasking.replaceAll("_", " ")}</td>
                <td><RiskBadge value={item.risk} /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
