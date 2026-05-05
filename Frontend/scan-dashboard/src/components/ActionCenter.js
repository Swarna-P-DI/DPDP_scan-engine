import RiskBadge from "./RiskBadge";

const groups = [
  { key: "critical", label: "Critical Actions" },
  { key: "improvement", label: "Improvements" },
  { key: "observation", label: "Observations" },
];

export default function ActionCenter({ tasks, onUpdateTask, onInspectTask }) {
  const grouped = groups.map((group) => ({
    ...group,
    items: (tasks || []).filter((task) => task.group === group.key),
  }));

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>Action Workspace</h2>
          <p>Deduplicated governance tasks with owner, status, and priority controls.</p>
        </div>
      </div>

      {grouped.map((group) => (
        <div className="task-group" key={group.key}>
          <h3>{group.label}</h3>
          {group.items.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Task</th>
                    <th>Table</th>
                    <th>Column</th>
                    <th>Owner</th>
                    <th>Status</th>
                    <th>Priority</th>
                  </tr>
                </thead>
                <tbody>
                  {group.items.map((task) => (
                    <tr key={task.id} onClick={() => onInspectTask?.(task)}>
                      <td>{task.task}</td>
                      <td>{task.table || "scan-wide"}</td>
                      <td>{task.column || "N/A"}</td>
                      <td>{task.owner}</td>
                      <td>
                        <select
                          className="status-select"
                          onClick={(event) => event.stopPropagation()}
                          onChange={(event) => onUpdateTask?.(task.id, event.target.value)}
                          value={task.status}
                        >
                          <option value="OPEN">OPEN</option>
                          <option value="IN_PROGRESS">IN PROGRESS</option>
                          <option value="DONE">DONE</option>
                        </select>
                      </td>
                      <td>
                        <RiskBadge
                          mode="severity"
                          value={task.priority === "high" ? "high" : task.priority === "medium" ? "medium" : "low"}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted-copy">No tasks in this section yet.</p>
          )}
        </div>
      ))}
    </section>
  );
}
