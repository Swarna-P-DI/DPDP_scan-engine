import json
import os
from datetime import datetime
from typing import Any, Dict, List


TASKS_PATH = "storage/tasks.json"
os.makedirs(os.path.dirname(TASKS_PATH), exist_ok=True)


def _load() -> Dict[str, Any]:
    if not os.path.exists(TASKS_PATH):
        return {"tasks": []}
    with open(TASKS_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _save(payload: Dict[str, Any]) -> None:
    with open(TASKS_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def create_tasks(tasks: List[Dict[str, Any]]) -> Dict[str, Any]:
    payload = _load()
    existing = {task.get("task_id"): task for task in payload.get("tasks", [])}
    created = []
    for task in tasks:
        if not task.get("task_id"):
            continue
        record = dict(task)
        record.setdefault("status", "OPEN")
        record["updated_at"] = datetime.utcnow().isoformat()
        existing[record["task_id"]] = record
        created.append(record)
    payload["tasks"] = list(existing.values())
    _save(payload)
    return {"created": len(created), "tasks": created}


def update_task(task_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    payload = _load()
    for task in payload.get("tasks", []):
        if task.get("task_id") == task_id:
            task.update({key: value for key, value in updates.items() if value is not None})
            task["updated_at"] = datetime.utcnow().isoformat()
            _save(payload)
            return {"updated": True, "task": task}
    return {"updated": False, "task": None}


def list_tasks() -> Dict[str, Any]:
    return _load()
