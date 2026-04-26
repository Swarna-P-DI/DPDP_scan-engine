import json
import os
from datetime import datetime
from typing import Any, Callable, Dict

from services.diff import compute_diff


HISTORY_DIR = "storage/monitoring"
SCHEDULE_PATH = os.path.join(HISTORY_DIR, "schedule.json")
os.makedirs(HISTORY_DIR, exist_ok=True)
_scheduler = None
_scheduled_job_id = "data_governance_scan"


def _history_path(scope: str) -> str:
    safe_scope = "".join(char if char.isalnum() or char in ("-", "_") else "_" for char in scope)
    return os.path.join(HISTORY_DIR, f"{safe_scope}.json")


def load_scan_history(scope: str = "default") -> Dict[str, Any]:
    path = _history_path(scope)
    if not os.path.exists(path):
        return {"scope": scope, "runs": []}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def record_scan_history(run_id: str, snapshot: Dict[str, Any], scope: str = "default") -> Dict[str, Any]:
    history = load_scan_history(scope)
    previous = history["runs"][-1]["snapshot"] if history["runs"] else None
    change_detection = compute_diff(snapshot, {"data": previous}) if previous else {"new_tables": [], "removed_tables": [], "score_delta": None}
    score = (snapshot.get("scores") or {}).get("final_score")
    risks = snapshot.get("risks") or []
    previous_risks = previous.get("risks", []) if previous else []
    previous_risk_ids = {risk.get("id") for risk in previous_risks}
    new_risks = [risk for risk in risks if risk.get("id") not in previous_risk_ids]
    previous_score = (previous.get("scores") or {}).get("final_score") if previous else None
    score_drop = round(float(previous_score) - float(score), 2) if previous_score is not None and score is not None else 0
    alerts = []
    if score_drop > 10:
        alerts.append({"type": "score_drop", "severity": "high", "message": f"Score dropped by {score_drop} points."})
    if any(str(risk.get("severity")).lower() in {"high", "critical"} for risk in new_risks):
        alerts.append({"type": "new_high_risk", "severity": "high", "message": "New HIGH/CRITICAL risks detected."})

    entry = {
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat(),
        "score": score,
        "issues_count": snapshot.get("issues_count", 0),
        "risks_count": len(risks),
        "snapshot": snapshot,
        "change_detection": change_detection,
        "new_risks": new_risks,
        "alerts": alerts,
    }
    history["runs"].append(entry)
    history["runs"] = history["runs"][-50:]
    with open(_history_path(scope), "w", encoding="utf-8") as handle:
        json.dump(history, handle, indent=2)
    return {
        "scope": scope,
        "run_count": len(history["runs"]),
        "latest_run_id": run_id,
        "change_detection": change_detection,
        "alerts": alerts,
    }


def scheduled_scan_descriptor(enabled: bool = True, interval_minutes: int = 1440) -> Dict[str, Any]:
    configured = get_schedule()
    return {
        "enabled": configured.get("enabled", enabled),
        "interval_minutes": configured.get("interval_minutes", interval_minutes),
        "mode": "apscheduler",
        "note": "APScheduler can trigger /scan-compatible jobs in-process when enabled.",
    }


def get_schedule() -> Dict[str, Any]:
    if not os.path.exists(SCHEDULE_PATH):
        return {"enabled": True, "interval_minutes": 1440}
    with open(SCHEDULE_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def set_schedule(enabled: bool = True, interval_minutes: int = 1440) -> Dict[str, Any]:
    payload = {"enabled": bool(enabled), "interval_minutes": int(interval_minutes)}
    with open(SCHEDULE_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return payload


def configure_scheduler(run_scan: Callable[[], Any], enabled: bool = True, interval_minutes: int = 1440) -> Dict[str, Any]:
    global _scheduler
    schedule = set_schedule(enabled, interval_minutes)
    if not enabled:
        if _scheduler:
            _scheduler.remove_all_jobs()
        return {**schedule, "scheduled": False}

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except Exception:
        return {**schedule, "scheduled": False, "warning": "APScheduler is not installed"}

    if _scheduler is None:
        _scheduler = BackgroundScheduler()
        _scheduler.start()

    if _scheduler.get_job(_scheduled_job_id):
        _scheduler.remove_job(_scheduled_job_id)
    _scheduler.add_job(run_scan, "interval", minutes=interval_minutes, id=_scheduled_job_id, replace_existing=True)
    return {**schedule, "scheduled": True}
