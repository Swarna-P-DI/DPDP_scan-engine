import json
import os
from datetime import datetime
import uuid

RUNS_DIR = "storage/runs"

os.makedirs(RUNS_DIR, exist_ok=True)

def save_run(data, run_id=None):
    run_id = run_id or str(uuid.uuid4())

    payload = {
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat(),
        "data": data
    }

    with open(f"{RUNS_DIR}/{run_id}.json", "w") as f:
        json.dump(payload, f, indent=2)

    return run_id


def get_latest_run():
    files = sorted(os.listdir(RUNS_DIR))
    if not files:
        return None

    latest = files[-1]

    with open(f"{RUNS_DIR}/{latest}") as f:
        return json.load(f)
