import os

from fastapi import FastAPI
from fastapi import HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.job_manager import get_result, get_status, start_job
from backend.main import graph
from backend.services.monitoring import configure_scheduler, load_scan_history
from backend.services.report_engine import generate_export
from backend.services.task_store import create_tasks, list_tasks, update_task

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3002",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/storage", StaticFiles(directory="storage"), name="storage")


class ScheduleRequest(BaseModel):
    enabled: bool = True
    interval_minutes: int = 1440


class TaskUpdateRequest(BaseModel):
    status: str | None = None
    owner: str | None = None
    due_date: str | None = None
    action: str | None = None


class TaskCreateRequest(BaseModel):
    tasks: list[dict]


@app.get("/")
def home():
    return {"message": "Data-only scan API running (async mode)"}


@app.get("/scan")
def run_scan_get():
    job_id = start_job(graph)
    return {
        "job_id": job_id,
        "status": "started"
    }


@app.get("/status/{job_id}")
def check_status(job_id: str):
    return get_status(job_id)


@app.get("/result/{job_id}")
def fetch_result(job_id: str):
    return get_result(job_id)


@app.get("/monitoring/history")
def monitoring_history(scope: str = "default"):
    return load_scan_history(scope)


@app.post("/scan/schedule")
def scan_schedule(payload: ScheduleRequest):
    return configure_scheduler(lambda: start_job(graph), payload.enabled, payload.interval_minutes)


@app.get("/scan/history")
def scan_history(scope: str = "default"):
    return load_scan_history(scope)


@app.post("/tasks/create")
def tasks_create(payload: TaskCreateRequest):
    return create_tasks(payload.tasks)


@app.post("/tasks/update/{task_id}")
def tasks_update(task_id: str, payload: TaskUpdateRequest):
    updates = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
    result = update_task(task_id, updates)
    if not result["updated"]:
        raise HTTPException(status_code=404, detail="Task not found")
    return result


@app.get("/tasks")
def tasks_list():
    return list_tasks()


@app.get("/exports/{job_id}/{format_name}")
def download_export(job_id: str, format_name: str):
    status_payload = get_status(job_id)
    if status_payload.get("status") == "not_found":
        raise HTTPException(status_code=404, detail="Job not found")
    if status_payload.get("status") != "completed" or not status_payload.get("result"):
        raise HTTPException(status_code=409, detail="Report is not ready for export")

    format_map = {
        "json": "json",
        "pdf": "pdf",
        "ppt": "pptx",
        "pptx": "pptx",
        "doc": "docx",
        "docx": "docx",
        "excel": "xlsx",
        "xlsx": "xlsx",
        "markdown": "md",
        "md": "md",
        "text": "txt",
        "txt": "txt",
    }
    normalized = format_map.get(format_name.lower())
    if not normalized:
        raise HTTPException(status_code=400, detail="Unsupported export format")

    try:
        path, media_type = generate_export(normalized, job_id, status_payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Export generation failed: {exc}") from exc

    if not os.path.exists(path):
        raise HTTPException(status_code=500, detail="Export generation failed: file was not created")

    return FileResponse(
        path=path,
        media_type=media_type,
        filename=os.path.basename(path)
    )
