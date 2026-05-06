from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.core.inventory_intelligence import latest_intelligence_report
from app.core.scanner import ScanService
from app.observability.logger import event_log
from app.pii_engine.index import pii_index_store
from app.search_engine.service import FederatedSearchService
from app.storage.memory import report_store


router = APIRouter(tags=["SCAN + RAID"])
scan_service = ScanService()
search_service = FederatedSearchService()


class SearchRequest(BaseModel):
    query: str


class SummaryRequest(BaseModel):
    prompt: str


@router.post("/scan")
async def scan(file: UploadFile = File(...)):
    try:
        content = await file.read()
        return await scan_service.scan_bytes(file.filename or "upload", content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc


@router.get("/heatmap")
def heatmap():
    return latest_intelligence_report().get("risk_heatmap")


@router.post("/search_pii")
def search_pii(payload: SearchRequest):
    event_log.record("query_execution", "pii_index", "search_pii", query=payload.query)
    latest_intelligence_report()
    return search_service.search(payload.query, pii_index_store.all())


@router.get("/compliance_report")
def compliance_report():
    return latest_intelligence_report().get("compliance_status", [])


@router.get("/raid_summary")
def raid_summary():
    report = latest_intelligence_report()
    return {
        "raid": report.get("raid"),
        "data_intelligence": report.get("data_intelligence"),
        "pii_summary": report.get("pii_summary"),
    }


@router.get("/raid")
def raid():
    return latest_intelligence_report().get("raid")


@router.get("/report")
def report():
    return latest_intelligence_report()


@router.post("/summarize_logs")
def summarize_logs(payload: SummaryRequest):
    return event_log.summarize(payload.prompt, report_store.latest().get("raid"))


@router.get("/logs")
def logs():
    return event_log.all()
