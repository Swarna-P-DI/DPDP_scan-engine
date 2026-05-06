import uuid
from concurrent.futures import ThreadPoolExecutor

from app.core.inventory_intelligence import build_inventory_intelligence_report
from app.pii_engine.index import pii_index_store
from app.storage.memory import report_store

executor = ThreadPoolExecutor(max_workers=2)
jobs = {}


def start_job(graph):
    job_id = str(uuid.uuid4())

    jobs[job_id] = {
        "status": "running",
        "result": None,
        "error": None
    }

    def run():
        try:
            result = graph.invoke({})
            final_output = result["final_output"]
            try:
                intelligence_report = build_inventory_intelligence_report(
                    final_output,
                    status="completed_scan_outputs",
                )
                report_store.save(intelligence_report)
                pii_index_store.replace(intelligence_report.get("pii_index", []))
            except Exception as intelligence_error:
                final_output.setdefault("warnings", []).append(
                    f"Core intelligence activation failed: {intelligence_error}"
                )
            jobs[job_id]["result"] = final_output
            jobs[job_id]["status"] = "completed"
        except Exception as e:
            jobs[job_id]["error"] = str(e)
            jobs[job_id]["status"] = "failed"

    executor.submit(run)
    return job_id


def get_status(job_id):
    return jobs.get(job_id, {"status": "not_found"})


def get_result(job_id):
    return jobs.get(job_id, {"status": "not_found"})
