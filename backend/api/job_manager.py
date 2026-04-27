import uuid
from concurrent.futures import ThreadPoolExecutor

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
            jobs[job_id]["result"] = result["final_output"]
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
