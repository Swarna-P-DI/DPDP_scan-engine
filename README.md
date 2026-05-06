# Automated Data Discovery Platform

This project is a DPDP-aware data discovery platform with a backend scan engine, Scan + RAID intelligence layer, and React dashboard.

It can:

- scan PostgreSQL source inventory and sampled table data;
- profile tables and detect PII such as name, email, phone/financial, Aadhaar, PAN, and IFSC;
- generate risk findings, DPDP compliance summaries, RAID outputs, heatmaps, and exportable reports;
- hydrate dashboard intelligence from the latest saved scan report;
- run file-level Scan + RAID on uploaded CSV, JSON, TXT, PDF, and similar supported inputs;
- search indexed PII by type, value, and row context such as `Jane+444455556666`.

More detailed integration notes are also available in [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md).

## Project Structure

```text
backend/                 Main platform scan graph and FastAPI application
app/                     Scan + RAID intelligence, PII index, search, compliance, report hydration
Frontend/scan-dashboard/ React/Vite dashboard
test_data/               Local synthetic fixtures and seed data
storage/reports/         Generated JSON/PDF/export reports
storage/runs/            Saved scan run snapshots
storage/tasks.json       Generated remediation/action tasks
```

Important test data folders:

```text
test_data/*.sql                    PostgreSQL seed datasets for Scan_db
test_data/scan_raid/               Small CSV/JSON upload-scan fixtures
test_data/synthetic_raid/          Multi-source synthetic fixtures for PostgreSQL/Mongo/S3/doc examples
storage/reports/*.json             Saved reports used by dashboard hydration
```

## Prerequisites

Use Windows PowerShell from the project root:

```powershell
cd e:\SLP1\Swarna_P\DI_LABS\Automated_Data_Discovery_Platform\test\scan_DPDP
```

Required software:

- Python 3.11
- Node.js and npm
- PostgreSQL running locally

The backend database connection is configured in [backend/config.py](backend/config.py):

```python
DB_CONFIG = {
    "host": "localhost",
    "port": "5433",
    "database": "Scan_db",
    "user": "postgres",
    "password": "Slp2003"
}
```

Update this file if your PostgreSQL host, port, database, user, or password is different.

## Install Dependencies

Backend:

```powershell
python -m pip install -r requirements.txt
```

If your environment does not already have the database/graph packages used by the backend, install them too:

```powershell
python -m pip install sqlalchemy psycopg2-binary langgraph
```

Frontend:

```powershell
cd Frontend\scan-dashboard
npm install
cd ..\..
```

## Prepare PostgreSQL Test Data

`Run Platform Scan` scans PostgreSQL `Scan_db`. It does not automatically scan the whole `test_data` folder.

Load the local SQL fixtures into `Scan_db`:

```powershell
psql -h localhost -p 5433 -U postgres -d Scan_db -f test_data\01_clean_data.sql
psql -h localhost -p 5433 -U postgres -d Scan_db -f test_data\02_pii_exposure.sql
psql -h localhost -p 5433 -U postgres -d Scan_db -f test_data\03_masked_data.sql
psql -h localhost -p 5433 -U postgres -d Scan_db -f test_data\04_poor_data_quality.sql
psql -h localhost -p 5433 -U postgres -d Scan_db -f test_data\05_no_relationships.sql
```

Optional synthetic RAID SQL fixture:

```powershell
psql -h localhost -p 5433 -U postgres -d Scan_db -f test_data\synthetic_raid\postgres_seed.sql
```

## Run The Backend

From the project root:

```powershell
python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8000 --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

Health check:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/ | Select-Object -ExpandProperty Content
```

Expected response:

```json
{"message":"Data-only scan API running (async mode)"}
```

## Run The Frontend

In a second PowerShell window:

```powershell
cd e:\SLP1\Swarna_P\DI_LABS\Automated_Data_Discovery_Platform\test\scan_DPDP\Frontend\scan-dashboard
npm.cmd run dev -- --host 127.0.0.1 --port 3001
```

Open:

```text
http://127.0.0.1:3001
```

If your backend is not on `http://127.0.0.1:8000`, create `Frontend/scan-dashboard/.env`:

```text
VITE_API_URL=http://127.0.0.1:8000
```

Then restart the frontend dev server.

## Exact Application Flow

### Platform Scan Flow

Click **Run Platform Scan** in the dashboard.

Backend flow:

```text
GET /scan
→ start async graph job
→ PostgreSQL source inventory
→ SELECT * FROM each table LIMIT 500
→ profiling and data quality checks
→ PII classification
→ document/unstructured scan, if storage/unstructured exists
→ risk engine
→ RAID agent
→ governance/recommendations
→ report export to storage/reports
→ activate Core RayIN Intelligence in memory
```

Frontend flow:

```text
Run Platform Scan
→ GET /scan
→ poll GET /status/{job_id}
→ when completed, read result
→ refresh dashboard sections
```

### Core RayIN Intelligence Flow

The Intelligence tab uses the Scan + RAID intelligence layer.

If a platform scan has just completed:

```text
completed scan output
→ build PII index
→ build compliance status
→ build heatmap
→ build RAID summary
→ search works on active PII index
```

If no in-memory scan exists yet:

```text
GET /report
→ load latest storage/reports/*.json
→ hydrate PII index and RAID from saved scan output
→ status = hydrated_from_scan_outputs
```

This fallback is intentional so the UI can load the latest report without running a fresh scan.

### File Upload Scan Flow

The app router also supports file-level scans:

```text
POST /scan multipart file upload
→ parse uploaded file
→ detect PII in rows/pages
→ build row-aware PII index
→ compliance
→ RAID
→ in-memory report
```

Use this when you want to scan files such as:

```text
test_data/scan_raid/sample_kyc.csv
test_data/scan_raid/sample_kyc.json
```

CLI demo:

```powershell
python -m app.demo test_data\scan_raid\sample_kyc.csv
python -m app.demo test_data\scan_raid\sample_kyc.json
```

## Important Data Source Notes

The dashboard button **Run Platform Scan** scans the configured PostgreSQL database, not the whole `test_data` folder.

Current behavior:

```text
Run Platform Scan        → PostgreSQL Scan_db via backend/config.py
Refresh Intelligence     → latest active report, or latest storage/reports/*.json fallback
test_data/scan_raid      → used only when uploaded or passed to app.demo
test_data/synthetic_raid → fixtures and synthetic full-coverage examples, not auto-scanned
```

Unstructured files are scanned only if this folder exists:

```text
storage/unstructured
```

You can override it before starting the backend:

```powershell
$env:UNSTRUCTURED_SCAN_DIR="e:\path\to\documents"
python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8000 --reload
```

Supported unstructured extensions in the backend agent:

```text
.txt, .log, .json, .pdf
```

## Search Behavior

Search uses the active in-memory PII index. It does not query raw databases directly at search time.

Supported examples:

```text
email
name
aadhaar
pan
ifsc
financial
ABCDE1234F
HDFC0001234
444455556666
Jane+444455556666
Ravi+234567890123
Meera+9123456789
```

How combined search works:

```text
Jane+444455556666
→ parse Jane as row-context text
→ parse 444455556666 as Aadhaar
→ hash Aadhaar query value
→ match index entries where row context contains Jane and value hash matches Aadhaar
→ return matching row metadata
```

Because the index is row-aware, exact combined searches work only after a fresh scan/report includes sampled row records. Old saved reports may not have enough row context until you rerun the scan.

## Main API Endpoints

Platform scan endpoints:

```text
GET  /scan
GET  /status/{job_id}
GET  /result/{job_id}
GET  /exports/{job_id}/{format}
GET  /scan/history
GET  /monitoring/history
POST /scan/schedule
```

Core Intelligence endpoints:

```text
GET  /report
GET  /raid
GET  /raid_summary
GET  /heatmap
GET  /compliance_report
POST /search_pii
GET  /logs
POST /summarize_logs
```

Task endpoints:

```text
GET  /tasks
POST /tasks/create
POST /tasks/update/{task_id}
```

Export formats:

```text
json, pdf, pptx, docx, xlsx, md, txt
```

Example API calls:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/scan
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/report
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/raid
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/heatmap
```

Search:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/search_pii `
  -ContentType "application/json" `
  -Body '{"query":"Jane+444455556666"}'
```

Upload scan:

```powershell
curl.exe -X POST `
  -F "file=@test_data/scan_raid/sample_kyc.json" `
  http://127.0.0.1:8000/scan
```

## Integrating With Other Applications

Other applications can integrate with this platform through HTTP APIs.

### Option 1: Trigger Scans From Another App

Call:

```text
GET /scan
```

Then poll:

```text
GET /status/{job_id}
```

When status is `completed`, fetch:

```text
GET /result/{job_id}
```

Use this when another system wants to launch full platform scans and consume the final report.

### Option 2: Consume Latest Intelligence

Call:

```text
GET /report
GET /raid_summary
GET /heatmap
GET /compliance_report
```

Use this for executive dashboards, governance portals, observability pages, or compliance review tools.

### Option 3: Embed PII Search

Call:

```text
POST /search_pii
```

Example payload:

```json
{
  "query": "Jane+444455556666"
}
```

Use this when another app needs to locate indexed PII across scanned sources without direct database access.

### Option 4: Upload Files For On-Demand Scan

Call:

```text
POST /scan
```

with multipart form field:

```text
file=<csv/json/pdf/txt>
```

Use this for KYC uploads, file intake workflows, document compliance checks, and ad hoc data review.

### Option 5: Export Reports

After a scan completes:

```text
GET /exports/{job_id}/json
GET /exports/{job_id}/pdf
GET /exports/{job_id}/xlsx
GET /exports/{job_id}/docx
GET /exports/{job_id}/pptx
```

Use this for audit packs, compliance submissions, and offline review.

## Integration Contract Summary

Typical external integration sequence:

```text
1. External app calls GET /scan
2. External app stores job_id
3. External app polls GET /status/{job_id}
4. On completed, external app calls GET /result/{job_id}
5. External app optionally calls GET /exports/{job_id}/pdf
6. External app displays or stores risks, issues, compliance, heatmap, RAID, and recommendations
```

Minimal JavaScript example:

```javascript
const baseUrl = "http://127.0.0.1:8000";

async function runScan() {
  const started = await fetch(`${baseUrl}/scan`).then((r) => r.json());
  const jobId = started.job_id;

  while (true) {
    const status = await fetch(`${baseUrl}/status/${jobId}`).then((r) => r.json());
    if (status.status === "completed") return status.result;
    if (status.status === "failed") throw new Error(status.error || "Scan failed");
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}
```

Minimal Python example:

```python
import time
import requests

base_url = "http://127.0.0.1:8000"

job = requests.get(f"{base_url}/scan", timeout=120).json()
job_id = job["job_id"]

while True:
    status = requests.get(f"{base_url}/status/{job_id}", timeout=120).json()
    if status["status"] == "completed":
        report = status["result"]
        break
    if status["status"] == "failed":
        raise RuntimeError(status.get("error", "Scan failed"))
    time.sleep(2)
```

## Run Tests

Backend and Scan + RAID tests:

```powershell
python -m pytest app\tests
python -m pytest backend\tests
```

Focused tests used during development:

```powershell
python -m pytest app\tests\test_scan_raid.py
python -m pytest backend\tests\test_profiling_engine.py backend\tests\test_risk_engine.py
```

Frontend build:

```powershell
cd Frontend\scan-dashboard
npm.cmd run build
```

## Troubleshooting

### Frontend Cannot Reach Backend

Check:

```text
Frontend/scan-dashboard/.env
```

Set:

```text
VITE_API_URL=http://127.0.0.1:8000
```

Restart the frontend after changing `.env`.

### Platform Scan Fails Immediately

Check PostgreSQL connection values in [backend/config.py](backend/config.py), then verify the database is reachable:

```powershell
psql -h localhost -p 5433 -U postgres -d Scan_db -c "\dt *.*"
```

### Dashboard Shows hydrated_from_scan_outputs

This means no fresh in-memory scan is active and the dashboard loaded the latest saved report from:

```text
storage/reports/*.json
```

Click **Run Platform Scan** to run a fresh scan. After completion, Core RayIN Intelligence should show:

```text
completed_scan_outputs
```

### Search Does Not Find A Known Value

Confirm the value exists in the active scan source, not only in a fixture file.

Example:

```text
Meera Shah exists in test_data/scan_raid/sample_kyc.json
```

but `Run Platform Scan` scans PostgreSQL `Scan_db`, not that file. Upload or demo-scan the JSON file if you want `Meera` in the active file-scan index.

### Vite Build Fails With spawn EPERM

This can be a local Windows process permission issue with esbuild. Close other Node/Vite processes and rerun:

```powershell
cd Frontend\scan-dashboard
npm.cmd run build
```
