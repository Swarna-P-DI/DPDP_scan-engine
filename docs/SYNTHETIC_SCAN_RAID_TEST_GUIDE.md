# Synthetic Scan + RAID Test Guide

This guide validates the Scan + RAID Agent with deterministic synthetic data only. The data simulates PostgreSQL, MongoDB, S3-like object storage, and unstructured documents. All identifiers are fake and are intended only for local QA.

## Test Data Files

- SQL: `test_data/synthetic_raid/postgres_seed.sql`
- MongoDB fixture: `test_data/synthetic_raid/mongodb_customer_profiles.json`
- S3-like JSON object: `test_data/synthetic_raid/s3/kyc_batch.json`
- S3-like text object: `test_data/synthetic_raid/s3/public_export.txt`
- Unstructured documents:
  - `test_data/synthetic_raid/documents/unstructured_notes.txt`
  - `test_data/synthetic_raid/documents/employee_plaintext_memo.txt`
- PII index seed: `test_data/synthetic_raid/pii_index_seed.json`
- UI/backend report fixture: `storage/reports/zz_synthetic_raid_full_coverage.json`

## Coverage Matrix

| Feature | Synthetic coverage |
|---|---|
| PostgreSQL structured schema | `users`, `bank_accounts`, `employees` |
| MongoDB nested documents | `customer_profiles` with nested identifiers and contact arrays |
| S3-like objects | Public JSON and text files with exposure flags |
| Unstructured text | Plain text, OCR-like noise, masked values, invalid candidates |
| Aadhaar | Unmasked, masked, invalid, encrypted-like, repeated across sources |
| PAN | Valid fake formats and invalid fixture |
| IFSC | Valid fake formats and invalid fixture |
| Masking detection | `XXXX-XXXX-0123`, account masks, partial phone masks |
| Encryption flag | Token-vault source and encrypted-like placeholder values |
| Public exposure | `s3.synthetic-public-kyc-bucket` has `publicly_exposed=true` |
| Missing flags | MongoDB nested Aadhaar has `masking_status=UNKNOWN` |
| Identity correlation | Same fake Aadhaar hash appears in PostgreSQL, MongoDB, and S3 |
| Identity ambiguity | Same name, `Ravi Kumar`, appears with different Aadhaar values |
| RAID | At least 3 risks, 3 issues, 2 assumptions, 2 dependencies |
| Heatmap | HIGH, MEDIUM, and LOW risk entries |
| Compliance | VIOLATION, RISK, and COMPLIANT conditions |

## How To Load Synthetic PostgreSQL Data

Use the SQL file against a local test PostgreSQL database only:

```powershell
psql -h localhost -p 5433 -U postgres -d Scan_db -f test_data/synthetic_raid/postgres_seed.sql
```

If you do not want to load SQL, the UI can still validate the full RAID functionality using `storage/reports/zz_synthetic_raid_full_coverage.json`, because the backend hydrates RAID intelligence from the latest scan report.

## Test Scenarios

### 1. Federated Search

Query: `Aadhaar`

Expected API behavior:

```json
{
  "query": "Aadhaar",
  "parsed": {"pii_types": ["aadhaar"]},
  "total_matches": "greater than 0",
  "groups": [
    {
      "identity_key": "source or row grouped key",
      "records": [
        {"pii_type": "aadhaar", "source_type": "postgresql"}
      ]
    }
  ]
}
```

Expected UI behavior:

- Open `Intelligence`.
- Select `Search`.
- Enter `Aadhaar`.
- Click `Search`.
- Results table shows Aadhaar records from PostgreSQL, MongoDB, S3-like, document, and token-vault sources.

Expected RAID signal:

- Risks include unmasked Aadhaar in employees and public S3-like exposure.

Query: `PAN`

Expected:

- Results show PAN records from `synthetic_raid.users`, `synthetic_mongo.customer_profiles`, and `s3.synthetic-public-kyc-bucket`.
- Invalid `BADPAN1234` is present in raw fixtures but should not be treated as a valid PAN detection.

Query: `Name + Aadhaar`

Expected:

- Parser recognizes `name` and `aadhaar` as PII types.
- Results include name and Aadhaar indexed entries when present.
- UI grouped response exposes ambiguity: `Ravi Kumar` appears with different Aadhaar values in different sources.

### 2. Compliance

Expected decisions:

| Source | Condition | Expected status |
|---|---|---|
| `synthetic_raid.employees` | Unmasked Aadhaar, encryption false | `VIOLATION` |
| `synthetic_raid.bank_accounts` | Partially masked financial/account data, encryption false | `RISK` |
| `vault.encrypted_identity_tokens` | Masked/tokenized and encrypted | `COMPLIANT` |
| `s3.synthetic-public-kyc-bucket` | Public exposure true and encryption false | `VIOLATION` |
| `synthetic_mongo.customer_profiles` | Missing masking flag on nested Aadhaar | `RISK` |

Expected API response fragment:

```json
[
  {
    "source_id": "s3.synthetic-public-kyc-bucket",
    "compliance_status": "VIOLATION",
    "issues": ["Source is marked publicly exposed."],
    "recommendations": ["Remove public exposure or isolate the source behind approved access controls."]
  }
]
```

Expected UI behavior:

- Open `Intelligence`.
- Select `Compliance`.
- Status badges show VIOLATION/RISK/COMPLIANT.
- Issue and recommendation columns explain the decision.

### 3. Heatmap

Expected:

- HIGH: unmasked Aadhaar/PAN/IFSC in PostgreSQL, MongoDB, S3-like, and document sources.
- MEDIUM: masked or partially masked fields.
- LOW: encrypted/tokenized vault source.

Expected API response fragment:

```json
{
  "source_vs_pii": {
    "dimensions": ["source_id", "pii_type"],
    "cells": [
      {
        "source_id": "synthetic_raid.employees",
        "pii_type": "aadhaar",
        "risk_level": "HIGH"
      },
      {
        "source_id": "vault.encrypted_identity_tokens",
        "pii_type": "aadhaar",
        "risk_level": "LOW"
      }
    ]
  }
}
```

Expected UI behavior:

- Open `Intelligence`.
- Select `Heatmap`.
- Table shows source, PII type, count, unprotected count, and risk badge.

### 4. RAID

Minimum expected RAID output:

Risks:

1. Unmasked Aadhaar stored in `synthetic_raid.employees.aadhaar`.
2. Public S3-like object exposes Aadhaar, PAN, and IFSC.
3. Same Aadhaar appears across PostgreSQL, MongoDB, and S3-like storage.

Issues:

1. No encryption confirmed for unmasked Aadhaar in employee memo.
2. Missing masking flags on MongoDB nested identifiers.
3. Invalid Aadhaar/PAN fixtures should not be treated as confirmed valid identities.

Assumptions:

1. Connector metadata is authoritative for access-control and public-exposure flags.
2. Encrypted-like token values represent encryption for deterministic tests only.

Dependencies:

1. Depends on connector scan output for PostgreSQL, MongoDB, S3, and documents.
2. Depends on masking/tokenization services for remediation.

Expected UI behavior:

- Open `Intelligence`.
- Select `RAID`.
- Section column shows risks, issues, assumptions, dependencies, and recommendations.

## UI Guide

### Main Buttons

`Run Platform Scan`

- Backend API: `GET /scan`
- Backend flow: connector/source inventory scan -> profiling -> PII detection -> classification -> risk engine -> RAID -> report export.
- UI flow: polls `/status/{job_id}` until complete, then calls `/result/{job_id}`, then refreshes `/report`.
- Use when validating live connector-backed scans.

`Refresh Intelligence`

- Backend API: `GET /report`
- Backend flow: if in-memory report exists, return it; otherwise hydrate from latest `storage/reports/*.json`.
- UI flow: reloads the Core RAID Intelligence workbench without requiring upload or source selection.
- Use when validating the synthetic report fixture or the latest completed platform scan.

### Dashboard Sections

#### 1. RAID Intelligence Tab

What it shows:

- Run metadata
- PII indexed count
- Exposure summary
- Compliance count
- Data intelligence `what`, `where`, and `how`

How risks/issues are derived:

- PII index tells what exists and where.
- Compliance engine checks masking, encryption, access control, and public exposure.
- RAID service converts those facts into risks, issues, assumptions, dependencies, and recommendations.

#### 2. PII Index Tab

Shown under `Intelligence -> Operations`.

Columns:

- `Type`: PII type such as aadhaar, pan, ifsc, email, phone.
- `Source`: source/table/object identifier.
- `Location`: table/column, document path, object path, or nested document path.
- `Masked`: whether the value/source is masked or partially masked.
- `Encrypted`: whether encryption is confirmed.

Interpretation:

- `masked=false` and `encrypted=false` is highest exposure.
- `masked=true` and `encrypted=false` is medium exposure.
- `encrypted=true` is low exposure.

#### 3. Federated Search

Shown under `Intelligence -> Search`.

Example queries:

- `Aadhaar`
- `PAN`
- `IFSC`
- `Name + Aadhaar`

Search button:

- Calls `POST /search_pii`.
- Backend parses query terms.
- Backend queries the PII index.
- Backend groups results by identity/source context.
- UI renders matching records and grouped JSON.

#### 4. Heatmap

Shown under `Intelligence -> Heatmap`.

Axes:

- Source ID
- PII type

Risk meaning:

- HIGH: unmasked sensitive PII, especially Aadhaar/PAN/IFSC.
- MEDIUM: masked or partially masked PII without confirmed encryption.
- LOW: encrypted/tokenized PII.

#### 5. Compliance Tab

Shown under `Intelligence -> Compliance`.

Statuses:

- `COMPLIANT`: PII is protected by masking/encryption and no exposure flags are present.
- `RISK`: one or more controls are missing or unknown.
- `VIOLATION`: unmasked Aadhaar or public exposure is present.

Decision logic:

- Unmasked Aadhaar -> VIOLATION.
- Publicly exposed source -> VIOLATION.
- Masked but not encrypted -> RISK.
- Encrypted and access controlled -> COMPLIANT.

#### 6. Logs Tab

Shown under `Intelligence -> Logs`.

Event types:

- `scan_execution`
- `pii_detection`
- `query_execution`

Trace flow:

1. `/report` hydrates or returns latest report.
2. `/search_pii` records query execution.
3. `/scan` records the platform scan path through backend job state.

#### 7. Log Summary

Shown under `Intelligence -> Logs`.

Summarize button:

- Calls `POST /summarize_logs`.
- Backend uses deterministic keyword matching against logs and RAID output.
- Example prompt: `Summarize high-risk PII exposures`.
- No LLM or chatbot is used.

#### 8. Full Report

Shown under `Intelligence -> Report`.

JSON structure:

- `metadata`: run and source details.
- `profiling`: structured profiling output.
- `pii_summary`: PII counts by type, source, and exposure.
- `pii_index`: hashed/tokenized PII location records.
- `raid`: risks, issues, assumptions, dependencies, recommendations.
- `compliance_status`: per-source DPDP status.
- `data_intelligence`: what/where/how summary.
- `risk_heatmap`: source-vs-PII heatmap cells.

## API Walkthrough

### `GET /scan`

Input:

- None.

Output:

```json
{"job_id": "uuid", "status": "started"}
```

When to use:

- Start a live connector-backed platform scan.

### `GET /report`

Input:

- None.

Output:

- Latest consolidated report. If no upload report exists, the backend hydrates from latest `storage/reports/*.json`.

When to use:

- Load the UI workbench or fetch all outputs in one response.

### `GET /raid`

Input:

- None.

Output:

```json
{
  "risks": [],
  "issues": [],
  "assumptions": [],
  "dependencies": [],
  "recommendations": []
}
```

When to use:

- Fetch only the RAID register.

### `GET /raid_summary`

Input:

- None.

Output:

```json
{
  "raid": {},
  "data_intelligence": {"what": [], "where": [], "how": []},
  "pii_summary": {}
}
```

When to use:

- Fetch a compact executive payload for dashboard summaries.

### `GET /heatmap`

Input:

- None.

Output:

```json
{
  "source_vs_pii": {
    "dimensions": ["source_id", "pii_type"],
    "cells": []
  }
}
```

When to use:

- Populate source-vs-PII heatmap visualizations.

### `GET /compliance_report`

Input:

- None.

Output:

```json
[
  {
    "source_id": "source",
    "compliance_status": "COMPLIANT | RISK | VIOLATION",
    "issues": [],
    "recommendations": []
  }
]
```

When to use:

- Show DPDP control posture by source.

### `POST /search_pii`

Input:

```json
{"query": "Name + Aadhaar"}
```

Output:

```json
{
  "query": "Name + Aadhaar",
  "parsed": {"pii_types": ["aadhaar", "name"]},
  "total_matches": 0,
  "groups": []
}
```

When to use:

- Search and correlate PII across sources.

### `GET /logs`

Input:

- None.

Output:

```json
[
  {
    "event": "query_execution",
    "source": "pii_index",
    "action": "search_pii",
    "timestamp": "2026-05-04T00:00:00Z",
    "status": "OK"
  }
]
```

When to use:

- Debug scan, hydration, and query trace flow.

### `POST /summarize_logs`

Input:

```json
{"prompt": "Summarize high-risk PII exposures"}
```

<!-- Here are good prompts for summarize_logs:
Summarize high-risk PII exposures
Show Aadhaar-related risks
List DPDP violations from the latest scan
Summarize unmasked PII findings
Show sources with public exposure risks
Summarize failed or risky scan events
What are the top compliance issues?
Show encryption-related issues
Summarize masking gaps
List RAID risks from the latest scan
Show S3-related PII exposure
Summarize MongoDB nested PII risks
Show PostgreSQL tables with unmasked PII
Summarize all query execution events
Show recent PII detection activity
What changed in the latest intelligence refresh?
Summarize Aadhaar exposures by source
Show PAN-related findings
Show IFSC-related risks
Give me a remediation-focused summary -->



Output:

```json
{
  "prompt": "Summarize high-risk PII exposures",
  "summary": "N matching RAID risk(s), N trace event(s) available.",
  "risks": [],
  "recent_events": []
}
```

When to use:

- Produce deterministic operational summaries from logs and RAID output.

## Recommended End-to-End QA Steps

1. Start backend: `python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8000`.
2. Start frontend: `npm.cmd run dev -- --host 127.0.0.1 --port 3001`.
3. Open `http://127.0.0.1:3001`.
4. Click `Refresh Intelligence`.
5. Validate `Operations` shows PII index and summary.
6. Go to `Search`, query `Aadhaar`, `PAN`, `IFSC`, and `Name + Aadhaar`.
7. Go to `Compliance`, confirm VIOLATION/RISK/COMPLIANT rows.
8. Go to `Heatmap`, confirm HIGH/MEDIUM/LOW badges.
9. Go to `RAID`, confirm risks, issues, assumptions, dependencies, and recommendations.
10. Go to `Logs`, click `Summarize` with `Show Aadhaar-related risks`.
11. Go to `Report`, verify the full JSON contains metadata, profiling, PII summary, PII index, RAID, compliance, heatmap, and data intelligence.

