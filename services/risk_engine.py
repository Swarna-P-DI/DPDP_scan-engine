import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2}
LIKELIHOOD_WEIGHT = {"high": 1.0, "medium": 0.65, "low": 0.35}
IMPACT_WEIGHT = {"compliance": 1.0, "security": 0.9, "business": 0.7}


def _risk_id(seed: str) -> str:
    return f"RISK-{hashlib.sha1(seed.encode('utf-8')).hexdigest()[:10].upper()}"


def _task_id(risk_id: str) -> str:
    return f"TASK-{hashlib.sha1(risk_id.encode('utf-8')).hexdigest()[:10].upper()}"


def _normalize_severity(value: str) -> str:
    lowered = str(value or "").lower()
    if lowered in {"critical", "high", "medium", "low"}:
        return lowered
    return "medium"


def _likelihood(severity: str, evidence: str = "") -> str:
    text = str(evidence or "").lower()
    if severity in {"critical", "high"} and ("unmasked" in text or "invalid" in text):
        return "high"
    if severity in {"critical", "high"}:
        return "medium"
    if severity == "medium":
        return "medium"
    return "low"


def _impact(issue_type: str, description: str) -> List[str]:
    text = f"{issue_type} {description}".lower()
    impacts = []
    if any(token in text for token in ("pii", "aadhaar", "pan", "email", "phone", "dpdp", "gdpr")):
        impacts.extend(["compliance", "security"])
    if any(token in text for token in ("null", "duplicate", "invalid", "quality", "primary key")):
        impacts.append("business")
    if "owner" in text or "steward" in text:
        impacts.append("compliance")
    return sorted(set(impacts or ["business"]))


def _compliance_mapping(description: str, issue_type: str) -> List[str]:
    text = f"{issue_type} {description}".lower()
    mappings = []
    if any(token in text for token in ("pii", "personal", "aadhaar", "pan", "email", "phone", "mask")):
        mappings.extend(["DPDP", "GDPR"])
    if "owner" in text or "steward" in text:
        mappings.append("DPDP")
    return sorted(set(mappings))


def _risk_score(severity: str, likelihood: str, impact: List[str]) -> float:
    impact_factor = max([IMPACT_WEIGHT.get(item, 0.5) for item in impact] or [0.5])
    return round(SEVERITY_WEIGHT.get(severity, 4) * LIKELIHOOD_WEIGHT.get(likelihood, 0.65) * impact_factor, 2)


def _priority_from_score(score: float) -> str:
    if score >= 8:
        return "CRITICAL"
    if score >= 5:
        return "HIGH"
    if score >= 2.5:
        return "MEDIUM"
    return "LOW"


def _task_action(risk: Dict[str, Any]) -> str:
    description = str(risk.get("description", "")).lower()
    affected = risk.get("affected_columns") or []
    target = f"{affected[0].get('table')}.{affected[0].get('column')}" if affected else "affected dataset"
    if "unmasked" in description:
        return f"Mask, tokenize, or restrict access to {target}"
    if "partially masked" in description:
        return f"Validate masking strength for {target}"
    if "owner" in description:
        return f"Assign accountable owner and data steward for {target}"
    if "duplicate" in description:
        return f"Resolve duplicates and enforce uniqueness for {target}"
    if "null" in description:
        return f"Define completeness rule and remediate nulls for {target}"
    if "invalid" in description:
        return f"Add validation and fix invalid values for {target}"
    return f"Review and remediate risk {risk.get('id')}"


def generate_tasks(risks: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tasks = []
    for risk in risks:
        severity = risk.get("severity", "medium")
        due_days = 3 if severity == "critical" else 7 if severity == "high" else 21 if severity == "medium" else 45
        tasks.append({
            "task_id": _task_id(risk["id"]),
            "risk_id": risk["id"],
            "owner": risk.get("owner") or "Data Engineering / Data Steward",
            "action": _task_action(risk),
            "due_date": (datetime.utcnow() + timedelta(days=due_days)).date().isoformat(),
            "status": "OPEN",
        })
    return tasks


def _affected_columns(issue: Dict[str, Any]) -> List[Dict[str, str]]:
    table = issue.get("table") or issue.get("affected_table")
    column = issue.get("column") or issue.get("affected_column")
    if table and column:
        return [{"table": table, "column": column}]

    description = str(issue.get("description") or issue.get("issue") or "")
    if "." in description:
        token = next((part for part in description.split() if "." in part), "")
        pieces = token.strip(".,:;()").split(".")
        if len(pieces) >= 2:
            return [{"table": ".".join(pieces[:-1]), "column": pieces[-1]}]
    return []


def issues_to_risks(issues: Iterable[Dict[str, Any]], column_intelligence: Dict[str, Any] | None = None) -> Dict[str, List[Dict[str, Any]]]:
    risks: List[Dict[str, Any]] = []
    seen = set()

    for issue in issues or []:
        if not isinstance(issue, dict):
            continue
        description = issue.get("description") or issue.get("issue") or "Governance issue detected"
        issue_type = issue.get("type") or issue.get("category") or "governance"
        severity = _normalize_severity(issue.get("severity"))
        if "unmasked" in str(description).lower() and severity == "high":
            severity = "critical"

        key = (str(description).lower(), issue_type, severity)
        if key in seen:
            continue
        seen.add(key)

        affected_columns = _affected_columns(issue)
        impact = _impact(issue_type, description)
        likelihood = _likelihood(severity, description)
        risk_score = _risk_score(severity, likelihood, impact)
        risks.append({
            "id": _risk_id("|".join(key)),
            "source_issue_id": issue.get("id"),
            "description": description,
            "severity": severity,
            "impact": impact,
            "likelihood": likelihood,
            "risk_score": risk_score,
            "priority": _priority_from_score(risk_score),
            "affected_columns": affected_columns,
            "owner": issue.get("owner") or issue.get("assigned_owner") or "Data Engineering / Data Steward",
            "compliance_mapping": _compliance_mapping(description, issue_type),
            "evidence": issue.get("evidence"),
        })

    for table, columns in (column_intelligence or {}).get("tables", {}).items():
        for column in columns:
            if not column.get("pii_detected"):
                continue
            masking = column.get("masking_status")
            if masking == "MASKED":
                continue
            severity = "critical" if masking == "NOT_MASKED" else "high"
            description = f"{table}.{column.get('column')} contains {masking.lower().replace('_', ' ')} {column.get('pii_type')} data."
            key = (description.lower(), "pii_exposure", severity)
            if key in seen:
                continue
            seen.add(key)
            likelihood = "high" if masking == "NOT_MASKED" else "medium"
            impact = ["compliance", "security"]
            risk_score = _risk_score(severity, likelihood, impact)
            risks.append({
                "id": _risk_id("|".join(key)),
                "source_issue_id": None,
                "description": description,
                "severity": severity,
                "impact": impact,
                "likelihood": likelihood,
                "risk_score": risk_score,
                "priority": _priority_from_score(risk_score),
                "affected_columns": [{"table": table, "column": column.get("column")}],
                "owner": "Data Engineering / Data Steward",
                "compliance_mapping": ["DPDP", "GDPR"],
                "evidence": column.get("evidence"),
            })

    risks.sort(key=lambda item: (-item.get("risk_score", 0), SEVERITY_RANK.get(item["severity"], 9), item["description"]))
    prioritized_risks = list(risks)
    return {
        "risks": risks,
        "prioritized_risks": prioritized_risks,
        "tasks": generate_tasks(prioritized_risks),
    }
