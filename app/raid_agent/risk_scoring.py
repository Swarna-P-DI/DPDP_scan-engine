from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.raid_agent.api_lineage import exposure_weight, frequency_weight, normalize_exposure_type


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    sensitivity_score: float
    exposure_score: float
    volume_score: float
    overall_risk_score: float
    risk_category: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "sensitivity_score": self.sensitivity_score,
            "exposure_score": self.exposure_score,
            "volume_score": self.volume_score,
            "overall_risk_score": self.overall_risk_score,
            "risk_category": self.risk_category,
            "recommendation": self.recommendation,
        }


def score_risk(
    *,
    pii_type: str,
    sensitivity_score: float | int | None = None,
    is_masked: bool,
    exposure_type: str = "INTERNAL",
    row_count: int | None = None,
    distinct_count: int | None = None,
    is_tokenized: bool = False,
    mask_ratio: float = 0.0,
    request_count: int | None = None,
    response_count: int | None = None,
    request_rate: float | None = None,
    last_accessed: object | None = None,
) -> RiskAssessment:
    exposure = normalize_exposure_type(exposure_type)
    exposure_score = exposure_weight(exposure) + frequency_weight(request_count, response_count) + request_rate_weight(request_rate)
    volume_score = volume_weight(row_count)
    base_score = _base_score(pii_type) if sensitivity_score is None or float(sensitivity_score) > 1 else float(sensitivity_score)
    masking_penalty = _masking_penalty(is_masked, is_tokenized, mask_ratio)
    decay = risk_decay(last_accessed)
    dynamic_sensitivity = _clamp(base_score + exposure_score + volume_score - masking_penalty - decay)
    density_score = pii_density(row_count=row_count, distinct_count=distinct_count)
    overall = _clamp(dynamic_sensitivity + density_score)
    risk_category = _risk_category(pii_type, is_masked, exposure, overall)
    return RiskAssessment(
        sensitivity_score=round(dynamic_sensitivity, 4),
        exposure_score=exposure_score,
        volume_score=volume_score,
        overall_risk_score=round(overall, 4),
        risk_category=risk_category,
        recommendation=_recommendation(str(pii_type or "").upper(), risk_category, is_masked, exposure),
    )


def volume_weight(row_count: int | None) -> float:
    if row_count is None:
        return 0.0
    if row_count > 100_000:
        return 0.03
    if row_count >= 10_000:
        return 0.01
    return 0.0


def pii_density(*, row_count: int | None, distinct_count: int | None) -> float:
    if not row_count or row_count <= 0 or distinct_count is None:
        return 0.0
    return round(max(0.0, min(1.0, distinct_count / row_count)) * 0.05, 4)


def request_rate_weight(request_rate: float | None) -> float:
    if request_rate is None:
        return 0.0
    rate = float(request_rate or 0)
    if rate >= 1000:
        return 0.08
    if rate >= 100:
        return 0.05
    if rate >= 10:
        return 0.02
    return 0.0


def risk_decay(last_accessed: object | None) -> float:
    accessed_at = _parse_datetime(last_accessed)
    if not accessed_at:
        return 0.0
    age_days = (datetime.now(timezone.utc) - accessed_at).days
    if age_days >= 365:
        return 0.06
    if age_days >= 90:
        return 0.03
    return 0.0


def _risk_category(pii_type: str, is_masked: bool, exposure: str, overall: float) -> str:
    key = str(pii_type or "").upper()
    if key == "AADHAAR" and exposure == "PUBLIC":
        return "CRITICAL"
    if key == "PAN" and not is_masked and exposure in {"PUBLIC", "PARTNER"}:
        return "HIGH"
    if key == "PAN" and not is_masked:
        return "HIGH"
    if key == "IFSC" and exposure == "INTERNAL":
        return "MEDIUM"
    if overall >= 0.95:
        return "CRITICAL"
    if overall >= 0.8:
        return "HIGH"
    if overall >= 0.55:
        return "MEDIUM"
    return "LOW"


def _recommendation(pii_type: str, risk_category: str, is_masked: bool, exposure: str) -> str:
    if risk_category == "CRITICAL":
        return "Block external exposure until masking/tokenization and explicit purpose controls are enforced."
    if pii_type in {"AADHAAR", "PAN"} and not is_masked:
        return "Apply tokenization or irreversible masking and restrict access to approved DPDP processing purposes."
    if exposure == "PUBLIC":
        return "Validate API necessity, add field-level redaction, and monitor exposure alerts."
    return "Keep internal access least-privilege and monitor for drift in PII volume."


def _base_score(pii_type: str) -> float:
    key = str(pii_type or "").upper()
    if key == "AADHAAR":
        return 0.9
    if key == "PAN":
        return 0.85
    if key == "IFSC":
        return 0.7
    return 0.5


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _masking_penalty(is_masked: bool, is_tokenized: bool, ratio: float) -> float:
    if is_tokenized:
        return 0.12
    if is_masked:
        return 0.1
    if ratio > 0.7:
        return 0.1
    if ratio > 0.0:
        return min(0.08, ratio * 0.08)
    return 0.0


def _parse_datetime(value: object | None) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
