from typing import Any, Dict, List

from pydantic import BaseModel


class Profiling(BaseModel):
    row_count: int
    column_count: int
    null_count: int
    duplicate_count: int


class FinalOutput(BaseModel):
    source_inventory: Dict[str, Any]
    schema: Dict[str, List[str]]
    schema_analysis: str | None = None
    profiling: Dict[str, Profiling]
    dq_report: Dict[str, Any] | None = None
    column_intelligence: Dict[str, Any]
    dpdp_compliance: Dict[str, Any]
    gap_analysis: Dict[str, Any]
    raid: Dict[str, Any]
    traceability: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    quality_score: float
