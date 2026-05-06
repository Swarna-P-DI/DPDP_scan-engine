from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class PiiFieldCatalog(Base):
    __tablename__ = "pii_field_catalog"

    field_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    source_system: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    schema_name: Mapped[str] = mapped_column(String(128), nullable=False)
    table_name: Mapped[str] = mapped_column(String(128), nullable=False)
    column_name: Mapped[str] = mapped_column(String(128), nullable=False)
    pii_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    pii_category: Mapped[str] = mapped_column(String(128), nullable=False)
    sensitivity_level: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    sensitivity_score: Mapped[float] = mapped_column(Float, nullable=False)
    detection_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    is_masked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_tokenized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    data_owner: Mapped[str | None] = mapped_column(Text, nullable=True)
    business_unit: Mapped[str | None] = mapped_column(Text, nullable=True)
    steward_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    retention_period_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_accessed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    detection_events: Mapped[list["PiiDetectionEvent"]] = relationship(back_populates="field", cascade="all, delete-orphan")
    api_mappings: Mapped[list["PiiApiMapping"]] = relationship(back_populates="field", cascade="all, delete-orphan")
    risk_assessments: Mapped[list["PiiRiskAssessment"]] = relationship(back_populates="field", cascade="all, delete-orphan")


class PiiDetectionEvent(Base):
    __tablename__ = "pii_detection_events"
    __table_args__ = (UniqueConstraint("field_id", "hashed_value", "detection_method", name="uq_pii_detection_event_idempotent"),)

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    field_id: Mapped[str] = mapped_column(String(512), ForeignKey("pii_field_catalog.field_id", ondelete="CASCADE"), nullable=False, index=True)
    hashed_value: Mapped[str] = mapped_column(String(64), nullable=False)
    last4_value: Mapped[str | None] = mapped_column(String(8), nullable=True)
    detection_method: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    field: Mapped[PiiFieldCatalog] = relationship(back_populates="detection_events")


class PiiApiMapping(Base):
    __tablename__ = "pii_api_mapping"
    __table_args__ = (UniqueConstraint("field_id", "api_path", "http_method", name="uq_pii_api_mapping_idempotent"),)

    mapping_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    field_id: Mapped[str] = mapped_column(String(512), ForeignKey("pii_field_catalog.field_id", ondelete="CASCADE"), nullable=False, index=True)
    api_path: Mapped[str] = mapped_column(String(512), nullable=False)
    http_method: Mapped[str] = mapped_column(String(16), nullable=False)
    service_name: Mapped[str] = mapped_column(String(128), nullable=False)
    exposure_type: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    request_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_accessed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    field: Mapped[PiiFieldCatalog] = relationship(back_populates="api_mappings")


class PiiRiskAssessment(Base):
    __tablename__ = "pii_risk_assessment"
    __table_args__ = (UniqueConstraint("field_id", "assessed_at", name="uq_pii_risk_assessment_field_time"),)

    assessment_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    field_id: Mapped[str] = mapped_column(String(512), ForeignKey("pii_field_catalog.field_id", ondelete="CASCADE"), nullable=False, index=True)
    sensitivity_score: Mapped[float] = mapped_column(Float, nullable=False)
    exposure_score: Mapped[float] = mapped_column(Float, nullable=False)
    volume_score: Mapped[float] = mapped_column(Float, nullable=False)
    overall_risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    exposure_type: Mapped[str] = mapped_column(Text, nullable=False, default="INTERNAL")
    anomaly_flag: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retention_violation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    risk_category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_factors: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_factors: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    request_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    field: Mapped[PiiFieldCatalog] = relationship(back_populates="risk_assessments")
