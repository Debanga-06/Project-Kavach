"""
Scan + Threat models — per TRD Section 9 `scans` and `threats` tables.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Float, Integer, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    scan_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "url" | "email" | "file" | "secret"
    target: Mapped[str] = mapped_column(String(2048), nullable=False)

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    classification: Mapped[str] = mapped_column(String(30), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="completed", nullable=False)

    recommendations: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    threats: Mapped[list["Threat"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    threat_type: Mapped[str] = mapped_column(String(60), nullable=False)  # signal name, e.g. "ip_based_host"
    indicator: Mapped[str] = mapped_column(String(2048), nullable=False)  # the scanned target
    severity: Mapped[int] = mapped_column(Integer, nullable=False)  # weight contributed
    description: Mapped[str] = mapped_column(String(1024), nullable=False)
    source: Mapped[str] = mapped_column(String(30), default="rule_engine", nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scan: Mapped["Scan"] = relationship(back_populates="threats")
