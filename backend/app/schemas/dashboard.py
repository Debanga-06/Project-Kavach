from datetime import datetime

from pydantic import BaseModel


class SeverityCount(BaseModel):
    severity: str
    count: int


class RecentScan(BaseModel):
    scan_id: str
    scan_type: str
    target: str
    risk_score: int
    severity: str
    created_at: datetime


class TrendPoint(BaseModel):
    date: str
    avg_risk_score: float
    scan_count: int


class DashboardStats(BaseModel):
    total_scans: int
    threats_detected: int
    critical_threats: int
    safe_scans: int
    severity_distribution: list[SeverityCount]
    recent_scans: list[RecentScan]
    risk_trend: list[TrendPoint]
