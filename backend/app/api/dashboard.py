"""
Dashboard analytics — per PRD Section 6.8.
Aggregates the current user's scan history into summary stats, a severity
distribution, recent scans, and a daily risk-score trend.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan
from app.models.user import User, UserRole
from app.schemas.dashboard import DashboardStats, SeverityCount, RecentScan, TrendPoint
from app.security.deps import get_current_user

router = APIRouter()

THREAT_SEVERITIES = ("SUSPICIOUS", "HIGH", "CRITICAL")


@router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    trend_days: int = 14,
):
    query = db.query(Scan)
    if current_user.role == UserRole.USER:
        query = query.filter(Scan.user_id == current_user.id)

    total_scans = query.count()
    threats_detected = query.filter(Scan.severity.in_(THREAT_SEVERITIES)).count()
    critical_threats = query.filter(Scan.severity == "CRITICAL").count()
    safe_scans = query.filter(Scan.severity.in_(("SAFE", "LOW"))).count()

    dist_rows = (
        query.with_entities(Scan.severity, func.count(Scan.id))
        .group_by(Scan.severity)
        .all()
    )
    dist_map = {sev: count for sev, count in dist_rows}
    severity_distribution = [
        SeverityCount(severity=s, count=dist_map.get(s, 0))
        for s in ("SAFE", "LOW", "SUSPICIOUS", "HIGH", "CRITICAL")
    ]

    recent = (
        query.order_by(Scan.created_at.desc())
        .limit(8)
        .all()
    )
    recent_scans = [
        RecentScan(
            scan_id=s.id, scan_type=s.scan_type, target=s.target,
            risk_score=s.risk_score, severity=s.severity, created_at=s.created_at,
        )
        for s in recent
    ]

    since = datetime.now(timezone.utc) - timedelta(days=trend_days)
    trend_rows = (
        query.filter(Scan.created_at >= since)
        .with_entities(
            func.date_trunc("day", Scan.created_at).label("day"),
            func.avg(Scan.risk_score).label("avg_score"),
            func.count(Scan.id).label("count"),
        )
        .group_by("day")
        .order_by("day")
        .all()
    )
    risk_trend = [
        TrendPoint(date=row.day.date().isoformat(), avg_risk_score=round(float(row.avg_score), 1), scan_count=row.count)
        for row in trend_rows
    ]

    return DashboardStats(
        total_scans=total_scans,
        threats_detected=threats_detected,
        critical_threats=critical_threats,
        safe_scans=safe_scans,
        severity_distribution=severity_distribution,
        recent_scans=recent_scans,
        risk_trend=risk_trend,
    )
