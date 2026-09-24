"""
Email scanning endpoint — per TRD Section 5 (Email Scanning pipeline).
"""
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan, Threat
from app.models.user import User
from app.schemas.email import EmailScanRequest
from app.schemas.scan import ScanOut, EvidenceOut
from app.security.deps import get_current_user
from app.services.email_analyzer import (
    parse_sender, extract_urls, detect_signal_categories,
    detect_attachment_mentions, check_brand_impersonation,
)
from app.services.email_rule_engine import evaluate_email
from app.services.risk_engine import compute_risk
from app.services.recommendations import recommendations_for
from app.services import ai_analyzer
from app.models.ai_report import AIReport

router = APIRouter()


@router.post("/scan/email", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def scan_email(
    payload: EmailScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sender = parse_sender(payload.sender)
    urls = extract_urls(payload.body)
    signal_categories = detect_signal_categories(payload.subject + " " + payload.body)
    attachment_hits = detect_attachment_mentions(payload.body)
    impersonated_brand = check_brand_impersonation(sender)

    rule_result = evaluate_email(
        sender=sender,
        subject=payload.subject,
        body=payload.body,
        signal_categories=signal_categories,
        attachment_hits=attachment_hits,
        impersonated_brand=impersonated_brand,
        urls=urls,
    )
    evidence_signals = {e.signal for e in rule_result.evidence}

    risk = compute_risk(rule_result.score, evidence_signals, network_checked=False)
    recs = recommendations_for(risk.severity)

    target = sender.email if sender.email else payload.sender[:2048]

    scan = Scan(
        user_id=current_user.id,
        scan_type="email",
        target=target,
        risk_score=risk.score,
        severity=risk.severity,
        classification=risk.classification,
        confidence=risk.confidence,
        status="completed",
        recommendations=recs,
    )
    db.add(scan)
    db.flush()

    for e in rule_result.evidence:
        db.add(Threat(
            scan_id=scan.id,
            threat_type=e.signal,
            indicator=target,
            severity=e.weight,
            description=e.description,
            source="rule_engine",
        ))

    db.commit()
    db.refresh(scan)

    ai = ai_analyzer.explain_threat(
        risk_score=risk.score, severity=risk.severity, classification=risk.classification,
        evidence=rule_result.evidence, target=target,
    )
    db.add(AIReport(
        scan_id=scan.id, summary=ai.summary, explanation=ai.explanation,
        recommendations=recs, model=ai.model,
    ))
    db.commit()

    return ScanOut(
        scan_id=scan.id,
        scan_type=scan.scan_type,
        target=scan.target,
        risk_score=scan.risk_score,
        severity=scan.severity,
        classification=scan.classification,
        confidence=scan.confidence,
        status=scan.status,
        evidence=[EvidenceOut(signal=e.signal, description=e.description, weight=e.weight) for e in rule_result.evidence],
        recommendations=scan.recommendations,
        ai_summary=ai.summary,
        ai_explanation=ai.explanation,
        ai_model=ai.model,
        created_at=scan.created_at,
    )
