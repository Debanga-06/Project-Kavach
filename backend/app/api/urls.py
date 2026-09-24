"""
URL scanning endpoints — orchestrates the pipeline from TRD Section 5:
validate -> normalize -> SSRF-safe fetch -> extract features -> rule engine
-> risk engine -> persist -> return report.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan, Threat
from app.models.user import User, UserRole
from app.schemas.scan import URLScanRequest, ScanOut, EvidenceOut, ScanSummaryOut
from app.security.deps import get_current_user
from app.services.url_analyzer import InvalidURLError, normalize_url, extract_features, safe_fetch
from app.services.rule_engine import evaluate as evaluate_rules
from app.services.risk_engine import compute_risk
from app.services.recommendations import recommendations_for
from app.services import ml_classifier
from app.services import ai_analyzer
from app.models.ai_report import AIReport

router = APIRouter()


@router.post("/scan/url", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def scan_url(payload: URLScanRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        normalized = normalize_url(payload.url)
    except InvalidURLError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    features = extract_features(normalized)
    # normalize_url() strips userinfo (the "user@" part) when reconstructing the URL,
    # so the '@' cloaking trick must be detected on the RAW input, before that stripping.
    if "@" in payload.url:
        features.has_at_symbol = True

    # SSRF-safe live verification (redirects, reachability). Failures degrade
    # gracefully — scoring continues on structural signals alone.
    redirect_count, final_url, fetch_error = safe_fetch(normalized)
    features.redirect_count = redirect_count
    features.final_url = final_url
    features.fetch_error = fetch_error
    features.network_checked = fetch_error is None

    rule_result = evaluate_rules(features)
    evidence_signals = {e.signal for e in rule_result.evidence}

    ml_score = ml_classifier.predict(features)

    risk = compute_risk(
        rule_result.score,
        evidence_signals,
        ml_score=ml_score,
        network_checked=features.network_checked,
    )
    recs = recommendations_for(risk.severity)

    evidence_list = list(rule_result.evidence)
    if ml_score is not None:
        from app.services.rule_engine import Evidence
        evidence_list.append(Evidence(
            signal="ml_classifier",
            description=f"Baseline ML classifier estimates a {ml_score:.0f}% probability this URL is phishing, "
                        "based on structural features (independent of the rule engine above).",
            weight=0,  # informational — its contribution is already folded into risk.score via risk_engine
        ))

    scan = Scan(
        user_id=current_user.id,
        scan_type="url",
        target=normalized,
        risk_score=risk.score,
        severity=risk.severity,
        classification=risk.classification,
        confidence=risk.confidence,
        status="completed",
        recommendations=recs,
    )
    db.add(scan)
    db.flush()  # get scan.id before creating dependent Threat rows

    for e in evidence_list:
        db.add(Threat(
            scan_id=scan.id,
            threat_type=e.signal,
            indicator=normalized,
            severity=e.weight,
            description=e.description,
            source="ml_classifier" if e.signal == "ml_classifier" else "rule_engine",
        ))

    db.commit()
    db.refresh(scan)

    # AI explanation is purely descriptive — it never touches risk.score/severity/
    # classification, which were already finalized above. Failures fall back to a
    # deterministic template internally, so this never blocks the scan result.
    ai = ai_analyzer.explain_threat(
        risk_score=risk.score, severity=risk.severity, classification=risk.classification,
        evidence=rule_result.evidence, target=normalized,
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
        evidence=[EvidenceOut(signal=e.signal, description=e.description, weight=e.weight) for e in evidence_list],
        recommendations=scan.recommendations,
        ai_summary=ai.summary,
        ai_explanation=ai.explanation,
        ai_model=ai.model,
        created_at=scan.created_at,
    )


@router.get("/scan/url/{scan_id}", response_model=ScanOut)
def get_url_scan(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan or scan.scan_type != "url":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    _authorize_scan_access(scan, current_user)

    ai_report = (
        db.query(AIReport).filter(AIReport.scan_id == scan.id).order_by(AIReport.created_at.desc()).first()
    )

    return ScanOut(
        scan_id=scan.id,
        scan_type=scan.scan_type,
        target=scan.target,
        risk_score=scan.risk_score,
        severity=scan.severity,
        classification=scan.classification,
        confidence=scan.confidence,
        status=scan.status,
        evidence=[
            EvidenceOut(signal=t.threat_type, description=t.description, weight=t.severity)
            for t in scan.threats
        ],
        recommendations=scan.recommendations,
        ai_summary=ai_report.summary if ai_report else None,
        ai_explanation=ai_report.explanation if ai_report else [],
        ai_model=ai_report.model if ai_report else None,
        created_at=scan.created_at,
    )


@router.get("/scans", response_model=list[ScanSummaryOut])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user), limit: int = 50):
    query = db.query(Scan)
    if current_user.role == UserRole.USER:
        query = query.filter(Scan.user_id == current_user.id)
    scans = query.order_by(Scan.created_at.desc()).limit(min(limit, 200)).all()
    return [
        ScanSummaryOut(
            scan_id=s.id, scan_type=s.scan_type, target=s.target,
            risk_score=s.risk_score, severity=s.severity, classification=s.classification,
            created_at=s.created_at,
        )
        for s in scans
    ]


def _authorize_scan_access(scan: Scan, user: User):
    if user.role == UserRole.USER and scan.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your scan")
