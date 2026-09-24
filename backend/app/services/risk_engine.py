"""
Risk Engine — per TRD Section 7.

Combines independent signal sources into one 0-100 score. Target weighting
per the TRD: ML 35% / Threat Intel 25% / Rules 20% / Domain 10% / Website 10%.

Currently wired: rule engine (always) + ML classifier (Logistic Regression,
trained on synthetic bootstrap data — see ml/README.md) for URL scans.
Threat-intel/domain/website scoring don't exist yet. Missing sources have
their target weight redistributed onto whatever IS available rather than
being silently treated as "safe".

VERDICT LOGIC: severity (the numeric score band) and classification (the
verdict) are related but distinct — a low numeric score with multiple
independently-strong indicators can still escalate the verdict, per PRD/TRD
"multiple strong indicators should be able to escalate the final verdict."
Kept internally as SAFE/LOW/SUSPICIOUS/HIGH/CRITICAL (SUSPICIOUS == "MEDIUM"
in product terms) rather than renamed, to avoid a breaking API/frontend
change across the dashboard, recommendations, and UI color mapping that all
key off these exact strings.
"""
from dataclasses import dataclass

TARGET_WEIGHTS = {
    "ml": 0.35,
    "threat_intel": 0.25,
    "rules": 0.20,
    "domain": 0.10,
    "website": 0.10,
}

# Signals strong/specific enough, in combination with at least one other
# strong signal, to override a purely score-band-driven verdict.
CORROBORATING_SIGNALS = {
    "verification_request", "security_scare", "suspension_threat",
    "financial_lure", "malformed_sender",
}

# Signals damning enough on their OWN — essentially no legitimate email/URL
# construct produces these — to escalate the verdict without needing a
# second corroborating signal. These are structural/behavioral deceptions
# (cloaking tricks, direct requests for credentials/financial data), not
# just suspicious wording that could theoretically appear in genuine urgent
# mail too.
SOLO_ESCALATING_SIGNALS = {
    "ip_based_host", "at_symbol_present", "redirect_domain_mismatch",
    "brand_impersonation", "embedded_link_risk",
    "credential_request", "otp_request", "financial_data_request",
}

STRONG_SIGNALS = CORROBORATING_SIGNALS | SOLO_ESCALATING_SIGNALS | {"combined_indicators"}


@dataclass
class RiskResult:
    score: int
    severity: str
    classification: str
    confidence: float


def _severity_for(score: int) -> str:
    if score <= 19:
        return "SAFE"
    if score <= 39:
        return "LOW"
    if score <= 59:
        return "SUSPICIOUS"  # product-facing label: MEDIUM
    if score <= 79:
        return "HIGH"
    return "CRITICAL"


def _classification_for(severity: str, evidence_signals: set[str]) -> str:
    """
    Verdict escalates on TWO independent axes: the numeric severity band,
    AND which signals fired — matching the requirement that "classification
    should NOT depend only on the total numeric score." SOLO_ESCALATING
    signals (structural deceptions like @-cloaking, IP hosts, credential
    requests) can push the verdict up alone; CORROBORATING signals (wording
    that could theoretically appear in legitimate urgent mail) need at least
    one partner. This only ever escalates classification upward relative to
    severity — a low numeric score can never carry a PHISHING verdict,
    avoiding the inconsistent "score 25, verdict PHISHING" case.
    """
    solo_hits = evidence_signals & SOLO_ESCALATING_SIGNALS
    strong_hits = evidence_signals & STRONG_SIGNALS

    if severity == "CRITICAL":
        return "PHISHING"
    if severity == "HIGH":
        return "PHISHING" if strong_hits else "SUSPICIOUS"
    if severity == "SUSPICIOUS":
        if solo_hits or len(strong_hits) >= 2:
            return "PHISHING"
        return "SUSPICIOUS"
    if severity == "LOW":
        if solo_hits:
            return "PHISHING"
        return "SUSPICIOUS" if strong_hits else "SAFE"
    # SAFE severity band (score <= 19) — cap escalation at SUSPICIOUS even
    # with a solo signal, since a PHISHING verdict on a near-zero score
    # would itself be an internal contradiction.
    if solo_hits or len(strong_hits) >= 2:
        return "SUSPICIOUS"
    return "SAFE"


def compute_risk(
    rule_score: int,
    evidence_signals: set[str],
    *,
    ml_score: float | None = None,
    ti_score: float | None = None,
    domain_score: float | None = None,
    website_score: float | None = None,
    network_checked: bool = False,
) -> RiskResult:
    available = {"rules": rule_score}
    if ml_score is not None:
        available["ml"] = ml_score
    if ti_score is not None:
        available["threat_intel"] = ti_score
    if domain_score is not None:
        available["domain"] = domain_score
    if website_score is not None:
        available["website"] = website_score

    total_target_weight = sum(TARGET_WEIGHTS[k] for k in available)
    final_score = sum(available[k] * (TARGET_WEIGHTS[k] / total_target_weight) for k in available)
    final_score = round(max(0, min(final_score, 100)))

    severity = _severity_for(final_score)
    classification = _classification_for(severity, evidence_signals)

    strong_hits = evidence_signals & STRONG_SIGNALS

    # Confidence reflects CERTAINTY, not danger — a SAFE result with zero
    # signals can be reported with high confidence; a borderline result with
    # one ambiguous signal should not. Strong/specific signals raise
    # confidence more than an equal number of weak/generic ones would.
    signal_count = len(evidence_signals)
    confidence = 0.45 + min(signal_count * 0.05, 0.25)
    if strong_hits:
        confidence += 0.15
    if len(strong_hits) >= 2:
        confidence += 0.10
    if network_checked:
        confidence += 0.05
    confidence = round(min(confidence, 0.97), 2)

    return RiskResult(score=final_score, severity=severity, classification=classification, confidence=confidence)
