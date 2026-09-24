"""
Email rule engine — combines sender analysis, categorized social-engineering
signals, attachment-mention checks, and embedded-URL risk (via the existing
URL rule engine) into one evidence list + score.

Each signal category contributes ONE fixed weight regardless of how many
phrases within that category matched (avoids double-counting a single
underlying signal, e.g. "urgent" + "immediately" both matching "pressure"
only counts once). Distinct categories stack normally, since they represent
genuinely independent red flags.
"""
from dataclasses import dataclass

from app.services.email_analyzer import ParsedSender
from app.services.url_analyzer import normalize_url, extract_features, InvalidURLError
from app.services.rule_engine import evaluate as evaluate_url_rules, Evidence

# Fixed weight per category — NOT multiplied by number of matched phrases.
CATEGORY_WEIGHTS = {
    "pressure": 10,
    "verification_request": 15,
    "security_scare": 15,
    "suspension_threat": 20,
    "credential_request": 25,
    "otp_request": 25,
    "financial_lure": 15,
    "financial_data_request": 25,
    "generic_greeting": 5,
}

CATEGORY_LABELS = {
    "pressure": "Urgency/pressure language",
    "verification_request": "Account verification request",
    "security_scare": "Security-scare / unusual-activity language",
    "suspension_threat": "Account suspension threat",
    "credential_request": "Credential/password request",
    "otp_request": "One-time code / OTP request",
    "financial_lure": "Financial lure (payment/prize scare)",
    "financial_data_request": "Direct request for financial account data",
    "generic_greeting": "Generic greeting (no personalization)",
}

# Categories serious enough, on their own, to matter for verdict escalation —
# excludes "pressure" and "generic_greeting", which are weak in isolation and
# common in legitimate mail too.
STRONG_CATEGORIES = {
    "verification_request", "security_scare", "suspension_threat",
    "credential_request", "otp_request", "financial_lure", "financial_data_request",
}

COMBINATION_ESCALATION_THRESHOLD = 2  # 2+ distinct strong categories together


@dataclass
class EmailRuleResult:
    score: int
    evidence: list[Evidence]
    urls_found: list[str]


def evaluate_email(
    sender: ParsedSender,
    subject: str,
    body: str,
    signal_categories: dict[str, list[str]],
    attachment_hits: list[str],
    impersonated_brand: str | None,
    urls: list[str],
) -> EmailRuleResult:
    evidence: list[Evidence] = []

    def flag(signal: str, description: str, weight: int):
        evidence.append(Evidence(signal=signal, description=description, weight=weight))

    if impersonated_brand:
        flag(
            "brand_impersonation",
            f"Sender display name claims to be '{impersonated_brand.title()}' but the sending "
            f"domain ('{sender.domain}') does not belong to that company.",
            30,
        )

    if not sender.email or "@" not in sender.email:
        flag("malformed_sender", "Sender address could not be parsed as a valid email.", 10)

    # One evidence entry per CATEGORY, fixed weight — this is the core fix.
    # Previously all social-engineering phrases fed one bucket capped at 25
    # total; now each of the 8 categories is scored independently.
    for category, matched_phrases in signal_categories.items():
        phrases_shown = ", ".join(f'"{p}"' for p in matched_phrases[:4])
        flag(
            category,
            f"{CATEGORY_LABELS[category]}: {phrases_shown}.",
            CATEGORY_WEIGHTS[category],
        )

    strong_hit_categories = set(signal_categories) & STRONG_CATEGORIES
    if len(strong_hit_categories) >= COMBINATION_ESCALATION_THRESHOLD:
        # Tiered: more co-occurring strong indicators = proportionally more
        # dangerous than their individual weights suggest on their own.
        n = len(strong_hit_categories)
        bonus = min(15 + 5 * (n - 2), 25)
        names = ", ".join(sorted(strong_hit_categories))
        flag(
            "combined_indicators",
            f"{n} independent strong phishing indicators appear together "
            f"({names}) — in combination these are more dangerous than any single signal alone.",
            bonus,
        )

    if attachment_hits:
        exts = ", ".join(attachment_hits)
        flag(
            "risky_attachment_mention",
            f"Email references file types commonly used to deliver malware: {exts}.",
            20,
        )

    # Reuse the URL rule engine on every embedded link — this is the same
    # detection logic Step 4 built for the standalone URL scanner.
    max_url_score = 0
    worst_url_signals: list[Evidence] = []
    for raw_url in urls[:5]:  # cap to avoid pathological emails with hundreds of links
        try:
            normalized = normalize_url(raw_url)
        except InvalidURLError:
            continue
        features = extract_features(normalized)
        result = evaluate_url_rules(features)
        if result.score > max_url_score:
            max_url_score = result.score
            worst_url_signals = result.evidence

    if worst_url_signals:
        flag(
            "embedded_link_risk",
            f"Email contains a link with its own risk signals (score {max_url_score}/100): "
            + "; ".join(e.description for e in worst_url_signals[:2]),
            min(round(max_url_score * 0.5), 30),
        )

    score = min(sum(e.weight for e in evidence), 100)
    return EmailRuleResult(score=score, evidence=evidence, urls_found=urls)
