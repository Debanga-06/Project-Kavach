"""
Tests for the email classification fix (see conversation deliverable).
Pure service-layer tests — no DB, no FastAPI, no network — so they run
fast and deterministically.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.email_analyzer import (
    parse_sender, extract_urls, detect_signal_categories,
    detect_attachment_mentions, check_brand_impersonation,
)
from app.services.email_rule_engine import evaluate_email
from app.services.risk_engine import compute_risk


def run_email(sender_str, subject, body):
    sender = parse_sender(sender_str)
    urls = extract_urls(body)
    signal_categories = detect_signal_categories(subject + " " + body)
    attachment_hits = detect_attachment_mentions(body)
    impersonated_brand = check_brand_impersonation(sender)

    rule_result = evaluate_email(
        sender=sender, subject=subject, body=body,
        signal_categories=signal_categories, attachment_hits=attachment_hits,
        impersonated_brand=impersonated_brand, urls=urls,
    )
    evidence_signals = {e.signal for e in rule_result.evidence}
    risk = compute_risk(rule_result.score, evidence_signals, network_checked=False)
    return risk, rule_result


def test_1_clearly_legitimate_email():
    risk, _ = run_email(
        "Alex <alex@company.com>",
        "Meeting Reminder",
        "Hi John,\n\nJust a reminder that our project meeting is scheduled for tomorrow at 10 AM.\n\nRegards,\nAlex",
    )
    assert risk.classification == "SAFE", f"got {risk.classification} (score={risk.score})"


def test_2_urgency_only_not_phishing():
    risk, _ = run_email(
        "Team <team@company.com>",
        "Urgent Notice",
        "Please review this message as soon as possible.\n\nRegards,\nTeam",
    )
    assert risk.classification in ("SAFE", "SUSPICIOUS") and risk.severity in ("SAFE", "LOW"), (
        f"'urgent' alone should not read as phishing — got {risk.classification}/{risk.severity} (score={risk.score})"
    )
    assert risk.classification != "PHISHING"


def test_3_account_phishing_the_reported_bug():
    """This is the exact bug from the report: must NOT be SAFE·51%."""
    risk, rule_result = run_email(
        "Security Team <security@totally-fake-domain-example.net>",
        "Urgent: Verify Your Account",
        "Dear User,\n\nWe detected unusual activity on your account.\n\n"
        "You must immediately verify your account or your account will be suspended.\n\n"
        "Click here to verify your account.",
    )
    print(f"\nTest 3 -> score={risk.score} severity={risk.severity} "
          f"classification={risk.classification} confidence={risk.confidence}")
    for e in rule_result.evidence:
        print(f"  +{e.weight} [{e.signal}] {e.description}")

    assert risk.classification == "PHISHING", f"got {risk.classification} (score={risk.score})"
    assert risk.severity in ("HIGH", "CRITICAL"), f"got severity={risk.severity} (score={risk.score})"
    assert not (risk.classification == "SAFE" and risk.confidence <= 0.55), "reproduced the original bug!"


def test_4_credential_phishing():
    risk, rule_result = run_email(
        "IT Support <support@some-generic-service.com>",
        "Password Expiration Warning",
        "Your password will expire today.\n\n"
        "Click the link below and enter your current password to prevent account suspension.",
    )
    print(f"\nTest 4 -> score={risk.score} severity={risk.severity} classification={risk.classification}")
    for e in rule_result.evidence:
        print(f"  +{e.weight} [{e.signal}] {e.description}")
    assert risk.classification == "PHISHING", f"got {risk.classification} (score={risk.score})"
    assert risk.severity in ("HIGH", "CRITICAL"), f"got severity={risk.severity} (score={risk.score})"


def test_5_financial_phishing():
    risk, rule_result = run_email(
        "Billing <billing@some-generic-vendor.com>",
        "Payment Verification Required",
        "Your payment could not be processed.\n\n"
        "Please confirm your banking information using the link below.",
    )
    print(f"\nTest 5 -> score={risk.score} severity={risk.severity} classification={risk.classification}")
    for e in rule_result.evidence:
        print(f"  +{e.weight} [{e.signal}] {e.description}")
    assert risk.classification == "PHISHING", f"got {risk.classification} (score={risk.score})"
    # Severity intentionally is NOT required to be HIGH/CRITICAL here — this
    # is exactly the "classification should not depend only on the numeric
    # score" case: two corroborating strong signals (a payment-failure lure
    # + a direct banking-info request) earn a PHISHING verdict even though
    # the raw score alone lands in the SUSPICIOUS band.
    assert risk.severity in ("SUSPICIOUS", "HIGH", "CRITICAL"), f"got severity={risk.severity} (score={risk.score})"


def test_6_legitimate_security_notification_not_flagged():
    """A REAL security email (e.g. 'new device sign-in') should not be
    treated the same as a phishing email just because it mentions security."""
    risk, _ = run_email(
        "Company IT <it@company.com>",
        "New device signed in to your account",
        "Hi,\n\nWe noticed a new sign-in to your account from a Mac device in your usual location.\n"
        "If this was you, no action is needed. If you don't recognize this activity, "
        "please contact IT at extension 4400.",
    )
    print(f"\nTest 6 -> score={risk.score} severity={risk.severity} classification={risk.classification}")
    assert risk.classification != "PHISHING", (
        f"legitimate security notification wrongly flagged as PHISHING (score={risk.score})"
    )


def test_no_double_counting_within_category():
    """Repeating multiple phrases from the SAME category must not multiply
    the score — each category contributes its fixed weight exactly once."""
    risk_one_phrase, _ = run_email(
        "Team <team@company.com>", "Notice", "Please act now.",
    )
    risk_many_phrases, _ = run_email(
        "Team <team@company.com>", "Notice",
        "Urgent! Immediately act now, act fast, this is a final notice with limited time remaining.",
    )
    # Both hit ONLY the "pressure" category — score must be identical (10),
    # not multiplied by the number of matched phrases.
    assert risk_one_phrase.score == risk_many_phrases.score == 10, (
        f"double-counting detected: {risk_one_phrase.score} vs {risk_many_phrases.score} (expected 10, 10)"
    )


def test_score_severity_classification_never_contradict():
    """The forbidden case from the spec: e.g. score=85/CRITICAL/verdict=SAFE."""
    cases = [
        ("Alex <alex@company.com>", "Meeting Reminder", "See you tomorrow at 10."),
        ("Security <security@fake-domain-xyz.net>", "Urgent: Verify Your Account",
         "Dear User, we detected unusual activity. Immediately verify your account or "
         "your account will be suspended. Click here to verify your account."),
        ("IT <it@generic-vendor.com>", "Password Expiration Warning",
         "Your password will expire today. Enter your current password to prevent account suspension."),
    ]
    for sender, subject, body in cases:
        risk, _ = run_email(sender, subject, body)
        if risk.severity == "CRITICAL":
            assert risk.classification == "PHISHING"
        if risk.classification == "PHISHING":
            assert risk.severity in ("SUSPICIOUS", "HIGH", "CRITICAL")
        if risk.severity in ("SAFE",):
            assert risk.classification in ("SAFE", "SUSPICIOUS")  # never PHISHING at SAFE band


def test_url_scanner_regression_still_works():
    """Make sure fixing email classification didn't break the URL scanner,
    which shares risk_engine.compute_risk()."""
    from app.services.url_analyzer import normalize_url, extract_features
    from app.services.rule_engine import evaluate as evaluate_url_rules

    normalized = normalize_url("https://paypal.com/myaccount")
    features = extract_features(normalized)
    rule_result = evaluate_url_rules(features)
    evidence_signals = {e.signal for e in rule_result.evidence}
    risk = compute_risk(rule_result.score, evidence_signals, network_checked=True)
    assert risk.severity == "SAFE", f"legit paypal.com regressed: {risk.severity} (score={risk.score})"

    normalized_bad = normalize_url("http://trusted-bank.com@evil-attacker.xyz/login")
    features_bad = extract_features(normalized_bad)
    features_bad.has_at_symbol = True
    rule_result_bad = evaluate_url_rules(features_bad)
    evidence_signals_bad = {e.signal for e in rule_result_bad.evidence}
    risk_bad = compute_risk(rule_result_bad.score, evidence_signals_bad, network_checked=False)
    assert risk_bad.classification == "PHISHING", f"@ cloaking regressed: {risk_bad.classification}"
