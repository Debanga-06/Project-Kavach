"""
Rule-based URL analysis — deterministic signals, no ML/LLM involved.
Each triggered rule contributes weighted points (capped at 100) and an
Evidence entry explaining what was found and why it matters.
"""
from dataclasses import dataclass

from app.services.url_analyzer import URLFeatures


@dataclass
class Evidence:
    signal: str
    description: str
    weight: int


@dataclass
class RuleResult:
    score: int  # 0-100
    evidence: list[Evidence]


def evaluate(features: URLFeatures) -> RuleResult:
    evidence: list[Evidence] = []

    def flag(signal: str, description: str, weight: int):
        evidence.append(Evidence(signal=signal, description=description, weight=weight))

    if features.is_ip_host:
        flag(
            "ip_based_host",
            f"The domain is a raw IP address ({features.hostname}) rather than a registered name — "
            "a common technique to obscure the real destination.",
            25,
        )

    if features.has_at_symbol:
        flag(
            "at_symbol_present",
            "URL contains an '@' symbol. Browsers ignore everything before it when connecting, "
            "so it can be used to disguise the real destination behind a trusted-looking prefix.",
            22,
        )

    if not features.is_https:
        flag(
            "no_https",
            "Connection is not encrypted (HTTP, not HTTPS) — credentials or data submitted here "
            "would be sent in plaintext.",
            15,
        )

    if features.suspicious_keyword_hits:
        kw = ", ".join(features.suspicious_keyword_hits[:5])
        flag(
            "suspicious_keywords",
            f"URL contains phishing-associated terms: {kw}.",
            min(6 * len(features.suspicious_keyword_hits), 20),
        )

    if features.subdomain_count > 3:
        flag(
            "excessive_subdomains",
            f"{features.subdomain_count} subdomain levels detected — often used to bury a "
            "suspicious host under a trusted-looking prefix.",
            10,
        )

    if features.hyphen_count >= 2:
        flag(
            "excessive_hyphens",
            f"Domain contains {features.hyphen_count} hyphens, a pattern common in "
            "typosquatted/lookalike domains (e.g. paypal-secure-login.com).",
            8,
        )

    if features.suspicious_tld:
        flag(
            "suspicious_tld",
            f"Top-level domain '.{features.tld}' is disproportionately associated with "
            "spam and phishing campaigns.",
            15,
        )

    if features.url_length > 90:
        flag(
            "excessive_length",
            f"URL is unusually long ({features.url_length} characters) — often used to hide "
            "the real path or obfuscate payload parameters.",
            8,
        )

    if features.digit_count >= 4:
        flag(
            "numeric_domain",
            "Domain contains an unusually high number of digits, atypical for legitimate brand domains.",
            6,
        )

    if features.redirect_count and features.redirect_count > 2:
        flag(
            "long_redirect_chain",
            f"URL redirects {features.redirect_count} times before reaching its final destination.",
            10,
        )

    if features.final_url and features.final_url != features.normalized_url:
        from urllib.parse import urlparse
        original_domain = features.hostname
        final_domain = urlparse(features.final_url).hostname
        if final_domain and original_domain and final_domain != original_domain:
            flag(
                "redirect_domain_mismatch",
                f"URL redirects to a different domain ({final_domain}) than the one submitted "
                f"({original_domain}) — a common cloaking technique.",
                15,
            )

    if features.fetch_error:
        flag(
            "unreachable",
            f"The destination could not be reached for live verification: {features.fetch_error}. "
            "Scoring below is based on structural analysis only.",
            5,
        )

    score = min(sum(e.weight for e in evidence), 100)
    return RuleResult(score=score, evidence=evidence)
