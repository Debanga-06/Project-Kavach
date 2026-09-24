"""
Email Analyzer — per TRD Section 5 (Email Scanning) and PRD Section 6.3.

Parses sender info, extracts embedded URLs, and detects social-engineering
signals / suspicious attachment mentions. No real headers (SPF/DKIM) are
available from pasted content, so authentication-indicator checks are
intentionally left out of MVP scope rather than faked.

IMPORTANT: social-engineering language is split into distinct CATEGORIES
(pressure, verification request, security scare, suspension threat,
credential request, OTP request, financial lure, generic greeting) rather
than one flat keyword list. A phishing email typically stacks several of
these; collapsing them into a single bucket would silently cap the total
evidence regardless of how many distinct red flags are actually present.
Each phrase belongs to exactly one category, so there's no cross-category
double counting by construction.
"""
import re
from dataclasses import dataclass
from email.utils import parseaddr

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

SIGNAL_CATEGORIES: dict[str, list[str]] = {
    # Generic pressure language. Weak on its own — appears in plenty of
    # legitimate "please respond soon" emails too.
    "pressure": [
        "urgent", "immediately", "act now", "act fast", "limited time",
        "final notice", "as soon as possible", "right away", "without delay",
    ],
    # Explicit request to verify/confirm identity or account.
    "verification_request": [
        "verify your account", "verify your identity", "confirm your identity",
        "confirm your account", "re-verify", "authenticate your account",
    ],
    # Scare tactic implying the account is already compromised.
    "security_scare": [
        "unusual activity", "unauthorized access", "suspicious activity",
        "unusual sign-in", "unusual login", "suspicious login attempt",
    ],
    # Explicit threat of losing access unless the target acts.
    "suspension_threat": [
        "account will be closed", "account suspended", "account will be suspended",
        "account will be disabled", "account disabled", "account locked",
        "will be terminated", "avoid suspension", "account suspension",
        "permanently deleted",
    ],
    # Directly asking for a password/credential.
    "credential_request": [
        "enter your password", "enter your current password", "provide your password",
        "enter your credentials", "password will expire", "password expires",
        "password expiration", "confirm your password",
    ],
    # Directly asking for a one-time code — nobody legitimate needs this by email.
    "otp_request": [
        "one-time code", "one time code", "otp", "verification code",
        "security code", "enter the code",
    ],
    # Financial/payment lures — the "something's wrong, act now" scare.
    "financial_lure": [
        "wire transfer", "winner", "congratulations", "you have won",
        "update your payment", "payment could not be processed", "claim your prize",
    ],
    # Directly requesting sensitive financial data — distinct from the lure
    # above: one is a hook, the other is the actual data grab.
    "financial_data_request": [
        "confirm your banking information", "banking information", "gift card",
        "provide your card details", "provide your account number", "cvv",
    ],
    # Weak standalone signal — mass-phishing often skips a real name.
    "generic_greeting": [
        "dear customer", "dear user", "dear valued customer", "dear account holder",
    ],
}

RISKY_ATTACHMENT_EXTENSIONS = [".exe", ".scr", ".js", ".vbs", ".bat", ".jar", ".cmd", ".msi"]

# Brand -> legitimate domains. Used to flag "PayPal <support@paypa1-verify.com>" style impersonation.
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com"},
    "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
    "bank of america": {"bankofamerica.com"},
    "chase": {"chase.com"},
    "wells fargo": {"wellsfargo.com"},
    "irs": {"irs.gov"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "fb.com"},
}


@dataclass
class ParsedSender:
    display_name: str
    email: str
    domain: str


def parse_sender(raw_sender: str) -> ParsedSender:
    display_name, email = parseaddr(raw_sender.strip())
    domain = email.split("@")[-1].lower() if "@" in email else ""
    return ParsedSender(display_name=display_name.strip(), email=email.lower(), domain=domain)


def extract_urls(body: str) -> list[str]:
    return list(dict.fromkeys(URL_RE.findall(body)))  # dedupe, preserve order


def detect_signal_categories(text: str) -> dict[str, list[str]]:
    """Returns {category: [matched phrases]} for every category with at least
    one hit. Categories with no hits are omitted entirely."""
    lower = text.lower()
    hits: dict[str, list[str]] = {}
    for category, phrases in SIGNAL_CATEGORIES.items():
        matched = [p for p in phrases if p in lower]
        if matched:
            hits[category] = matched
    return hits


def detect_attachment_mentions(text: str) -> list[str]:
    lower = text.lower()
    return [ext for ext in RISKY_ATTACHMENT_EXTENSIONS if ext in lower]


def check_brand_impersonation(sender: ParsedSender) -> str | None:
    """Returns the impersonated brand name if display name claims a brand
    the sending domain doesn't belong to, else None."""
    name_lower = sender.display_name.lower()
    for brand, domains in BRAND_DOMAINS.items():
        if brand in name_lower and sender.domain not in domains:
            if not any(sender.domain.endswith("." + d) for d in domains):
                return brand
    return None
