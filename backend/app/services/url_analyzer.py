"""
URL analysis: validation, normalization, structural feature extraction,
and SSRF-safe network verification (redirect chain, reachability).
"""
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

from app.security.ssrf import SSRFError, validate_url_for_fetch

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "webscr", "password", "billing", "suspend",
]
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click"}
IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
# Registrable hostname: labels of letters/digits/hyphens separated by dots (also matches raw IPs).
VALID_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")


class InvalidURLError(Exception):
    pass


@dataclass
class URLFeatures:
    normalized_url: str
    scheme: str
    hostname: str
    url_length: int
    domain_length: int
    subdomain_count: int
    digit_count: int
    special_char_count: int
    is_https: bool
    is_ip_host: bool
    has_at_symbol: bool
    hyphen_count: int
    suspicious_keyword_hits: list[str]
    tld: str
    suspicious_tld: bool
    redirect_count: int = 0
    final_url: str | None = None
    fetch_error: str | None = None
    network_checked: bool = False


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise InvalidURLError("URL is empty")
    if not URL_SCHEME_RE.match(url):
        url = "http://" + url

    if any(ch.isspace() for ch in url):
        raise InvalidURLError("URL must not contain whitespace")

    parsed = urlparse(url)
    if not parsed.hostname:
        raise InvalidURLError("URL has no hostname")
    if not VALID_HOSTNAME_RE.match(parsed.hostname):
        raise InvalidURLError(f"'{parsed.hostname}' is not a valid hostname")

    scheme = parsed.scheme.lower()
    netloc = (parsed.hostname or "").lower()
    if parsed.port and not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
        netloc += f":{parsed.port}"

    path = parsed.path or "/"
    normalized = f"{scheme}://{netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized


def extract_features(url: str) -> URLFeatures:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    domain_parts = hostname.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    subdomain_count = max(len(domain_parts) - 2, 0)
    keyword_hits = [
        kw for kw in SUSPICIOUS_KEYWORDS
        if re.search(r"\b" + re.escape(kw) + r"\b", url.lower())
    ]

    return URLFeatures(
        normalized_url=url,
        scheme=parsed.scheme,
        hostname=hostname,
        url_length=len(url),
        domain_length=len(hostname),
        subdomain_count=subdomain_count,
        digit_count=sum(c.isdigit() for c in url),
        special_char_count=sum(1 for c in url if c in "!#$%^&*()_+=[]{}|\\;:'\",<>?"),
        is_https=parsed.scheme == "https",
        is_ip_host=bool(IP_HOST_RE.match(hostname)),
        has_at_symbol="@" in url,
        hyphen_count=hostname.count("-"),
        suspicious_keyword_hits=keyword_hits,
        tld=tld,
        suspicious_tld=tld in SUSPICIOUS_TLDS,
    )


def safe_fetch(url: str, max_redirects: int = 3, timeout: float = 4.0) -> tuple[int, str, str | None]:
    """Follows redirects manually, re-validating each hop against SSRF rules
    before connecting. Returns (redirect_count, final_url, error_or_None)."""
    current = url
    for hop in range(max_redirects + 1):
        try:
            validate_url_for_fetch(current)
        except SSRFError as e:
            return hop, current, str(e)

        try:
            resp = requests.get(
                current,
                allow_redirects=False,
                timeout=timeout,
                headers={"User-Agent": "KavachAI-Scanner/1.0"},
            )
        except requests.RequestException as e:
            return hop, current, f"fetch failed: {e}"

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                return hop, current, "redirect with no Location header"
            current = urljoin(current, location)
            continue

        return hop, current, None

    return max_redirects, current, "too many redirects"
