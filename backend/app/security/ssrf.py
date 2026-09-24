"""
SSRF protection — required before this service ever fetches a user-submitted URL.

Per TRD §11 "SSRF Protection": accept only http/https, resolve DNS safely, reject
loopback/private/reserved ranges and cloud metadata endpoints, limit redirects,
enforce timeouts.
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}

# RFC 6052 "Well-Known Prefix" used by NAT64/DNS64 networks to represent a real
# IPv4 destination as an IPv6 address. Python's ipaddress module marks this
# whole /96 as is_reserved=True, which would block every legitimate site for
# anyone on an IPv6-only/NAT64 network (some ISPs, carriers, VPNs). The correct
# check is on the IPv4 address embedded in the last 32 bits, not the wrapper.
NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")


class SSRFError(Exception):
    """Raised when a URL/host fails SSRF safety checks."""


def _unwrap_nat64(ip: "ipaddress.IPv6Address") -> "ipaddress.IPv4Address | None":
    if ip in NAT64_WELL_KNOWN_PREFIX:
        return ipaddress.IPv4Address(ip.packed[12:])
    return None


def _is_blocked_ip(ip_str: str) -> bool:
    if ip_str in METADATA_IPS:
        return True
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address):
        embedded_v4 = _unwrap_nat64(ip)
        if embedded_v4 is not None:
            ip = embedded_v4  # validate the real destination, not the NAT64 wrapper
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_and_validate(hostname: str) -> list[str]:
    """Resolves a hostname and rejects it if ANY resolved address is unsafe
    (protects against DNS rebinding to internal ranges)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise SSRFError(f"DNS resolution failed for {hostname}: {e}") from e

    ips = {info[4][0] for info in infos}
    if not ips:
        raise SSRFError(f"No addresses resolved for {hostname}")

    for ip in ips:
        if _is_blocked_ip(ip):
            raise SSRFError(f"Blocked address range: {ip} (resolved from {hostname})")

    return list(ips)


def validate_url_for_fetch(url: str) -> None:
    """Raises SSRFError if this URL is not safe to fetch. Call before every hop,
    including redirects, not just the original URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"Unsupported scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise SSRFError("URL has no hostname")
    resolve_and_validate(parsed.hostname)
