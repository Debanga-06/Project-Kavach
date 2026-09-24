"""Security recommendations — per PRD Section 6.10.

Keyed by severity (SAFE/LOW/SUSPICIOUS/HIGH/CRITICAL — "SUSPICIOUS" is the
internal name for the product-facing "MEDIUM" tier; see risk_engine.py for
why the string wasn't renamed). Shared between URL and email scans, so
wording stays generic enough to apply to either ("this page or message").
"""

BY_SEVERITY = {
    "SAFE": [
        "No action needed based on current signals.",
        "Continue standard security practices.",
    ],
    "LOW": [
        "Proceed with normal caution.",
        "Verify unexpected requests before acting on them.",
    ],
    "SUSPICIOUS": [
        "Avoid clicking unexpected links or downloading attachments.",
        "Verify the sender or source through a separate, trusted channel before proceeding.",
    ],
    "HIGH": [
        "Do not click links or open attachments.",
        "Do not provide credentials, OTPs, or personal information.",
        "Verify the sender through an official channel before taking any action.",
    ],
    "CRITICAL": [
        "Do not interact with this page or message.",
        "Do not provide passwords, OTPs, financial information, or other sensitive data.",
        "Report it to your security team or email provider.",
        "If you already entered any information, change your credentials immediately and enable MFA.",
    ],
}


def recommendations_for(severity: str) -> list[str]:
    return BY_SEVERITY.get(severity, BY_SEVERITY["SUSPICIOUS"])
