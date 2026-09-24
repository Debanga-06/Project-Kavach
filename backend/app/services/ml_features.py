"""
Converts URLFeatures into a fixed-order numeric vector.
Used by BOTH the training script (ml/training/) and the live inference
service (ml_classifier.py) so there's no train/serve skew.
"""
from app.services.url_analyzer import URLFeatures

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "subdomain_count",
    "digit_count",
    "special_char_count",
    "hyphen_count",
    "is_https",
    "is_ip_host",
    "has_at_symbol",
    "suspicious_keyword_count",
    "suspicious_tld",
]


def vectorize(features: URLFeatures) -> list[float]:
    return [
        float(features.url_length),
        float(features.domain_length),
        float(features.subdomain_count),
        float(features.digit_count),
        float(features.special_char_count),
        float(features.hyphen_count),
        1.0 if features.is_https else 0.0,
        1.0 if features.is_ip_host else 0.0,
        1.0 if features.has_at_symbol else 0.0,
        float(len(features.suspicious_keyword_hits)),
        1.0 if features.suspicious_tld else 0.0,
    ]
