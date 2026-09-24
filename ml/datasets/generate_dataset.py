"""
Generates a synthetic labeled URL dataset for training the baseline classifier.

HONEST CAVEAT: this is bootstrap/synthetic data, not a real labeled phishing
corpus. It exists to stand up the full ML pipeline (training harness, eval
metrics, serving path) end-to-end. Before this model is trusted for real
scoring, it should be retrained on a real dataset (e.g. PhishTank, OpenPhish,
or an internal labeled corpus) — swapping the CSV is all that's needed to
retrain, per train_baseline.py.

Design notes to avoid the model just re-deriving the rule engine:
- "Hard negative" legitimate examples include some risky-looking traits
  (numbers in domain, occasional shorteners, deep subdomains).
- "Stealthy positive" phishing examples deliberately omit obvious keywords
  or IP hosts, relying on subtler combinations (typosquat hyphens + TLD).
"""
import csv
import random
from pathlib import Path

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "apple.com", "nytimes.com", "chase.com", "paypal.com", "stripe.com",
    "notion.so", "figma.com", "vercel.app", "cloudflare.com", "mozilla.org",
    "docs.google.com", "mail.google.com", "drive.google.com", "accounts.google.com",
    "web.whatsapp.com", "outlook.office.com", "teams.microsoft.com",
    "reddit.com", "linkedin.com", "spotify.com", "netflix.com", "adobe.com",
    "salesforce.com", "atlassian.com", "slack.com", "dropbox.com", "zoom.us",
    "web3.storage", "npmjs.com", "pypi.org", "readthedocs.io", "developer.mozilla.org",
]

LEGIT_PATHS = [
    "/", "/login", "/signin", "/account", "/settings", "/dashboard",
    "/docs/getting-started", "/pricing", "/about", "/careers", "/blog/2026/update",
    "/user/profile", "/api/v1/status", "/support/contact",
]

PHISHING_BRANDS = [
    "paypal", "amazon", "chase", "bankofamerica", "netflix", "apple",
    "microsoft", "wellsfargo", "coinbase", "facebook", "instagram", "outlook",
]

SUSPICIOUS_TLDS = ["top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "work", "loan"]
PHISHING_KEYWORDS = ["login", "verify", "secure", "update", "confirm", "account", "signin", "suspended"]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def make_legit_row():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https" if random.random() > 0.03 else "http"  # legit is almost always https

    # Occasional hard negatives: legit-but-risky-looking traits
    if random.random() < 0.08:
        domain = f"promo{random.randint(100,999)}.{domain}"  # deep numeric subdomain, still legit
    if random.random() < 0.04:
        domain = "bit.ly"  # legit brands do use shorteners for campaigns sometimes
        path = "/" + "".join(random.choices("abcdefghijkmnpqrstuvwxyz23456789", k=7))

    url = f"{scheme}://{domain}{path}"
    return url, 0


def make_phishing_row():
    style = random.choice(["ip_host", "typosquat", "keyword_http", "stealthy_typosquat", "shortener_abuse"])

    if style == "ip_host":
        path = "/" + random.choice(["login.php", "verify-account", "secure/signin", "update.html"])
        url = f"http://{random_ip()}{path}"

    elif style == "typosquat":
        brand = random.choice(PHISHING_BRANDS)
        filler = random.choice(["secure", "verify", "login", "account", "update"])
        tld = random.choice(SUSPICIOUS_TLDS)
        url = f"http://{brand}-{filler}-{random.choice(PHISHING_KEYWORDS)}.{tld}/confirm"

    elif style == "keyword_http":
        brand = random.choice(PHISHING_BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        url = f"http://{brand}{random.randint(1,99)}-{kw}.info/{kw}"

    elif style == "stealthy_typosquat":
        # No IP, no obvious keyword — just a subtle hyphenated lookalike + risky TLD, over HTTPS even.
        brand = random.choice(PHISHING_BRANDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        url = f"https://{brand}-support.{tld}/case/{random.randint(10000,99999)}"

    else:  # shortener_abuse
        shortener = random.choice(["bit.ly", "tinyurl.com", "cutt.ly"])
        url = f"http://{shortener}/" + "".join(random.choices("abcdefghijkmnpqrstuvwxyz23456789", k=6))

    return url, 1


def generate(n_per_class: int = 400) -> list[tuple[str, int]]:
    rows = [make_legit_row() for _ in range(n_per_class)]
    rows += [make_phishing_row() for _ in range(n_per_class)]
    random.shuffle(rows)
    # de-dupe while preserving order
    seen = set()
    unique_rows = []
    for url, label in rows:
        if url not in seen:
            seen.add(url)
            unique_rows.append((url, label))
    return unique_rows


if __name__ == "__main__":
    rows = generate(n_per_class=450)
    out_path = Path(__file__).parent / "urls.csv"
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    n_pos = sum(1 for _, l in rows if l == 1)
    print(f"Wrote {len(rows)} rows ({n_pos} phishing / {len(rows) - n_pos} legit) to {out_path}")
