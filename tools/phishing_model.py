"""
tools/phishing_model.py — run_phishing_model(): wraps the existing trained
XGBoost classifier from Rahmanimouad0/phishing-url-detector.

IMPORTANT: the trained model (best_model_url.pkl) is NOT part of that
repo — its own README notes models aren't committed due to size. This
tool expects a local copy of that file. See MODEL_PATH below.

The feature extraction logic is VENDORED (copied, not imported) from
that repo's features/url_features.py, so this tool has no dependency on
the other project's folder existing on disk or being on sys.path — only
the model bundle file is needed.
  Source: github.com/Rahmanimouad0/phishing-url-detector
          features/url_features.py  (23 lexical features)
          api/app.py                (bundle = {"model", "features", "name"})

⚠ SYNC RISK, worth a line in your README's honest-findings section:
  this is a COPY of the extractor, not a live import. If you ever edit
  features/url_features.py in the original repo, this file will silently
  drift out of sync unless you update it here too.
"""

import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import joblib
import pandas as pd
import tldextract

# ── Point this at your actual model file ────────────────────────────
# Recommended: copy best_model_url.pkl from
#   C:\Users\MOUAD\phishing-detector\models\best_model_url.pkl
# into this project at phishlens/models/best_model_url.pkl (default
# below), so the repo is self-contained and doesn't depend on another
# project folder existing at a fixed path on your machine.
MODEL_PATH = Path(__file__).parent.parent / "models" / "best_model_url.pkl"

_bundle = None
_model = None
_FEATURES = None
_MODEL_NAME = None


def _load_bundle():
    global _bundle, _model, _FEATURES, _MODEL_NAME
    if _bundle is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. Copy best_model_url.pkl "
                f"here, or edit MODEL_PATH in tools/phishing_model.py."
            )
        _bundle = joblib.load(MODEL_PATH)
        _model = _bundle["model"]
        _FEATURES = _bundle["features"]
        _MODEL_NAME = _bundle["name"]
    return _model, _FEATURES, _MODEL_NAME


# ── Vendored from phishing-url-detector/features/url_features.py ──
# Kept in sync MANUALLY. Do not diverge without also retraining --
# the model's weights are tied to exactly this feature computation.

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "update",
    "account", "confirm", "banking", "paypal", "ebay",
    "amazon", "apple", "microsoft", "password", "credential",
    "recover", "unlock", "suspend", "limited", "unusual",
    "validate", "wallet", "alert", "urgent", "click",
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "tk",
    "ml", "ga", "cf", "gq", "pw", "cc", "work",
    "info", "biz", "link", "click", "live", "space",
}

BRAND_NAMES = [
    "paypal", "apple", "amazon", "microsoft", "google",
    "facebook", "netflix", "instagram", "linkedin", "ebay",
    "bankofamerica", "wellsfargo", "chase", "citibank",
]


def _extract_url_features(url: str) -> dict:
    if not isinstance(url, str) or len(url) == 0:
        return _empty_features()
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
    except Exception:
        return _empty_features()

    scheme = parsed.scheme.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()
    domain = ext.domain.lower()
    subdomain = ext.subdomain.lower()
    suffix = ext.suffix.lower()

    url_length = len(url)
    domain_length = len(domain)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_at = url.count("@")
    num_digits = sum(c.isdigit() for c in url)
    digit_ratio = round(num_digits / max(url_length, 1), 4)
    has_ip = int(bool(re.search(r'https?://(\d{1,3}\.){3}\d{1,3}', url)))
    has_https = int(scheme == "https")
    has_double_slash = int("//" in url[8:])

    if subdomain:
        subdomain_depth = len(subdomain.split("."))
        subdomain_length = len(subdomain)
    else:
        subdomain_depth = 0
        subdomain_length = 0

    url_entropy = round(_shannon_entropy(url), 4)
    domain_entropy = round(_shannon_entropy(domain), 4)
    is_suspicious_tld = int(suffix in SUSPICIOUS_TLDS)
    tld_length = len(suffix)
    path_length = len(path)

    try:
        num_query_params = len(parse_qs(query))
    except Exception:
        num_query_params = 0

    has_fragment = int("#" in url)
    suspicious_word_count = sum(1 for word in SUSPICIOUS_WORDS if word in full_url)
    domain_has_brand = int(any(brand in (domain + subdomain) for brand in BRAND_NAMES))

    return {
        "url_length": url_length, "domain_length": domain_length,
        "num_dots": num_dots, "num_hyphens": num_hyphens,
        "num_underscores": num_underscores, "num_slashes": num_slashes,
        "num_at": num_at, "num_digits": num_digits, "digit_ratio": digit_ratio,
        "has_ip": has_ip, "has_https": has_https,
        "has_double_slash": has_double_slash, "subdomain_depth": subdomain_depth,
        "subdomain_length": subdomain_length, "url_entropy": url_entropy,
        "domain_entropy": domain_entropy, "is_suspicious_tld": is_suspicious_tld,
        "tld_length": tld_length, "path_length": path_length,
        "num_query_params": num_query_params, "has_fragment": has_fragment,
        "suspicious_word_count": suspicious_word_count,
        "domain_has_brand": domain_has_brand,
    }


def _empty_features() -> dict:
    return {
        "url_length": 0, "domain_length": 0, "num_dots": 0,
        "num_hyphens": 0, "num_underscores": 0, "num_slashes": 0,
        "num_at": 0, "num_digits": 0, "digit_ratio": 0.0,
        "has_ip": 0, "has_https": 0, "has_double_slash": 0,
        "subdomain_depth": 0, "subdomain_length": 0,
        "url_entropy": 0.0, "domain_entropy": 0.0,
        "is_suspicious_tld": 0, "tld_length": 0, "path_length": 0,
        "num_query_params": 0, "has_fragment": 0,
        "suspicious_word_count": 0, "domain_has_brand": 0,
    }


def run_phishing_model(url: str) -> dict:
    """
    Runs the existing trained classifier on a URL. Returns a REAL
    calibrated probability from a real trained model -- not an LLM
    guess. This is the "S1 baseline" system in your Week 3 evaluation,
    and also a tool the agent can call in S4.
    """
    model, features, model_name = _load_bundle()
    feats = _extract_url_features(url)

    missing = [f for f in features if f not in feats]
    if missing:
        return {"error": f"feature mismatch: model expects {missing}, "
                          f"vendored extractor doesn't produce them. "
                          f"The vendored copy may be out of sync."}

    row = pd.DataFrame([[feats[f] for f in features]], columns=features)
    proba = float(model.predict_proba(row)[0, 1])

    return {
        "model_name": model_name,
        "phishing_probability": round(proba, 4),
        "prediction": "phishing" if proba >= 0.5 else "legitimate",
    }


RUN_PHISHING_MODEL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_phishing_model",
        "description": (
            "Run the existing trained ML classifier (XGBoost, trained on "
            "100,000 URLs, 23 lexical features) on this URL. Returns a "
            "calibrated phishing probability from a real trained model -- "
            "ground-truth-backed evidence, not a guess."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The full URL to classify"}
            },
            "required": ["url"],
        },
    },
}
