"""
tools/url_analysis.py — analyze_url(): pure-Python URL structure heuristics.

No network calls, no external state — this is deliberately the FIRST tool
the agent gets. If URL -> agent -> analyze_url() -> verdict works end to
end, the core architecture is proven and every later tool is additive.

Returns evidence (a dict of findings), never a verdict. Deciding what the
evidence means is the agent's job, not this function's.
"""

import math
import re
from urllib.parse import urlparse

import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "confirm",
    "signin", "banking", "password", "billing", "authenticat",
]

# TLDs that see disproportionate phishing abuse. Not proof of anything on
# their own — evidence to weigh alongside everything else.
SUSPICIOUS_TLDS = {"cfd", "bid", "click", "top", "xyz", "cc", "work", "gq", "tk", "ml"}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def analyze_url(url: str) -> dict:
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.netloc.lower()

    return {
        "url": url,
        "length": len(url),
        "hostname": hostname,
        "registered_domain": ext.registered_domain,
        "subdomain": ext.subdomain,
        "subdomain_count": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "tld": ext.suffix,
        "suspicious_tld": ext.suffix in SUSPICIOUS_TLDS,
        "path_entropy": round(_shannon_entropy(parsed.path), 2),
        "hostname_entropy": round(_shannon_entropy(hostname), 2),
        "has_punycode": "xn--" in hostname,
        "has_ip_address_host": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname.split(":")[0])),
        "suspicious_keywords_found": [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()],
        "uses_https": parsed.scheme == "https",
    }


ANALYZE_URL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "analyze_url",
        "description": (
            "Analyze the structural properties of a URL: length, character "
            "entropy, suspicious keywords, TLD reputation, punycode/homograph "
            "tricks, and IP-address hosts. Makes no network requests — pure "
            "structural analysis only."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The full URL to analyze"}
            },
            "required": ["url"],
        },
    },
}
