"""
tools/link_extraction.py — extract_links(): detailed outbound-link analysis.

Fetches the page (sandboxed, via tools/_sandbox.py -- the SAME container
logic analyze_html() uses) and analyzes the SET of outbound links: which
external domains are linked, whether any are known URL shorteners (a
common redirect-chain evasion technique), and how concentrated the links
are toward a single external domain (every link funneling to one place
is a stronger signal than a normal mix of a few different sites).
"""

from collections import Counter
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tools._sandbox import fetch_html_sandboxed

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}


def extract_links(url: str) -> dict:
    html, error = fetch_html_sandboxed(url)
    if error:
        return {"url": url, "fetch_error": error}
    if not html.strip():
        return {"url": url, "fetch_error": "empty response"}

    soup = BeautifulSoup(html, "html.parser")
    target_domain = urlparse(url).netloc.lower()

    all_hrefs = [a["href"] for a in soup.find_all("a", href=True)]
    external = []
    domain_counts = Counter()

    for href in all_hrefs:
        if not href.startswith("http"):
            continue
        link_domain = urlparse(href).netloc.lower()
        if link_domain and link_domain != target_domain:
            external.append(href)
            domain_counts[link_domain] += 1

    shortener_links = [
        h for h in external if urlparse(h).netloc.lower() in KNOWN_SHORTENERS
    ]

    top_domain, top_count = (domain_counts.most_common(1) or [(None, 0)])[0]
    concentration = round(top_count / len(external), 2) if external else 0.0

    return {
        "url": url,
        "fetch_error": None,
        "total_links": len(all_hrefs),
        "external_link_count": len(external),
        "unique_external_domains": list(domain_counts.keys()),
        "shortener_links_found": shortener_links,
        "top_external_domain": top_domain,
        # 1.0 = every external link funnels to a single domain -- a
        # stronger phishing signal than a normal spread across many sites.
        "link_concentration": concentration,
    }


EXTRACT_LINKS_SCHEMA = {
    "type": "function",
    "function": {
        "name": "extract_links",
        "description": (
            "Fetch a page (sandboxed) and analyze its outbound links: which "
            "external domains are linked, whether any use known URL "
            "shortener services (a common redirect-chain evasion "
            "technique), and how concentrated the links are toward a "
            "single domain."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The full URL to fetch and analyze links from"}
            },
            "required": ["url"],
        },
    },
}
