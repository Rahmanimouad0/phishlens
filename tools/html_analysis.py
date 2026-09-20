"""
tools/html_analysis.py — analyze_html(): fetches a URL's HTML inside a
sandboxed, ephemeral Docker container (via tools/_sandbox.py), then
parses the returned text with BeautifulSoup on the host (safe -- parsing
text executes nothing).

Prerequisite (run once, from the phishlens root):
    docker build -t phishlens-fetcher docker/fetcher/
"""

from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tools._sandbox import fetch_html_sandboxed

BRAND_NAMES = [
    "paypal", "apple", "amazon", "microsoft", "google",
    "facebook", "netflix", "instagram", "linkedin", "ebay",
    "bankofamerica", "wellsfargo", "chase", "citibank",
]


def analyze_html(url: str) -> dict:
    html, error = fetch_html_sandboxed(url)
    if error:
        return {"url": url, "fetch_error": error}
    if not html.strip():
        return {"url": url, "fetch_error": "empty response"}

    soup = BeautifulSoup(html, "html.parser")
    target_domain = urlparse(url).netloc.lower()

    forms = soup.find_all("form")
    password_fields = soup.find_all("input", {"type": "password"})

    external_form_actions = []
    for form in forms:
        action = form.get("action", "")
        if action.startswith("http"):
            action_domain = urlparse(action).netloc.lower()
            if action_domain and action_domain != target_domain:
                external_form_actions.append(action)

    all_links = soup.find_all("a", href=True)
    external_links = [
        a["href"] for a in all_links
        if a["href"].startswith("http")
        and urlparse(a["href"]).netloc.lower() != target_domain
    ]

    meta_refresh = soup.find(
        "meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"}
    )

    page_text = soup.get_text().lower()
    brand_mentions = [b for b in BRAND_NAMES if b in page_text]

    return {
        "url": url,
        "fetch_error": None,
        "title": soup.title.string.strip() if soup.title and soup.title.string else None,
        "num_forms": len(forms),
        "has_password_field": len(password_fields) > 0,
        "num_external_form_actions": len(external_form_actions),
        "external_form_actions": external_form_actions[:3],
        "num_scripts": len(soup.find_all("script")),
        "has_iframe": len(soup.find_all("iframe")) > 0,
        "has_meta_refresh_redirect": meta_refresh is not None,
        "num_external_links": len(external_links),
        "brand_names_mentioned": brand_mentions,
    }


ANALYZE_HTML_SCHEMA = {
    "type": "function",
    "function": {
        "name": "analyze_html",
        "description": (
            "Fetch a URL's HTML in a sandboxed environment and analyze its "
            "content: login/password forms, whether forms submit to a "
            "DIFFERENT domain than the page itself (a classic phishing "
            "credential-harvesting pattern), redirects, iframes, and "
            "mentions of well-known brand names in the page text."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The full URL to fetch and analyze"}
            },
            "required": ["url"],
        },
    },
}
