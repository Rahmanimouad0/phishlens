"""
Tests for analyze_html() and extract_links() -- exercise the REAL
sandboxed Docker fetch path against a stable page. Require the
phishlens-fetcher image to be built first:

    docker build -t phishlens-fetcher docker/fetcher/

The CI workflow does this before running tests.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.html_analysis import analyze_html
from tools.link_extraction import extract_links


def test_analyze_html_on_simple_page():
    result = analyze_html("https://example.com")
    assert result["fetch_error"] is None
    assert result["num_forms"] == 0
    assert result["has_password_field"] is False


def test_analyze_html_handles_fetch_failure_gracefully():
    result = analyze_html("https://this-domain-definitely-does-not-exist-xyz123abc.com")
    assert result["fetch_error"] is not None


def test_extract_links_on_simple_page():
    result = extract_links("https://example.com")
    assert result["fetch_error"] is None
    assert result["external_link_count"] >= 1
