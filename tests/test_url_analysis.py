"""Pure unit tests for analyze_url() -- no network, no external files."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.url_analysis import analyze_url


def test_detects_suspicious_tld():
    result = analyze_url("http://example.tk/login")
    assert result["suspicious_tld"] is True


def test_detects_suspicious_keywords():
    result = analyze_url("http://example.com/verify-account-login")
    found = result["suspicious_keywords_found"]
    assert "login" in found
    assert "verify" in found
    assert "account" in found


def test_detects_ip_host():
    result = analyze_url("http://192.168.1.1/admin")
    assert result["has_ip_address_host"] is True


def test_https_detection():
    assert analyze_url("https://example.com")["uses_https"] is True
    assert analyze_url("http://example.com")["uses_https"] is False


def test_no_false_positive_on_clean_url():
    result = analyze_url("https://github.com/torvalds/linux")
    assert result["suspicious_tld"] is False
    assert result["has_ip_address_host"] is False
    assert result["suspicious_keywords_found"] == []


def test_registered_domain_extraction():
    result = analyze_url("https://www.github.com/some/path")
    assert result["registered_domain"] == "github.com"
