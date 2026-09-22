"""
Tests for the feature-extraction logic in tools/phishing_model.py.

Does NOT require the actual trained model file (best_model_url.pkl,
never committed -- see README). Tests the pure feature-computation
function only. run_phishing_model() itself needs the real model and is
exercised manually / in run_milestone.py, not here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.phishing_model import _extract_url_features, _empty_features


def test_extract_features_returns_expected_keys():
    feats = _extract_url_features("https://example.com/login")
    assert set(feats.keys()) == set(_empty_features().keys())


def test_extract_features_handles_empty_string():
    assert _extract_url_features("") == _empty_features()


def test_suspicious_word_count():
    feats = _extract_url_features("http://verify-login-secure.tk/account")
    assert feats["suspicious_word_count"] >= 3


def test_https_flag():
    assert _extract_url_features("https://example.com")["has_https"] == 1
    assert _extract_url_features("http://example.com")["has_https"] == 0
