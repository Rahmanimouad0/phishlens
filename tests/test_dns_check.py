"""
Tests for check_dns() -- uses REAL DNS lookups against stable, well-known
domains. Closer to an integration test than a pure unit test, but DNS
lookups work fine in standard CI environments (unlike the Docker- or
Ollama-dependent parts of this project), so this runs directly rather
than being skipped.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.dns_check import check_dns


def test_resolves_known_domain():
    result = check_dns("https://google.com")
    assert result["resolved"] is True
    assert len(result["a_records"]) > 0


def test_handles_nonexistent_domain_gracefully():
    result = check_dns("https://this-domain-definitely-does-not-exist-xyz123abc.com")
    assert result["resolved"] is False
