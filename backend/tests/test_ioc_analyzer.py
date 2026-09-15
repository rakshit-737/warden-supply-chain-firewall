"""IOC analyzer boundary tests.

Indicator values come from the bundled demonstration snapshot (``app/analysis/data/iocs.json``),
which contains synthetic values, not live threat intelligence.
"""

from __future__ import annotations

import pytest

from app.analysis.analyzers.base import PackageContext, SourceFile
from app.analysis.analyzers.ioc import CONFIDENCE_EXACT, CONFIDENCE_FINGERPRINT_ONLY, IOCAnalyzer
from app.analysis.signals import Code


def _scan(text: str, relpath: str = "pkg/data.py"):
    ctx = PackageContext(ecosystem="pypi", name="pkg", version="1.0",
                         files=[SourceFile(relpath=relpath, text=text, size=len(text))])
    return IOCAnalyzer().analyze(ctx)


def test_ip_indicator_is_not_matched_inside_a_longer_address():
    """Regression: '185.220.101.1' matched inside '185.220.101.123' with exact-match confidence."""
    assert _scan("TOR_EXITS = ['185.220.101.123', '185.220.101.45']\n") == []


def test_delimited_ip_indicator_reports_the_text_actually_found():
    [finding] = _scan("import socket\nHOST = '185.220.101.1:4444'\n")
    assert finding.code == Code.IOC_MATCH and finding.confidence == CONFIDENCE_EXACT
    assert finding.evidence["matches"] == [{"type": "ip", "value": "185.220.101.1", "file": "pkg/data.py"}]
    assert finding.location.file == "pkg/data.py" and finding.location.line == 2


@pytest.mark.parametrize(("text", "matched"), [
    ("x = '2185.220.101.1'", False),
    ("x = '185.220.101.10'", False),
    ("x = '185.220.101.1.7'", False),
    ("x = '185.220.101.1'", True),
    ("addr = 185.220.101.1.", True),  # sentence-ending dot is not part of the address
    ("u = 'http://malicious-c2.example.net/collector'", False),
    ("u = 'http://malicious-c2.example.net/collect.php'", False),
    ("u = 'xhttp://malicious-c2.example.net/collect'", False),
    ("u = 'http://malicious-c2.example.net/collect'", True),
    ("u = 'https://exfil.badpackage.io/upload?id=1'", True),
    ("u = 'https://exfil.badpackage.io/upload/more'", True),
    ("w = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef00'", False),
    ("w = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'", True),
])
def test_network_and_wallet_indicators_match_only_delimited_occurrences(text, matched):
    assert bool(_scan(text)) is matched


def test_code_fingerprints_remain_substring_matches_at_lower_confidence():
    [finding] = _scan("payload = __import__('base64').b64decode(blob)\n")
    assert finding.confidence == CONFIDENCE_FINGERPRINT_ONLY
    assert finding.evidence["matches"][0]["type"] == "fingerprint"
