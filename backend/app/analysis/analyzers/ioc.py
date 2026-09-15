"""Indicator-of-compromise matcher.

Matches package text files against a bundled indicator set (malicious URLs/hosts, IPs,
crypto wallet addresses, and known-bad code fingerprints). The bundled snapshot
(``data/iocs.json``) contains synthetic demonstration values, not live threat intelligence;
in production it should be replaced by a maintained feed. Findings therefore carry the
provenance ``intel:bundled-ioc-snapshot`` so consumers can see where the indicator came from.

URL, IP and wallet indicators match only when the occurrence is delimited: an IPv4 indicator
must not be followed by another digit or ``.digit`` (``185.220.101.1`` does not match
``185.220.101.123``, but does match ``185.220.101.1:4444``), a URL must not continue with
more host/path characters (``/collect`` does not match ``/collector`` or a longer host name;
``?query`` or ``/sub/path`` after it still match) and a wallet must be a whole token. Only such
delimited occurrences are reported with the deterministic-evidence confidence (0.95), and the
reported value is exactly the text found. Code fingerprints remain substring matches at a
lower confidence. Line numbers are computed from the real match offset in the analysed text
(counting ``\\r\\n``, ``\\r`` and ``\\n`` terminators, as the Python parser does), so
``location`` and ``evidence["locations"]`` point at genuine occurrences.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.analyzers.static_code import LocationCollector
from app.analysis.findings import Provenance
from app.analysis.signals import Capability, Code, Severity, Signal

ANALYZER_VERSION = "1.1.0"
PROVENANCE = Provenance.intel("bundled-ioc-snapshot")

_DATA = Path(__file__).resolve().parent.parent / "data" / "iocs.json"
_NEWLINE_RE = re.compile(r"\r\n|\r|\n")

# Exact network/wallet indicators are deterministic evidence; code fingerprints are short
# substrings that could in principle appear in benign code, so they rate lower.
CONFIDENCE_EXACT = 0.95
CONFIDENCE_FINGERPRINT_ONLY = 0.8
_EXACT_TYPES = frozenset({"url", "ip", "wallet"})


@lru_cache(maxsize=1)
def _iocs() -> dict:
    if _DATA.exists():
        return json.loads(_DATA.read_text(encoding="utf-8"))
    return {"urls": [], "ips": [], "wallets": [], "fingerprints": []}


def indicator_pattern(kind: str, value: str) -> re.Pattern[str]:
    """Delimited-occurrence pattern for a URL / IP / wallet indicator (see module docstring)."""
    body = re.escape(value)
    if kind == "ip":
        if ":" in value:  # IPv6
            return re.compile(rf"(?<![0-9A-Fa-f:]){body}(?![0-9A-Fa-f:])")
        return re.compile(rf"(?<![\d.]){body}(?!\d|\.\d)")
    if kind == "url":
        suffix = "" if value.endswith("/") else r"(?![A-Za-z0-9\-_~%@]|\.[A-Za-z0-9])"
        return re.compile(rf"(?<![A-Za-z0-9]){body}{suffix}")
    return re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])")


@lru_cache(maxsize=1)
def _patterns() -> tuple[tuple[str, str, re.Pattern[str]], ...]:
    data = _iocs()
    out: list[tuple[str, str, re.Pattern[str]]] = []
    for kind, key in (("url", "urls"), ("wallet", "wallets"), ("ip", "ips")):
        out.extend((kind, value, indicator_pattern(kind, value)) for value in data.get(key, []) if value)
    return tuple(out)


def _line_of(text: str, offset: int) -> int:
    """1-based line number of ``offset`` in ``text``."""
    return len(_NEWLINE_RE.findall(text, 0, offset)) + 1


class IOCAnalyzer(BaseAnalyzer):
    name = "ioc"
    version = ANALYZER_VERSION

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        data = _iocs()
        hits: list[dict] = []
        locations = LocationCollector()

        patterns = _patterns()

        for index, f in enumerate(ctx.files):
            text = f.text

            def hit(kind: str, value: str, offset: int, _f=f, _text=text, _index=index) -> None:
                hits.append({"type": kind, "value": value, "file": _f.relpath})
                locations.add("ioc", _index, _f.relpath, _line_of(_text, offset))

            for kind, _value, pattern in patterns:
                m = pattern.search(text)
                if m:
                    hit(kind, m.group(0), m.start())
            for fp in data.get("fingerprints", []):
                pos = text.find(fp)
                if pos >= 0:
                    hit("fingerprint", fp, pos)

        if not hits:
            return []

        # De-duplicate.
        seen = set()
        unique = []
        for h in hits:
            key = (h["type"], h["value"])
            if key not in seen:
                seen.add(key)
                unique.append(h)

        exact = any(h["type"] in _EXACT_TYPES for h in unique)
        return [Signal(
            Code.IOC_MATCH, Severity.critical, 12.0,
            f"Matched {len(unique)} known malicious indicator(s)",
            {"matches": unique[:10], "locations": locations.evidence("ioc")},
            capability=Capability.IOC,
            confidence=CONFIDENCE_EXACT if exact else CONFIDENCE_FINGERPRINT_ONLY,
            location=locations.first("ioc"),
            provenance=PROVENANCE,
        )]
