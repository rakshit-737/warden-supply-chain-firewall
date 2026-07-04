"""Indicator-of-compromise matcher.

Matches package source against a bundled indicator set (malicious URLs/hosts, IPs, crypto
wallet addresses, and known-bad code fingerprints). In production this list would be fed
from a maintained threat-intel feed; the bundled snapshot demonstrates the mechanism and
gives the demo deterministic hits.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from app.analysis.analyzers.base import PackageContext
from app.analysis.signals import Capability, Code, Severity, Signal

_DATA = Path(__file__).resolve().parent.parent / "data" / "iocs.json"


@lru_cache(maxsize=1)
def _iocs() -> dict:
    if _DATA.exists():
        return json.loads(_DATA.read_text(encoding="utf-8"))
    return {"urls": [], "ips": [], "wallets": [], "fingerprints": []}


class IOCAnalyzer:
    name = "ioc"

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        data = _iocs()
        hits: list[dict] = []

        # Precompile IP regexes once.
        ip_patterns = [re.compile(re.escape(ip)) for ip in data.get("ips", [])]

        for f in ctx.files:
            text = f.text
            for url in data.get("urls", []):
                if url in text:
                    hits.append({"type": "url", "value": url, "file": f.relpath})
            for wallet in data.get("wallets", []):
                if wallet in text:
                    hits.append({"type": "wallet", "value": wallet, "file": f.relpath})
            for fp in data.get("fingerprints", []):
                if fp in text:
                    hits.append({"type": "fingerprint", "value": fp, "file": f.relpath})
            for pat, ip in zip(ip_patterns, data.get("ips", [])):
                if pat.search(text):
                    hits.append({"type": "ip", "value": ip, "file": f.relpath})

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

        return [Signal(
            Code.IOC_MATCH, Severity.critical, 12.0,
            f"Matched {len(unique)} known malicious indicator(s)",
            {"matches": unique[:10]},
            capability=Capability.IOC,
        )]
