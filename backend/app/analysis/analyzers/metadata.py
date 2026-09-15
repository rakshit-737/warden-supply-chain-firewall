"""Package-metadata analyzer.

Behavioural code analysis is complemented by *reputation* signals drawn from registry
metadata. Individually weak, together they meaningfully shift risk:

* **New package** — most malicious uploads are caught (or removed) within days, so a
  brand-new package carries elevated baseline risk.
* **Single/anonymous maintainer** — low accountability.
* **No source repository** — nothing to review; a common trait of throwaway malware.
* **Release flood** — many versions published in a very short window (spray-and-pray).

Registry metadata is attacker-published, and these traits are shared by many benign
projects, so confidences are deliberately low (0.3–0.5). ``VERSION_NOT_FOUND`` is a factual
pipeline observation and has confidence 1.0. Findings describe the release, not a file, so
they carry no source location; provenance is ``registry-metadata``.
"""

from __future__ import annotations

from datetime import datetime

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.findings import Provenance
from app.analysis.signals import Code, Severity, Signal

ANALYZER_VERSION = "1.1.0"

CONFIDENCE = {
    Code.NEW_PACKAGE: 0.4,
    Code.SINGLE_MAINTAINER: 0.3,
    Code.NO_SOURCE_REPO: 0.35,
    Code.RELEASE_FLOOD: 0.5,
    Code.VERSION_NOT_FOUND: 1.0,
}


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _finding(code: str, severity: Severity, weight: float, message: str, evidence: dict) -> Signal:
    return Signal(code, severity, weight, message, evidence,
                  confidence=CONFIDENCE[code], provenance=Provenance.REGISTRY)


class MetadataAnalyzer(BaseAnalyzer):
    name = "metadata"
    version = ANALYZER_VERSION

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        md = ctx.metadata or {}
        signals: list[Signal] = []

        age_days = md.get("_age_days")
        if isinstance(age_days, (int, float)):
            if age_days < 7:
                signals.append(_finding(
                    Code.NEW_PACKAGE, Severity.medium, 4.0,
                    f"Release is only {int(age_days)} day(s) old",
                    {"age_days": age_days},
                ))
            elif age_days < 30:
                signals.append(_finding(
                    Code.NEW_PACKAGE, Severity.low, 2.0,
                    f"Release is {int(age_days)} day(s) old",
                    {"age_days": age_days},
                ))

        maintainers = md.get("_maintainer_count")
        if isinstance(maintainers, int) and maintainers <= 1:
            signals.append(_finding(
                Code.SINGLE_MAINTAINER, Severity.low, 1.5,
                "Package has a single or anonymous maintainer",
                {"maintainer_count": maintainers},
            ))

        home = (md.get("home_page") or "")
        project_urls = md.get("project_urls") or {}
        has_repo = bool(home) or any(
            "github" in str(v).lower() or "gitlab" in str(v).lower()
            for v in project_urls.values()
        )
        if not has_repo:
            signals.append(_finding(
                Code.NO_SOURCE_REPO, Severity.low, 2.0,
                "No source repository or homepage declared",
                {},
            ))

        recent = md.get("_releases_last_7d")
        if isinstance(recent, int) and recent >= 10:
            signals.append(_finding(
                Code.RELEASE_FLOOD, Severity.medium, 3.0,
                f"{recent} releases published in the last 7 days (spray pattern)",
                {"releases_last_7d": recent},
            ))

        if md.get("_version_found") is False:
            signals.append(_finding(
                Code.VERSION_NOT_FOUND, Severity.low, 1.0,
                "Requested version not found on the registry; analysed latest instead",
                {},
            ))
        return signals
