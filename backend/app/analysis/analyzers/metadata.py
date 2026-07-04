"""Package-metadata analyzer.

Behavioural code analysis is complemented by *provenance* signals drawn from registry
metadata. Individually weak, together they meaningfully shift risk:

* **New package** — most malicious uploads are caught (or removed) within days, so a
  brand-new package carries elevated baseline risk.
* **Single/anonymous maintainer** — low accountability.
* **No source repository** — nothing to review; a common trait of throwaway malware.
* **Release flood** — many versions published in a very short window (spray-and-pray).
"""

from __future__ import annotations

from datetime import datetime

from app.analysis.analyzers.base import PackageContext
from app.analysis.signals import Code, Severity, Signal


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class MetadataAnalyzer:
    name = "metadata"

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        md = ctx.metadata or {}
        signals: list[Signal] = []

        age_days = md.get("_age_days")
        if isinstance(age_days, (int, float)):
            if age_days < 7:
                signals.append(Signal(
                    Code.NEW_PACKAGE, Severity.medium, 4.0,
                    f"Release is only {int(age_days)} day(s) old",
                    {"age_days": age_days},
                ))
            elif age_days < 30:
                signals.append(Signal(
                    Code.NEW_PACKAGE, Severity.low, 2.0,
                    f"Release is {int(age_days)} day(s) old",
                    {"age_days": age_days},
                ))

        maintainers = md.get("_maintainer_count")
        if isinstance(maintainers, int) and maintainers <= 1:
            signals.append(Signal(
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
            signals.append(Signal(
                Code.NO_SOURCE_REPO, Severity.low, 2.0,
                "No source repository or homepage declared",
                {},
            ))

        recent = md.get("_releases_last_7d")
        if isinstance(recent, int) and recent >= 10:
            signals.append(Signal(
                Code.RELEASE_FLOOD, Severity.medium, 3.0,
                f"{recent} releases published in the last 7 days (spray pattern)",
                {"releases_last_7d": recent},
            ))

        if md.get("_version_found") is False:
            signals.append(Signal(
                Code.VERSION_NOT_FOUND, Severity.low, 1.0,
                "Requested version not found on the registry; analysed latest instead",
                {},
            ))
        return signals
