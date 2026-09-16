"""Dependency-confusion analyzer for package scans.

A package scan fetches the release from the registry at ``PYPI_JSON_BASE`` (the public PyPI by
default), so the package demonstrably exists there. This analyzer is designed to flag two situations
in which that existence is a dependency-confusion risk:

* **Internal name on the public registry** - the canonical package name matches a private-namespace
  pattern (``settings.PRIVATE_PACKAGE_PATTERNS`` or the scan's ``private_namespaces``; see
  :mod:`app.analysis.depconf` for pattern semantics and exclusions). An installer that also sees
  the public index may resolve this public package instead of the internal one.
  ``DEPENDENCY_CONFUSION`` critical, weight 12, confidence 0.9, capability ``dependency_confusion``.
  When the registry Warden fetched from (``PYPI_JSON_BASE``) is not a known public registry host (a
  mirror or proxy that may also serve private packages) confidence drops to 0.6, below the policy
  engine's default confidence gate. When it matches ``PRIVATE_INDEX_URLS`` the package is the
  internal one, served from where it is expected, and nothing is reported - not even the version
  heuristic below, which targets public squatters (internal version schemes such as build numbers
  would otherwise read as squatting). A private index that transparently proxies PyPI cannot be told
  apart from a real private index; listing such a proxy in ``PRIVATE_INDEX_URLS`` hides this signal.
* **Squatting by version** (needs no private configuration) - a very new project (first release fewer
  than 30 days before the registry metadata was fetched, at most 3 releases) whose scanned version is
  implausibly high: major version >= 50, or any PEP 440 epoch. Public squatters publish versions such
  as 99.0.0 or 9000.0.0 so they outrank whatever version the internal package has. Calendar versions
  (``YYYY.*`` within ten years before to one year after the upload year, or ``YYYYMM[DD...]``) are not
  treated as implausible. ``DEPENDENCY_CONFUSION`` medium, weight 4, confidence 0.5 and no capability
  tag: legitimate new projects that mirror an upstream version number (stub or binary-mirror
  packages) can match, so on its own this stays below the policy engine's confidence gate.

When both apply, a single critical finding carries the version evidence under
``version_squatting``, so the same observation is not scored twice.

Context: findings record ``evidence["context"] = "resolution-time"``. The risk materialises when an
installer resolves the name against its indexes, not in code the package runs, so the findings are
deliberately *not* labelled install-time: the correlation engine treats install-time context as
corroboration of install-time behaviour, and a name/version observation must not vouch for the
behaviour findings it is correlated with (a weak version heuristic plus a runtime credential read in
an SDK would otherwise form a critical attack chain).

Project age is derived from the release history in the context (``_age_days`` of the scanned release
plus the gap back to the first release), so no clock is consulted here and results are deterministic
for a given context. Unknown ages, missing upload times and non-PEP 440 versions (which modern pip
ignores during resolution) yield no version finding: unknown is not new. The analyzer performs no
network I/O (``requires_network = False``); findings describe the package name and version, so they
carry no source location.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from packaging.version import InvalidVersion, Version

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, ReleaseInfo
from app.analysis.depconf import PRIVATE, PUBLIC, IndexClassifier, NamespaceMatch, resolve_private_namespaces
from app.analysis.findings import Finding, Provenance, Severity
from app.analysis.signals import Capability, Code
from app.core.config import settings
from app.core.http import safe_url

ANALYZER_VERSION = "1.0.0"

NEW_PROJECT_MAX_DAYS = 30.0
FEW_RELEASES_MAX = 3
HIGH_MAJOR_THRESHOLD = 50
CALVER_PAST_YEARS = 10
CALVER_FUTURE_YEARS = 1

CONFIDENCE_NAMESPACE = 0.9
CONFIDENCE_NAMESPACE_UNVERIFIED_REGISTRY = 0.6
CONFIDENCE_VERSION_SQUAT = 0.5
CONTEXT = "resolution-time"
_MAX_TIME_TEXT = 64


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value or len(value) > _MAX_TIME_TEXT:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _current_release(releases: list[ReleaseInfo], version: str) -> ReleaseInfo | None:
    exact = next((r for r in releases if r.version == version), None)
    if exact is not None:
        return exact
    try:
        wanted = Version(version)
    except InvalidVersion:
        return None
    for release in releases:
        try:
            if Version(release.version) == wanted:
                return release
        except InvalidVersion:
            continue
    return None


def _first_release_time(releases: list[ReleaseInfo]) -> datetime | None:
    times = [t for t in (_parse_time(r.upload_time) for r in releases) if t is not None]
    return min(times) if times else None


def plausible_calver(release: tuple[int, ...], uploaded: datetime) -> bool:
    """True when a high leading version component reads as a calendar version for ``uploaded``."""
    if not release:
        return False
    major, year = release[0], uploaded.year
    if year - CALVER_PAST_YEARS <= major <= year + CALVER_FUTURE_YEARS:
        return True
    digits = str(major)
    if len(digits) in (6, 8, 10, 12, 14):  # YYYYMM, YYYYMMDD, optionally followed by HH, MM, SS
        y, month = int(digits[:4]), int(digits[4:6])
        if not (year - CALVER_PAST_YEARS <= y <= year + CALVER_FUTURE_YEARS and 1 <= month <= 12):
            return False
        return len(digits) == 6 or 1 <= int(digits[6:8]) <= 31
    return False


def version_squatting_evidence(ctx: PackageContext) -> dict[str, Any] | None:
    """Evidence of the new-project-with-implausible-version pattern, or ``None``."""
    try:
        version = Version(ctx.version)
    except (InvalidVersion, TypeError):
        return None
    releases = list(ctx.releases or [])
    if not releases or len(releases) > FEW_RELEASES_MAX:
        return None
    age = (ctx.metadata or {}).get("_age_days")
    if isinstance(age, bool) or not isinstance(age, (int, float)) or not math.isfinite(age) or age < 0:
        return None
    current = _current_release(releases, ctx.version)
    uploaded = _parse_time(current.upload_time) if current else None
    first = _first_release_time(releases)
    if uploaded is None or first is None:
        return None
    project_age = float(age) + max(0.0, (uploaded - first).total_seconds() / 86400.0)
    if project_age >= NEW_PROJECT_MAX_DAYS:
        return None
    major = version.release[0] if version.release else 0
    if version.epoch >= 1:
        reason = "epoch"
    elif major >= HIGH_MAJOR_THRESHOLD and not plausible_calver(version.release, uploaded):
        reason = "high_major"
    else:
        return None
    return {
        "version": ctx.version,
        "reason": reason,
        "epoch": version.epoch,
        "major": major,
        "project_age_days": round(project_age, 2),
        "release_count": len(releases),
        "first_release_at": first.isoformat(),
        "thresholds": {"max_project_age_days": NEW_PROJECT_MAX_DAYS, "max_releases": FEW_RELEASES_MAX,
                       "min_major": HIGH_MAJOR_THRESHOLD},
    }


class DependencyConfusionAnalyzer(BaseAnalyzer):
    name = "dependency_confusion"
    version = ANALYZER_VERSION
    requires_network = False

    def analyze(self, ctx: PackageContext) -> list[Finding]:
        if str(ctx.ecosystem or "").lower() != "pypi":
            return []
        namespaces = resolve_private_namespaces(ctx.options)
        match = namespaces.match(ctx.name) if namespaces.configured else None
        if match is not None:
            registry_class = IndexClassifier().classify(settings.PYPI_JSON_BASE)
            if registry_class == PRIVATE:
                return []  # the internal package, fetched from the configured private index
            return [self._namespace_finding(ctx, match, registry_class, version_squatting_evidence(ctx))]
        squat = version_squatting_evidence(ctx)
        return [self._squat_finding(ctx, squat)] if squat is not None else []

    @staticmethod
    def _namespace_finding(ctx: PackageContext, match: NamespaceMatch, registry_class: str,
                           squat: dict[str, Any] | None) -> Finding:
        first = _first_release_time(list(ctx.releases or []))
        evidence: dict[str, Any] = {
            "package": ctx.name,
            "normalized_name": match.name,
            "version": ctx.version,
            **match.to_evidence(),
            "registry": safe_url(settings.PYPI_JSON_BASE),
            "registry_classification": registry_class,
            "release_count": len(ctx.releases or []),
            "first_release_at": first.isoformat() if first else None,
            "context": CONTEXT,
        }
        if squat is not None:
            evidence["version_squatting"] = squat
        verified = registry_class == PUBLIC
        where = "the public registry" if verified else "a registry Warden cannot verify as public"
        return Finding(
            Code.DEPENDENCY_CONFUSION, Severity.critical, 12.0,
            f"Package name '{ctx.name}' matches private namespace pattern '{match.pattern}' but is published on "
            f"{where}; installers that also see that index may resolve it instead of the internal package",
            evidence, capability=Capability.DEPENDENCY_CONFUSION,
            confidence=CONFIDENCE_NAMESPACE if verified else CONFIDENCE_NAMESPACE_UNVERIFIED_REGISTRY,
            provenance=Provenance.REGISTRY,
        )

    @staticmethod
    def _squat_finding(ctx: PackageContext, squat: dict[str, Any]) -> Finding:
        what = f"epoch {squat['epoch']}" if squat["reason"] == "epoch" else f"major version {squat['major']}"
        return Finding(
            Code.DEPENDENCY_CONFUSION, Severity.medium, 4.0,
            f"New project ({squat['project_age_days']:g} day(s) since its first release, {squat['release_count']} "
            f"release(s)) publishes version {ctx.version} ({what}), a version-squatting pattern used to outrank "
            "internal package versions",
            {"package": ctx.name, **squat, "pattern": "version-squatting", "context": CONTEXT},
            confidence=CONFIDENCE_VERSION_SQUAT, provenance=Provenance.REGISTRY,
        )


__all__ = ["DependencyConfusionAnalyzer", "plausible_calver", "version_squatting_evidence"]
