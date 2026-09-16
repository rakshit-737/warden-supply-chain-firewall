"""PyPI acquisition client: project / release JSON, artifact download, integrity (provenance) API.

Everything PyPI returns about a package was published by whoever controls that package, so
it is treated as hostile input:

* **Validated URL construction** — the project name must match the PEP 508 name grammar and
  versions / filenames a conservative character set *before* any URL is built, and every path
  segment is percent-quoted, so a name cannot inject path segments, queries or hosts.
* **Separate host allowlists** — registry JSON may only come from ``REGISTRY_HOST_ALLOWLIST``
  and artifacts only from ``ARTIFACT_HOST_ALLOWLIST``; :class:`~app.core.http.SafeHttpClient`
  re-checks every redirect hop, so registry metadata cannot point Warden at an internal host.
* **Size caps** — ``MAX_METADATA_BYTES`` for JSON, ``MAX_DOWNLOAD_BYTES`` for artifacts (checked
  against the registry-declared size before downloading and enforced while streaming).
* **Bounded metadata** — every string copied into the slim metadata dict is cut to 2000
  characters and every list to 200 items (classifiers to 50); unexpected types are dropped.
* **Integrity** — the sha256 of the downloaded bytes is compared with the registry digest in
  constant time; ``hash_verified`` is ``None`` when the registry published no sha256.

Timeouts are per network operation (httpx semantics), not a total wall-clock bound on a
download. No package code is executed here.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

from app.analysis.analyzers.base import ArtifactInfo, ReleaseInfo
from app.core.config import settings
from app.core.errors import AnalysisError
from app.core.http import OutboundHTTPError, SafeHttpClient, safe_url
from app.core.logging import get_logger

log = get_logger("warden.acquisition.pypi")

# PEP 508 project name grammar (case-insensitive); PyPI additionally caps names at 214 chars.
NAME_RE = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)
MAX_NAME_LENGTH = 214
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,254}$")
_HEX_RE = re.compile(r"^[0-9a-f]{32,128}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

MAX_STRING = 2000
MAX_LIST = 200
MAX_CLASSIFIERS = 50
MAX_ARTIFACTS_PER_RELEASE = 500
MAX_RELEASES = 10000
MAX_PROVENANCE_BYTES = 2 * 1024 * 1024
INTEGRITY_ACCEPT = "application/vnd.pypi.integrity.v1+json"
_DIGEST_ALGORITHMS = ("sha256", "md5", "blake2b_256")
_SLIM_STRING_KEYS = (
    "name", "version", "summary", "home_page", "author", "author_email", "maintainer", "maintainer_email",
    "license", "license_expression", "requires_python", "yanked_reason",
)


# --------------------------------------------------------------------------- validation helpers
def validate_name(name: object) -> str:
    value = name.strip() if isinstance(name, str) else ""
    if not value or len(value) > MAX_NAME_LENGTH or not NAME_RE.match(value):
        raise AnalysisError("Invalid PyPI package name", code="invalid_package_name", status_code=400)
    return value


def validate_version(version: object) -> str:
    value = version.strip() if isinstance(version, str) else ""
    if not VERSION_RE.match(value):
        raise AnalysisError("Invalid package version", code="invalid_version", status_code=400)
    return value


def _quote(segment: str) -> str:
    return quote(segment, safe="")


def bounded_str(value: object, max_len: int = MAX_STRING) -> str | None:
    """A registry string cut to ``max_len``; non-strings become ``None``."""
    return value[:max_len] if isinstance(value, str) else None


def bounded(value: Any, *, depth: int = 0) -> Any:
    """JSON-like registry value with bounded strings, lists, mappings and nesting."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_STRING]
    if depth >= 4:
        return None
    if isinstance(value, Mapping):
        return {str(k)[:200]: bounded(v, depth=depth + 1) for k, v in list(value.items())[:MAX_LIST]}
    if isinstance(value, (list, tuple)):
        return [bounded(v, depth=depth + 1) for v in list(value)[:MAX_LIST]]
    return None


def _str_list(value: object, limit: int) -> list[str] | None:
    if not isinstance(value, list):
        return None
    return [v[:MAX_STRING] for v in value if isinstance(v, str)][:limit]


def _str_map(value: object) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    items = [(k, v) for k, v in value.items() if isinstance(k, str) and isinstance(v, str)]
    return {k[:200]: v[:MAX_STRING] for k, v in items[:MAX_LIST]}


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _version_key(version: str) -> tuple:
    try:
        return (0, Version(version), "")
    except InvalidVersion:
        return (1, Version("0"), version)


def wheel_tags(filename: str) -> tuple[str, str, str] | None:
    """``(python, abi, platform)`` tag strings from a wheel filename, or ``None`` if not a wheel name."""
    if not isinstance(filename, str) or not filename.lower().endswith(".whl"):
        return None
    parts = filename[:-4].split("-")
    if len(parts) not in (5, 6):
        return None
    return parts[-3], parts[-2], parts[-1]


def is_pure_python_wheel(filename: str) -> bool:
    """True for wheels tagged ``none-any`` (no compiled code expected)."""
    tags = wheel_tags(filename)
    if tags is None:
        return False
    return all(a == "none" for a in tags[1].split(".")) and all(p == "any" for p in tags[2].split("."))


def maintainer_count(metadata: Mapping[str, Any]) -> int:
    """v1 feature semantics: distinct comma-separated names across author and maintainer."""
    names: set[str] = set()
    for key in ("author", "maintainer"):
        value = metadata.get(key)
        if isinstance(value, str) and value:
            names.update(part.strip() for part in value.split(",") if part.strip())
    return len(names)


@dataclass
class ResolvedRelease:
    """The registry view of one release, as selected by :meth:`PyPIClient.resolve`."""

    name: str
    requested_version: str | None
    version: str
    version_found: bool
    info: dict  # raw registry ``info`` for ``version`` (hostile; bound via build_metadata)
    files: list  # raw registry file entries for ``version``
    releases: list[ReleaseInfo] = field(default_factory=list)
    project_info: dict = field(default_factory=dict)


# Outcomes of :meth:`PyPIClient.provenance_lookup` (``ProvenanceLookup.status``).
LOOKUP_FOUND = "found"
LOOKUP_NOT_FOUND = "not_found"
LOOKUP_MALFORMED = "malformed"
LOOKUP_ERROR = "error"
LOOKUP_INVALID_INPUT = "invalid_input"


@dataclass
class ProvenanceLookup:
    """Outcome of one Integrity API provenance request, keeping *why* no document is available.

    ``status`` is one of:

    * ``found`` — HTTP 2xx with a JSON object body in ``document`` (still hostile and unvalidated);
    * ``not_found`` — HTTP 404: the registry reports no provenance for the file;
    * ``malformed`` — HTTP 2xx whose body is not valid JSON or not a JSON object
      (``error_kind`` ``invalid_json`` / ``not_an_object``);
    * ``error`` — no complete answer: transport failure, refused response (size cap, host
      allowlist, undecodable encoding) or an HTTP status other than 2xx/404. ``error_kind`` is the
      :class:`~app.core.http.OutboundHTTPError` kind, or ``status`` for an error status;
    * ``invalid_input`` — the coordinates failed validation, so no request was made.
    """

    status: str
    document: dict | None = None
    http_status: int | None = None
    error_kind: str | None = None


class PyPIClient:
    def __init__(
        self,
        *,
        registry_http: SafeHttpClient | None = None,
        artifact_http: SafeHttpClient | None = None,
        json_base: str | None = None,
        integrity_base: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        timeout = float(settings.FETCH_TIMEOUT_SECONDS)
        self._owned: list[SafeHttpClient] = []
        if registry_http is None:
            registry_http = SafeHttpClient(
                name="pypi-registry", allowed_hosts=settings.REGISTRY_HOST_ALLOWLIST,
                max_response_bytes=settings.MAX_METADATA_BYTES, timeout=timeout, rate_limit_per_second=10.0,
                total_timeout=float(settings.SCAN_TIMEOUT_SECONDS),
            )
            self._owned.append(registry_http)
        if artifact_http is None:
            artifact_http = SafeHttpClient(
                name="pypi-artifacts", allowed_hosts=settings.ARTIFACT_HOST_ALLOWLIST,
                max_response_bytes=settings.MAX_DOWNLOAD_BYTES, timeout=timeout, rate_limit_per_second=5.0,
                # A slow-drip artifact server must not hold a scan past the scan budget.
                total_timeout=float(settings.SCAN_TIMEOUT_SECONDS),
            )
            self._owned.append(artifact_http)
        self.registry_http = registry_http
        self.artifact_http = artifact_http
        self.json_base = (json_base or settings.PYPI_JSON_BASE).rstrip("/")
        self.integrity_base = (integrity_base or settings.PYPI_INTEGRITY_API_BASE).rstrip("/")
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def close(self) -> None:
        for client in self._owned:
            client.close()

    # ------------------------------------------------------------------ registry JSON
    def _get_registry_json(self, url: str) -> dict | None:
        """GET registry JSON; ``None`` on 404. Transport/status/format problems raise AnalysisError."""
        try:
            result = self.registry_http.request("GET", url, max_bytes=settings.MAX_METADATA_BYTES)
            if result.status == 404:
                return None
            if result.status >= 400:
                raise AnalysisError(f"PyPI registry error (HTTP {result.status})", code="registry_unavailable")
            data = result.json()
        except OutboundHTTPError as exc:
            log.warning("registry_request_failed", url=safe_url(url), kind=exc.kind, status=exc.status)
            if exc.kind == "decode":
                raise AnalysisError("PyPI registry returned malformed metadata", code="registry_malformed") from exc
            raise AnalysisError(f"PyPI registry request failed ({exc.kind})", code="registry_unavailable") from exc
        if not isinstance(data, dict) or not isinstance(data.get("info"), dict):
            raise AnalysisError("PyPI registry returned malformed metadata", code="registry_malformed")
        return data

    def project(self, name: str) -> dict:
        """Project JSON (``/pypi/<name>/json``). 404 raises ``package_not_found``."""
        name = validate_name(name)
        data = self._get_registry_json(f"{self.json_base}/{_quote(name)}/json")
        if data is None:
            raise AnalysisError(f"Package '{name}' not found on PyPI", code="package_not_found", status_code=404)
        return data

    def release(self, name: str, version: str) -> dict | None:
        """Version-specific JSON (``/pypi/<name>/<version>/json``); ``None`` when it does not exist."""
        name, version = validate_name(name), validate_version(version)
        return self._get_registry_json(f"{self.json_base}/{_quote(name)}/{_quote(version)}/json")

    def resolve(self, name: str, version: str | None) -> ResolvedRelease:
        """Select the release to analyse. A missing version yields ``version_found=False`` with the
        latest release's data; the caller decides whether that is acceptable (fail closed by default)."""
        name = validate_name(name)
        requested = validate_version(version) if version is not None else None
        project = self.project(name)
        info = project["info"]
        latest = bounded_str(info.get("version"), 128) or ""
        releases = self.releases(project)
        raw_releases = project.get("releases") if isinstance(project.get("releases"), Mapping) else {}

        match = self._match_version(requested, {r.version for r in releases} | {latest}) if requested else latest
        doc: dict | None = project if match == latest else None
        if requested and match is None:
            doc = self.release(name, requested)  # project JSON may omit the releases map
            match = requested if doc is not None else None
        elif match and doc is None:
            doc = self.release(name, match)
        if not match or doc is None:
            files = self._files(project, raw_releases, latest)
            return ResolvedRelease(name, requested, latest, False, dict(info), files, releases, dict(info))
        files = self._files(doc, raw_releases, match)
        return ResolvedRelease(name, requested, match, True, dict(doc["info"]), files, releases, dict(info))

    @staticmethod
    def _match_version(requested: str, known: set[str]) -> str | None:
        if requested in known:
            return requested
        try:
            wanted = Version(requested)
        except InvalidVersion:
            return None
        for candidate in sorted(known):
            try:
                if Version(candidate) == wanted:
                    return candidate
            except InvalidVersion:
                continue
        return None

    @staticmethod
    def _files(doc: Mapping, raw_releases: Mapping, version: str) -> list:
        urls = doc.get("urls")
        if isinstance(urls, list) and urls:
            return urls
        files = raw_releases.get(version)
        return files if isinstance(files, list) else []

    # ------------------------------------------------------------------ releases / artifacts
    def releases(self, project: Mapping) -> list[ReleaseInfo]:
        """Release history sorted oldest → newest by earliest upload time; untimed releases last."""
        raw = project.get("releases")
        if not isinstance(raw, Mapping):
            return []
        timed: list[tuple[datetime, str, int, bool]] = []
        untimed: list[tuple[str, int, bool]] = []
        for version, files in raw.items():
            if not isinstance(version, str) or not VERSION_RE.match(version):
                continue
            entries = [f for f in files if isinstance(f, Mapping)] if isinstance(files, list) else []
            times = [t for t in (parse_time(f.get("upload_time_iso_8601") or f.get("upload_time")) for f in entries)
                     if t]
            yanked = bool(entries) and all(f.get("yanked") is True for f in entries)
            if times:
                timed.append((min(times), version, len(entries), yanked))
            else:
                untimed.append((version, len(entries), yanked))
        timed.sort(key=lambda r: (r[0], _version_key(r[1])))
        untimed.sort(key=lambda r: _version_key(r[0]))
        timed = timed[-MAX_RELEASES:]
        untimed = untimed[: max(0, MAX_RELEASES - len(timed))]
        out = [ReleaseInfo(version=v, upload_time=_iso(t), yanked=y, file_count=n) for t, v, n, y in timed]
        out.extend(ReleaseInfo(version=v, upload_time=None, yanked=y, file_count=n) for v, n, y in untimed)
        return out

    def artifacts(self, files: object) -> list[ArtifactInfo]:
        """Distribution files for a release; malformed entries are dropped."""
        if not isinstance(files, list):
            return []
        out: list[ArtifactInfo] = []
        dropped = 0
        for entry in files[:MAX_ARTIFACTS_PER_RELEASE]:
            filename = entry.get("filename") if isinstance(entry, Mapping) else None
            url = entry.get("url") if isinstance(entry, Mapping) else None
            if not (isinstance(filename, str) and FILENAME_RE.match(filename)
                    and isinstance(url, str) and 0 < len(url) <= MAX_STRING):
                dropped += 1
                continue
            raw_digests = entry.get("digests") if isinstance(entry.get("digests"), Mapping) else {}
            digests = {}
            for algo in _DIGEST_ALGORITHMS:
                value = raw_digests.get(algo)
                if isinstance(value, str) and _HEX_RE.match(value.lower()):
                    digests[algo] = value.lower()
            if "sha256" in digests and not _SHA256_RE.match(digests["sha256"]):
                del digests["sha256"]
            size = entry.get("size")
            uploaded = parse_time(entry.get("upload_time_iso_8601") or entry.get("upload_time"))
            out.append(ArtifactInfo(
                filename=filename,
                url=url,
                packagetype=bounded_str(entry.get("packagetype"), 32) or "",
                size=size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None,
                digests=digests,
                upload_time=_iso(uploaded),
                yanked=entry.get("yanked") is True,
                yanked_reason=bounded_str(entry.get("yanked_reason")),
                requires_python=bounded_str(entry.get("requires_python"), 200),
            ))
        if dropped:
            log.warning("registry_artifacts_dropped", count=dropped)
        return out

    def download(self, artifact: ArtifactInfo) -> bytes:
        """Download ``artifact`` and record its sha256 / verification status on the object.

        Raises :class:`OutboundHTTPError` (``too_large`` without a request when the registry
        declares a size above ``MAX_DOWNLOAD_BYTES``).
        """
        if artifact.size is not None and artifact.size > settings.MAX_DOWNLOAD_BYTES:
            raise OutboundHTTPError("artifact exceeds maximum download size", kind="too_large",
                                    url=safe_url(artifact.url))
        data = self.artifact_http.get_bytes(artifact.url, max_bytes=settings.MAX_DOWNLOAD_BYTES)
        digest = hashlib.sha256(data).hexdigest()
        artifact.downloaded_sha256 = digest
        expected = artifact.digests.get("sha256")
        artifact.hash_verified = hmac.compare_digest(digest, expected) if expected else None
        return data

    # ------------------------------------------------------------------ integrity API
    def provenance(self, name: str, version: str, filename: str) -> dict | None:
        """PEP 740 provenance for one file, or ``None`` (absent, invalid input, or lookup failure)."""
        try:
            name, version = validate_name(name), validate_version(version)
        except AnalysisError:
            log.warning("provenance_lookup_skipped", reason="invalid_coordinates")
            return None
        if not isinstance(filename, str) or not FILENAME_RE.match(filename):
            log.warning("provenance_lookup_skipped", reason="invalid_filename")
            return None
        url = f"{self.integrity_base}/{_quote(name)}/{_quote(version)}/{_quote(filename)}/provenance"
        try:
            result = self.registry_http.request("GET", url, headers={"Accept": INTEGRITY_ACCEPT},
                                                max_bytes=MAX_PROVENANCE_BYTES)
            if result.status == 404:
                return None
            if result.status >= 400:
                log.warning("provenance_lookup_failed", url=safe_url(url), status=result.status)
                return None
            data = result.json()
        except OutboundHTTPError as exc:
            log.warning("provenance_lookup_failed", url=safe_url(url), kind=exc.kind, status=exc.status)
            return None
        return data if isinstance(data, dict) else None

    def provenance_lookup(self, name: str, version: str, filename: str) -> ProvenanceLookup:
        """PEP 740 provenance for one file, reporting why no document is available (see :class:`ProvenanceLookup`).

        Unlike :meth:`provenance` (kept unchanged for existing callers) this distinguishes "the
        registry has no provenance" (404) from "the lookup failed" and from "the registry served a
        2xx body that is not a provenance object", which callers must not conflate. It never raises
        for network, status or decoding problems.
        """
        try:
            name, version = validate_name(name), validate_version(version)
        except AnalysisError:
            log.warning("provenance_lookup_skipped", reason="invalid_coordinates")
            return ProvenanceLookup(LOOKUP_INVALID_INPUT, error_kind="invalid_coordinates")
        if not isinstance(filename, str) or not FILENAME_RE.match(filename):
            log.warning("provenance_lookup_skipped", reason="invalid_filename")
            return ProvenanceLookup(LOOKUP_INVALID_INPUT, error_kind="invalid_filename")
        url = f"{self.integrity_base}/{_quote(name)}/{_quote(version)}/{_quote(filename)}/provenance"
        try:
            result = self.registry_http.request("GET", url, headers={"Accept": INTEGRITY_ACCEPT},
                                                max_bytes=MAX_PROVENANCE_BYTES)
        except OutboundHTTPError as exc:
            log.warning("provenance_lookup_failed", url=safe_url(url), kind=exc.kind, status=exc.status)
            return ProvenanceLookup(LOOKUP_ERROR, http_status=exc.status, error_kind=exc.kind)
        if result.status == 404:
            return ProvenanceLookup(LOOKUP_NOT_FOUND, http_status=404)
        if not 200 <= result.status < 300:
            log.warning("provenance_lookup_failed", url=safe_url(url), status=result.status)
            return ProvenanceLookup(LOOKUP_ERROR, http_status=result.status, error_kind="status")
        try:
            data = result.json()
        except OutboundHTTPError:
            log.warning("provenance_document_malformed", url=safe_url(url), reason="invalid_json")
            return ProvenanceLookup(LOOKUP_MALFORMED, http_status=result.status, error_kind="invalid_json")
        if not isinstance(data, dict):
            log.warning("provenance_document_malformed", url=safe_url(url), reason="not_an_object")
            return ProvenanceLookup(LOOKUP_MALFORMED, http_status=result.status, error_kind="not_an_object")
        return ProvenanceLookup(LOOKUP_FOUND, document=data, http_status=result.status)

    def previous_release_metadata(self, name: str, version: str) -> dict[str, Any] | None:
        """Bounded identity metadata of one specific release (e.g. the release before the analysed one).

        Reads ``/pypi/<name>/<version>/json`` and returns the slim string keys (``author``,
        ``author_email``, ``maintainer``, ``maintainer_email`` ...), ``project_urls``,
        ``ownership`` (when present) and ``_maintainer_count``, bounded exactly like
        :meth:`build_metadata`. Returns ``None`` when the version does not exist; raises
        :class:`AnalysisError` for invalid coordinates, transport failures and malformed metadata
        (see :meth:`release`).

        PyPI serves ``ownership`` as the project's *current* roles, not the roles at the time the
        release was published, so on its own it cannot reveal a historical ownership change.
        """
        doc = self.release(name, version)
        if doc is None:
            return None
        info = doc["info"]
        md: dict[str, Any] = {key: bounded_str(info.get(key)) for key in _SLIM_STRING_KEYS}
        md["version"] = validate_version(version)
        md["project_urls"] = _str_map(info.get("project_urls"))
        ownership = info.get("ownership")
        if isinstance(ownership, Mapping):
            md["ownership"] = bounded(ownership)
        md["_maintainer_count"] = maintainer_count(md)
        return md

    # ------------------------------------------------------------------ metadata
    def build_metadata(self, release: ResolvedRelease) -> dict[str, Any]:
        """Slim, bounded metadata for the analyzers plus Warden-derived ``_`` keys."""
        info = release.info
        md: dict[str, Any] = {key: bounded_str(info.get(key)) for key in _SLIM_STRING_KEYS}
        md["version"] = release.version
        md["project_urls"] = _str_map(info.get("project_urls"))
        md["requires_dist"] = _str_list(info.get("requires_dist"), MAX_LIST)
        md["classifiers"] = _str_list(info.get("classifiers"), MAX_CLASSIFIERS) or []
        keywords = info.get("keywords")
        md["keywords"] = _str_list(keywords, MAX_LIST) if isinstance(keywords, list) else bounded_str(keywords)
        ownership = info.get("ownership") if info.get("ownership") is not None else release.project_info.get(
            "ownership")
        if isinstance(ownership, Mapping):
            md["ownership"] = bounded(ownership)
        md["yanked"] = info.get("yanked") is True
        md.update(self._derived(md, release))
        return md

    def _derived(self, md: Mapping[str, Any], release: ResolvedRelease) -> dict[str, Any]:
        now = self._clock()
        timed = [(parse_time(r.upload_time), r) for r in release.releases if r.upload_time]
        index = next((i for i, (_, r) in enumerate(timed) if r.version == release.version), None)
        current = timed[index][0] if index is not None else None
        previous = timed[index - 1] if index else None
        return {
            "_maintainer_count": maintainer_count(md),
            "_age_days": round(max((now - current).total_seconds() / 86400.0, 0.0), 4) if current else None,
            "_releases_last_7d": sum(1 for t, _ in timed if (now - t).total_seconds() <= 7 * 86400),
            "_version_found": release.version_found,
            "_release_count": len(release.releases),
            "_first_release_at": timed[0][1].upload_time if timed else None,
            "_previous_version": previous[1].version if previous else None,
            "_previous_release_at": previous[1].upload_time if previous else None,
            "_days_since_previous_release": (
                round((current - previous[0]).total_seconds() / 86400.0, 4) if previous and current else None
            ),
        }
