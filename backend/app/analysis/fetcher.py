"""Registry fetcher — the *only* component that touches the network or untrusted archives.

Responsibilities and the security guarantees each provides:

* Resolve ``(name, version)`` against the PyPI JSON API and compute provenance metadata
  (age, maintainer count, release cadence) for the metadata analyzer.
* Download the source artifact under a hard **size cap** (defends against oversized
  downloads) and a **wall-clock timeout** (defends against slowloris-style stalls).
* Extract the archive with **path-traversal (Zip-Slip) guards**, a **decompressed-size
  cap** and **file-count cap** (defends against zip/tar bombs), rejecting symlinks and
  absolute members.
* Return only decoded, per-file-size-capped text for Python and build files. **No package
  code is ever executed.**

Everything downstream operates purely on the returned in-memory context.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from datetime import datetime, timezone

import httpx

from app.analysis.analyzers.base import PackageContext, SourceFile
from app.analysis.signals import Code, Severity, Signal
from app.core.config import settings
from app.core.errors import AnalysisError
from app.core.logging import get_logger

log = get_logger("warden.fetcher")

# Only files we actually analyse are retained (keeps memory bounded, avoids binary blobs).
_INTERESTING_SUFFIXES = (".py", ".cfg", ".toml", ".txt", ".sh", ".ps1", ".js")
_ALWAYS_KEEP = {"setup.py", "setup.cfg", "pyproject.toml", "PKG-INFO"}


class RegistryFetcher:
    def __init__(self, client: httpx.Client | None = None) -> None:
        # The HTTP client is created lazily so importing the app performs no I/O setup
        # and unit tests never construct a real network client.
        self._client_override = client
        self._client_instance: httpx.Client | None = None

    @property
    def _client(self) -> httpx.Client:
        if self._client_override is not None:
            return self._client_override
        if self._client_instance is None:
            self._client_instance = httpx.Client(
                timeout=settings.FETCH_TIMEOUT_SECONDS,
                follow_redirects=True,
                headers={"User-Agent": "Warden-SupplyChainFirewall/1.0"},
            )
        return self._client_instance

    # -- public API --------------------------------------------------------
    def build_context(self, name: str, version: str | None) -> PackageContext:
        info, resolved_version, sdist_url, version_found = self._resolve(name, version)
        ctx = PackageContext(
            ecosystem="pypi",
            name=name,
            version=resolved_version,
            metadata={**info, "_version_found": version_found},
        )
        if not sdist_url:
            ctx.context_signals.append(Signal(
                Code.FETCH_FAILED, Severity.medium, 3.0,
                "No source distribution available to analyse (only wheels/none)",
                {"package": name, "version": resolved_version},
            ))
            return ctx

        try:
            archive = self._download(sdist_url)
            files = self._safe_extract(archive, sdist_url)
        except AnalysisError:
            raise
        except Exception as exc:  # fail-safe: extraction issues raise risk, never crash
            log.warning("extract_failed", error=str(exc), url=sdist_url)
            ctx.context_signals.append(Signal(
                Code.EXTRACTION_ABORTED, Severity.medium, 4.0,
                "Package archive could not be safely extracted", {"reason": str(exc)[:120]},
            ))
            return ctx

        ctx.files = files
        return ctx

    # -- metadata resolution ----------------------------------------------
    def _resolve(self, name: str, version: str | None):
        url = f"{settings.PYPI_JSON_BASE}/{name}/json"
        try:
            resp = self._client.get(url)
        except httpx.HTTPError as exc:
            raise AnalysisError(f"Registry unreachable: {exc}") from exc
        if resp.status_code == 404:
            raise AnalysisError(f"Package '{name}' not found on PyPI", code="package_not_found")
        if resp.status_code >= 400:
            raise AnalysisError(f"Registry error {resp.status_code} for '{name}'")

        data = resp.json()
        info = data.get("info", {})
        releases: dict = data.get("releases", {})

        version_found = True
        resolved = version
        if version is None or version not in releases:
            version_found = version is None
            resolved = info.get("version")  # latest

        # Provenance features.
        info["_maintainer_count"] = _maintainer_count(info)
        info["_age_days"] = _release_age_days(releases.get(resolved, []))
        info["_releases_last_7d"] = _releases_last_7d(releases)

        # Pick the sdist for the resolved version.
        sdist_url = None
        for artifact in releases.get(resolved, []):
            if artifact.get("packagetype") == "sdist":
                sdist_url = artifact.get("url")
                break
        # Fall back to the latest sdist if the exact version has none.
        if sdist_url is None:
            for artifact in data.get("urls", []):
                if artifact.get("packagetype") == "sdist":
                    sdist_url = artifact.get("url")
                    break

        # Keep only JSON-safe metadata fields we use (avoid storing huge blobs).
        slim = {
            k: info.get(k)
            for k in (
                "name", "version", "home_page", "project_urls", "summary",
                "author", "license", "requires_python",
                "_maintainer_count", "_age_days", "_releases_last_7d",
            )
        }
        return slim, resolved or "unknown", sdist_url, version_found

    # -- download with caps ------------------------------------------------
    def _download(self, url: str) -> bytes:
        if not url.startswith("https://") and not url.startswith("http://"):
            raise AnalysisError("Refusing to fetch non-http(s) artifact URL")
        buf = io.BytesIO()
        try:
            with self._client.stream("GET", url) as resp:
                if resp.status_code >= 400:
                    raise AnalysisError(f"Artifact download failed ({resp.status_code})")
                total = 0
                for chunk in resp.iter_bytes(chunk_size=65536):
                    total += len(chunk)
                    if total > settings.MAX_DOWNLOAD_BYTES:
                        raise AnalysisError("Artifact exceeds maximum allowed size")
                    buf.write(chunk)
        except httpx.HTTPError as exc:
            raise AnalysisError(f"Artifact download error: {exc}") from exc
        return buf.getvalue()

    # -- safe extraction ---------------------------------------------------
    def _safe_extract(self, archive: bytes, url: str) -> list[SourceFile]:
        if url.endswith(".zip"):
            return self._extract_zip(archive)
        return self._extract_tar(archive)

    def _extract_tar(self, archive: bytes) -> list[SourceFile]:
        files: list[SourceFile] = []
        total_bytes = 0
        count = 0
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
            for member in tar:
                count += 1
                if count > settings.MAX_EXTRACTED_FILES:
                    raise AnalysisError("Archive contains too many files (bomb guard)")
                if not member.isfile():
                    continue  # skip dirs, and crucially symlinks/devices
                if member.issym() or member.islnk():
                    continue
                if _is_unsafe_path(member.name):
                    raise AnalysisError(f"Unsafe path in archive: {member.name}")
                if member.size > settings.MAX_ANALYZED_FILE_BYTES * 4:
                    continue
                if not _is_interesting(member.name):
                    continue
                total_bytes += member.size
                if total_bytes > settings.MAX_EXTRACTED_BYTES:
                    raise AnalysisError("Archive decompressed size exceeds cap (bomb guard)")
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                files.append(_read_source(member.name, fh.read()))
        return files

    def _extract_zip(self, archive: bytes) -> list[SourceFile]:
        files: list[SourceFile] = []
        total_bytes = 0
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            infos = zf.infolist()
            if len(infos) > settings.MAX_EXTRACTED_FILES:
                raise AnalysisError("Archive contains too many files (bomb guard)")
            for zi in infos:
                if zi.is_dir():
                    continue
                if _is_unsafe_path(zi.filename):
                    raise AnalysisError(f"Unsafe path in archive: {zi.filename}")
                if not _is_interesting(zi.filename):
                    continue
                if zi.file_size > settings.MAX_ANALYZED_FILE_BYTES * 4:
                    continue
                total_bytes += zi.file_size
                if total_bytes > settings.MAX_EXTRACTED_BYTES:
                    raise AnalysisError("Archive decompressed size exceeds cap (bomb guard)")
                with zf.open(zi) as fh:
                    files.append(_read_source(zi.filename, fh.read()))
        return files


# --- helpers ---------------------------------------------------------------
def _is_unsafe_path(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or ".." in n.split("/") or n.startswith("~")


def _is_interesting(name: str) -> bool:
    base = name.replace("\\", "/").split("/")[-1]
    return base in _ALWAYS_KEEP or name.endswith(_INTERESTING_SUFFIXES)


def _read_source(name: str, raw: bytes) -> SourceFile:
    truncated = False
    if len(raw) > settings.MAX_ANALYZED_FILE_BYTES:
        raw = raw[: settings.MAX_ANALYZED_FILE_BYTES]
        truncated = True
    text = raw.decode("utf-8", errors="replace")
    rel = name.replace("\\", "/")
    # Drop the leading "pkg-1.0/" top-level directory for cleaner relpaths.
    parts = rel.split("/", 1)
    rel = parts[1] if len(parts) == 2 else rel
    return SourceFile(relpath=rel, text=text, size=len(raw), truncated=truncated)


def _maintainer_count(info: dict) -> int:
    names = set()
    for key in ("author", "maintainer"):
        val = info.get(key)
        if val:
            names.update(p.strip() for p in str(val).split(",") if p.strip())
    return max(len(names), 0)


def _release_age_days(artifacts: list) -> float | None:
    for a in artifacts:
        ts = a.get("upload_time_iso_8601") or a.get("upload_time")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return max((datetime.now(timezone.utc) - dt).total_seconds() / 86400.0, 0.0)
            except ValueError:
                return None
    return None


def _releases_last_7d(releases: dict) -> int:
    now = datetime.now(timezone.utc)
    recent = 0
    for artifacts in releases.values():
        for a in artifacts:
            ts = a.get("upload_time_iso_8601") or a.get("upload_time")
            if not ts:
                continue
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if (now - dt).total_seconds() <= 7 * 86400:
                    recent += 1
            except ValueError:
                continue
            break  # count each version once
    return recent
