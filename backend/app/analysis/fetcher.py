"""Registry fetcher — builds the hostile-input :class:`PackageContext` for a package scan.

This is the only analysis component that touches the network or untrusted archives; every
analyzer downstream works on the returned in-memory context. **No package code is executed.**

Pipeline and the guarantee each step provides:

1. **Resolve** ``(name, version)`` with :class:`~app.analysis.acquisition.pypi.PyPIClient`
   (validated names, host allowlists, size caps, bounded metadata). **Fail closed:** an
   explicitly requested version that does not exist raises ``AnalysisError(code=
   "version_not_found", status_code=404)`` while ``FAIL_ON_VERSION_NOT_FOUND`` is enabled —
   a verdict for a different version is never returned silently.
2. **Choose an artifact:** the sdist (it is what builds run from, so install-time code lives
   there), otherwise a wheel, preferring ``py3-none-any``. Artifacts whose registry-declared size
   exceeds ``MAX_DOWNLOAD_BYTES`` are not chosen. No usable artifact → ``FETCH_FAILED``.
3. **Download and verify:** the sha256 of the downloaded bytes is compared with the registry
   digest; a mismatch adds a critical ``HASH_MISMATCH`` finding and analysis continues on the
   bytes actually received. A deterministic refusal (too large, artifact host not allowlisted)
   adds ``FETCH_FAILED``; transient network/HTTP failures raise ``AnalysisError`` so no verdict is
   produced from an incomplete fetch.
4. **Extract** with :class:`~app.analysis.extraction.safe_archive.SafeArchiveReader`. A tripped
   hostile-input guard adds ``EXTRACTION_ABORTED``; members read before the abort are kept.
5. **Wheel inventory (optional):** when an sdist was analysed and wheel analysis is enabled, one
   wheel is inventoried too (``wheel_inventory`` / ``wheel_files``) so sdist/wheel divergence can
   be detected. The wheel reader gets whatever text budget the sdist left, but never less than
   ``WHEEL_MIN_TEXT_BYTES``, so a large benign sdist cannot switch the divergence check off. A
   wheel extraction abort of any kind is reported as ``EXTRACTION_ABORTED``; download failures
   never fail the scan.

``_extract_tar`` / ``_extract_zip`` / ``_is_unsafe_path`` are kept for v1 callers; the extract
shims raise ``AnalysisError`` whenever the reader aborts (traversal, bombs, corruption) or had
to leave text members unanalysed because of the retention budget (v1 was all-or-nothing).
"""

from __future__ import annotations

import threading

import httpx

from app.analysis.acquisition.pypi import PyPIClient, is_pure_python_wheel, wheel_tags
from app.analysis.analyzers.base import ArtifactInfo, PackageContext, ScanOptions, SourceFile
from app.analysis.extraction.safe_archive import (
    ABORTING_PATH_PROBLEMS,
    TEXT_BUDGET_SKIP_REASON,
    ExtractionResult,
    SafeArchiveReader,
    normalize_member_path,
)
from app.analysis.findings import Category, Finding, Provenance
from app.analysis.signals import Code, Severity
from app.core.config import settings
from app.core.errors import AnalysisError
from app.core.http import OutboundHTTPError, SafeHttpClient
from app.core.logging import get_logger
from app.core.redaction import sanitize_text

log = get_logger("warden.fetcher")

PIPELINE_PROVENANCE = "analysis-pipeline"
WHEEL_FILE_SUFFIXES = (".py", ".pth")
# Deterministic refusals: the package itself cannot be fetched within policy.
_REFUSAL_KINDS = frozenset({"too_large", "host_not_allowed", "scheme"})
# Abort reasons that indicate a deliberately malformed archive rather than a budget limit.
_HOSTILE_ABORTS = frozenset({
    "unsafe_path", "decompressed_size_exceeded", "declared_size_exceeded", "tar_metadata_header_too_large",
    "tar_metadata_exceeded", "tar_metadata_chain_too_long", "suspicious_compression_ratio",
    "inconsistent_member_header", "member_size_mismatch", "sparse_member_unsupported",
    "priority_text_budget_exceeded", "lzma_dictionary_too_large",
})
# Floor for the wheel reader's text budget, independent of how much the sdist retained.
WHEEL_MIN_TEXT_BYTES = 16 * 1024 * 1024


# --------------------------------------------------------------------------- artifact choice
def _within_download_cap(artifact: ArtifactInfo) -> bool:
    return artifact.size is None or artifact.size <= settings.MAX_DOWNLOAD_BYTES


def _is_wheel(artifact: ArtifactInfo) -> bool:
    return artifact.packagetype == "bdist_wheel" or artifact.filename.lower().endswith(".whl")


def choose_wheel(artifacts: list[ArtifactInfo]) -> ArtifactInfo | None:
    """Best wheel to inventory: pure ``py3`` first, then other pure wheels, then any wheel."""

    def rank(artifact: ArtifactInfo) -> tuple[int, str]:
        tags = wheel_tags(artifact.filename)
        pure = is_pure_python_wheel(artifact.filename)
        if pure and tags and "py3" in tags[0].split("."):
            return 0, artifact.filename
        return (1 if pure else 2), artifact.filename

    wheels = [a for a in artifacts if _is_wheel(a) and _within_download_cap(a)]
    return min(wheels, key=rank) if wheels else None


def choose_artifact(artifacts: list[ArtifactInfo]) -> ArtifactInfo | None:
    """The sdist when one is available within the download cap (``.tar.gz`` preferred), else a wheel."""
    sdists = [a for a in artifacts if a.packagetype == "sdist" and _within_download_cap(a)]
    if sdists:
        return min(sdists, key=lambda a: (not a.filename.lower().endswith(".tar.gz"), a.filename))
    return choose_wheel(artifacts)


# --------------------------------------------------------------------------- context findings
def _fetch_failed(message: str, evidence: dict) -> Finding:
    return Finding(Code.FETCH_FAILED, Severity.medium, 3.0, message, evidence, confidence=1.0,
                   category=Category.PIPELINE, provenance=PIPELINE_PROVENANCE)


def _hash_mismatch(artifact: ArtifactInfo) -> Finding:
    expected = artifact.digests.get("sha256") or ""
    actual = artifact.downloaded_sha256 or ""
    return Finding(
        Code.HASH_MISMATCH, Severity.critical, 10.0,
        f"Downloaded {artifact.filename} does not match the sha256 digest published by the registry",
        {"artifact": artifact.filename, "algorithm": "sha256",
         "expected_digest_prefix": expected[:12], "actual_digest_prefix": actual[:12]},
        confidence=0.98, category=Category.INTEGRITY, provenance=Provenance.REGISTRY,
    )


def _extraction_aborted(artifact: ArtifactInfo, result: ExtractionResult) -> Finding:
    reason = result.aborted_reason or "unknown"
    hostile = reason in _HOSTILE_ABORTS
    return Finding(
        Code.EXTRACTION_ABORTED, Severity.high if hostile else Severity.medium, 6.0 if hostile else 4.0,
        f"Archive {artifact.filename} failed safe-extraction checks ({reason}); analysis is partial",
        {
            "artifact": artifact.filename,
            "reason": reason,
            "detail": sanitize_text(result.abort_detail, max_len=200) if result.abort_detail else None,
            "archive_format": result.archive_format,
            "members_seen": result.stats.get("members"),
        },
        confidence=0.95 if hostile else 0.9, category=Category.INTEGRITY, provenance=PIPELINE_PROVENANCE,
    )


class RegistryFetcher:
    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        pypi: PyPIClient | None = None,
        reader: SafeArchiveReader | None = None,
    ) -> None:
        # Clients are created lazily so importing the app performs no network-client setup and
        # unit tests never construct a real client. A supplied ``httpx.Client`` is wrapped in
        # SafeHttpClient so allowlists, size caps and redirect checks still apply.
        self._client_override = client
        self._pypi_override = pypi
        self._pypi_instance: PyPIClient | None = None
        self._reader = reader or SafeArchiveReader()
        self._lock = threading.Lock()

    @property
    def pypi(self) -> PyPIClient:
        if self._pypi_override is not None:
            return self._pypi_override
        with self._lock:
            if self._pypi_instance is None:
                self._pypi_instance = self._make_pypi()
            return self._pypi_instance

    def _make_pypi(self) -> PyPIClient:
        if self._client_override is None:
            return PyPIClient()
        timeout = float(settings.FETCH_TIMEOUT_SECONDS)
        budget = float(settings.SCAN_TIMEOUT_SECONDS)
        registry = SafeHttpClient(name="pypi-registry", allowed_hosts=settings.REGISTRY_HOST_ALLOWLIST,
                                  max_response_bytes=settings.MAX_METADATA_BYTES, timeout=timeout,
                                  client=self._client_override, total_timeout=budget)
        artifacts = SafeHttpClient(name="pypi-artifacts", allowed_hosts=settings.ARTIFACT_HOST_ALLOWLIST,
                                   max_response_bytes=settings.MAX_DOWNLOAD_BYTES, timeout=timeout,
                                   client=self._client_override, total_timeout=budget)
        return PyPIClient(registry_http=registry, artifact_http=artifacts)

    def close(self) -> None:
        if self._pypi_instance is not None:
            self._pypi_instance.close()

    # ------------------------------------------------------------------ public API
    def build_context(
        self, name: str, version: str | None = None, options: ScanOptions | None = None
    ) -> PackageContext:
        options = options if options is not None else ScanOptions()
        pypi = self.pypi
        release = pypi.resolve(name, version)
        if not release.version_found:
            if release.requested_version is None:
                raise AnalysisError("PyPI registry returned no latest version", code="registry_malformed")
            if settings.FAIL_ON_VERSION_NOT_FOUND:
                raise AnalysisError(
                    f"Version '{release.requested_version}' of '{release.name}' not found on PyPI",
                    code="version_not_found", status_code=404,
                )
            log.warning("version_not_found_analysing_latest", package=release.name)

        ctx = PackageContext(
            ecosystem="pypi",
            name=release.name,
            version=release.version or "unknown",
            metadata=pypi.build_metadata(release),
            releases=release.releases,
            options=options,
        )
        ctx.artifacts = pypi.artifacts(release.files)
        chosen = choose_artifact(ctx.artifacts)
        if chosen is None:
            oversized = sum(1 for a in ctx.artifacts if not _within_download_cap(a))
            ctx.context_signals.append(_fetch_failed(
                "No sdist or wheel is available to analyse within download limits",
                {"package": release.name, "version": ctx.version, "artifact_count": len(ctx.artifacts),
                 "oversized_artifacts": oversized},
            ))
            return ctx

        data = self._download(pypi, chosen, ctx, fatal=True)
        if data is None:
            return ctx
        ctx.analyzed_artifact = chosen
        result = self._reader.read(data, chosen.filename)
        ctx.files, ctx.inventory, ctx.binaries = result.files, result.inventory, result.binaries
        if result.aborted:
            ctx.context_signals.append(_extraction_aborted(chosen, result))
        if chosen.packagetype == "sdist" and options.analyze_wheels and settings.ANALYZE_WHEELS:
            self._add_wheel_inventory(pypi, ctx, retained_text=sum(len(f.text) for f in result.files))
        return ctx

    # ------------------------------------------------------------------ helpers
    def _download(self, pypi: PyPIClient, artifact: ArtifactInfo, ctx: PackageContext, *, fatal: bool) -> bytes | None:
        try:
            data = pypi.download(artifact)
        except OutboundHTTPError as exc:
            log.warning("artifact_download_failed", artifact=artifact.filename, kind=exc.kind, status=exc.status)
            if not fatal:
                return None
            if exc.kind in _REFUSAL_KINDS:
                ctx.context_signals.append(_fetch_failed(
                    f"Artifact {artifact.filename} was not downloaded ({exc.kind})",
                    {"artifact": artifact.filename, "reason": exc.kind, "declared_size": artifact.size},
                ))
                return None
            raise AnalysisError(f"Artifact download failed ({exc.kind})", code="artifact_unavailable") from exc
        if artifact.hash_verified is False:
            log.warning("artifact_hash_mismatch", artifact=artifact.filename)
            ctx.context_signals.append(_hash_mismatch(artifact))
        return data

    def _add_wheel_inventory(self, pypi: PyPIClient, ctx: PackageContext, *, retained_text: int) -> None:
        wheel = choose_wheel(ctx.artifacts)
        if wheel is None:
            return
        try:
            data = self._download(pypi, wheel, ctx, fatal=False)
            if data is None:
                return
            floor = min(settings.MAX_EXTRACTED_BYTES, WHEEL_MIN_TEXT_BYTES)
            budget = max(settings.MAX_EXTRACTED_BYTES - retained_text, floor)
            result = SafeArchiveReader(max_text_bytes=budget, max_binary_bytes=0).read(data, wheel.filename)
        except Exception as exc:  # wheel inventory is best-effort; never fail the scan
            log.warning("wheel_inventory_failed", artifact=wheel.filename, error_type=type(exc).__name__)
            return
        ctx.wheel_inventory = result.inventory
        ctx.wheel_files = [f for f in result.files if f.relpath.lower().endswith(WHEEL_FILE_SUFFIXES)]
        if result.aborted:
            ctx.context_signals.append(_extraction_aborted(wheel, result))

    # ------------------------------------------------------------------ v1 compatibility shims
    def _compat_extract(self, archive: bytes, filename: str) -> list[SourceFile]:
        result = self._reader.read(archive, filename)
        budget_skipped = any(e.skipped_reason == TEXT_BUDGET_SKIP_REASON for e in result.inventory)
        if result.aborted or budget_skipped:
            reason = result.aborted_reason or TEXT_BUDGET_SKIP_REASON
            raise AnalysisError(f"Archive failed safe-extraction checks ({reason})", code="extraction_aborted")
        return result.files

    def _extract_tar(self, archive: bytes) -> list[SourceFile]:
        return self._compat_extract(archive, "archive.tar")

    def _extract_zip(self, archive: bytes) -> list[SourceFile]:
        return self._compat_extract(archive, "archive.zip")


def _is_unsafe_path(name: str) -> bool:
    """v1 helper: True for member names that escape the extraction root (or start with ``~``)."""
    _, problem = normalize_member_path(name)
    return problem in ABORTING_PATH_PROBLEMS or str(name).replace("\\", "/").startswith("~")


__all__ = ["RegistryFetcher", "choose_artifact", "choose_wheel"]
