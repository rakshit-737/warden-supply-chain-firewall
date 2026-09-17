"""Offline analysis of a container image archive (``docker save`` or an OCI image layout tarball).

The archive is read in memory with :class:`~app.analysis.extraction.safe_archive.SafeArchiveReader`
(outer archive and every layer), so the same decompression, path and budget guards apply as for
packages. Nothing is pulled, unpacked to disk or run.

What is reported:

* image facts from the config blob: architecture, OS, configured user, exposed ports, layer count;
* installed packages: Debian (``var/lib/dpkg/status``), Alpine (``lib/apk/db/installed``) and
  Python distributions (``*.dist-info/METADATA``), after applying layer whiteouts;
* ``DOCKERFILE_ROOT_USER`` when the image runs as root, ``DOCKERFILE_SECRET_IN_ENV`` for credential
  values in the configured environment, ``SECRET_DETECTED`` for high-confidence credential formats in
  retained text files, ``CONTAINER_MISCONFIG`` for set-uid / set-gid executables (aggregated);
* ``EXTRACTION_ABORTED`` whenever a layer could not be read completely - the image is then *not*
  fully analysed, and the report says so (``complete`` is false) instead of looking clean.

Secret values never leave this module: findings carry the detector name and the file, never the
matched text.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.analysis.extraction.safe_archive import ExtractionResult, SafeArchiveReader
from app.analysis.findings import Finding, Location, Provenance, Severity
from app.analysis.signals import Code
from app.containers.dockerfile import looks_like_secret
from app.core.redaction import find_secrets, sanitize_text

ANALYZER_NAME = "container-image"
ANALYZER_VERSION = "1.0.0"

MAX_IMAGE_BYTES = 1024 * 1024 * 1024
MAX_LAYER_BYTES = 512 * 1024 * 1024
MAX_LAYERS = 128
MAX_COMPONENTS = 20_000
MAX_SECRET_FINDINGS = 50
MAX_SETUID_LISTED = 25

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIST_INFO_RE = re.compile(r"(?:^|/)(?:site|dist)-packages/([^/]+)\.dist-info/METADATA$")
_ROOT_USERS = frozenset({"", "root", "0", "0:0", "root:root", "root:0", "0:root"})
_DPKG_STATUS = "var/lib/dpkg/status"
_APK_INSTALLED = "lib/apk/db/installed"


@dataclass
class ImageComponent:
    type: str  # deb | apk | pypi
    name: str
    version: str | None
    purl: str | None
    layer: int

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "name": self.name, "version": self.version, "purl": self.purl,
                "layer": self.layer}


@dataclass
class ImageReport:
    image_refs: list[str] = field(default_factory=list)
    config_digest: str | None = None
    architecture: str | None = None
    os: str | None = None
    user: str | None = None
    exposed_ports: list[str] = field(default_factory=list)
    layer_count: int = 0
    components: list[ImageComponent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_refs": self.image_refs,
            "config_digest": self.config_digest,
            "architecture": self.architecture,
            "os": self.os,
            "user": self.user,
            "exposed_ports": self.exposed_ports,
            "layer_count": self.layer_count,
            "complete": self.complete,
            "components": [c.to_dict() for c in self.components],
            "component_counts": _counts(self.components),
            "findings": [f.to_dict() for f in self.findings],
            "warnings": self.warnings[:50],
        }


def _counts(components: list[ImageComponent]) -> dict[str, int]:
    out: dict[str, int] = {}
    for c in components:
        out[c.type] = out.get(c.type, 0) + 1
    return out


def _finding(code: str, severity: Severity, message: str, evidence: dict, file: str | None = None,
             confidence: float = 0.9) -> Finding:
    return Finding(code, severity, 1.0, sanitize_text(message, max_len=300), evidence, confidence=confidence,
                   location=Location(file=file) if file else None, provenance=Provenance.STATIC,
                   ).with_defaults(analyzer=ANALYZER_NAME, analyzer_version=ANALYZER_VERSION)


def _member_bytes(result: ExtractionResult, path: str) -> bytes | None:
    for f in result.files:
        if f.relpath == path and not f.truncated:
            return f.text.encode("utf-8", "surrogateescape")
    return result.binaries.get(path)


def _json_member(result: ExtractionResult, path: str) -> Any:
    raw = _member_bytes(result, path)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _blob_path(digest: str) -> str | None:
    return f"blobs/sha256/{digest.split(':', 1)[1]}" if isinstance(digest, str) and _DIGEST_RE.match(digest) else None


def _locate(outer: ExtractionResult, report: ImageReport) -> tuple[str | None, list[str]]:
    """(config path, ordered layer paths) from a docker-save manifest or an OCI index."""
    manifest = _json_member(outer, "manifest.json")
    if isinstance(manifest, list) and manifest and isinstance(manifest[0], dict):
        entry = manifest[0]
        if len(manifest) > 1:
            report.warnings.append(f"archive holds {len(manifest)} images; only the first was analysed")
        report.image_refs = [sanitize_text(t, max_len=200) for t in (entry.get("RepoTags") or [])[:10]
                             if isinstance(t, str)]
        layers = [p for p in entry.get("Layers") or [] if isinstance(p, str)]
        config = entry.get("Config") if isinstance(entry.get("Config"), str) else None
        return config, layers
    index = _json_member(outer, "index.json")
    if isinstance(index, dict):
        manifests = [m for m in index.get("manifests") or [] if isinstance(m, dict)]
        if manifests:
            ref = (manifests[0].get("annotations") or {}).get("org.opencontainers.image.ref.name")
            if isinstance(ref, str):
                report.image_refs = [sanitize_text(ref, max_len=200)]
            image_manifest = _json_member(outer, _blob_path(manifests[0].get("digest")) or "")
            if isinstance(image_manifest, dict):
                config = _blob_path((image_manifest.get("config") or {}).get("digest"))
                layers = [p for p in (_blob_path(layer.get("digest")) for layer in image_manifest.get("layers") or []
                                      if isinstance(layer, dict)) if p]
                return config, layers
    return None, []


def _parse_dpkg(text: str, layer: int) -> list[ImageComponent]:
    out = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if line[:1].isspace():
                continue
            key, sep, value = line.partition(":")
            if sep:
                fields[key.strip().lower()] = value.strip()
        name, status = fields.get("package"), fields.get("status", "")
        if name and "installed" in status.split():
            version = fields.get("version")
            arch = fields.get("architecture")
            purl = f"pkg:deb/debian/{name}@{version}" + (f"?arch={arch}" if arch else "") if version else None
            out.append(ImageComponent("deb", name, version, purl, layer))
    return out


def _parse_apk(text: str, layer: int) -> list[ImageComponent]:
    out = []
    for block in text.split("\n\n"):
        fields = {line[0]: line[2:].strip() for line in block.splitlines() if len(line) > 2 and line[1] == ":"}
        name = fields.get("P")
        if name:
            version = fields.get("V")
            out.append(ImageComponent("apk", name, version,
                                      f"pkg:apk/alpine/{name}@{version}" if version else None, layer))
    return out


def _parse_metadata(text: str, layer: int) -> ImageComponent | None:
    name = version = None
    for line in text.splitlines():
        if not line.strip():
            break
        key, sep, value = line.partition(":")
        if key.lower() == "name" and sep:
            name = value.strip()
        elif key.lower() == "version" and sep:
            version = value.strip()
    if not name:
        return None
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    return ImageComponent("pypi", name, version, f"pkg:pypi/{normalized}@{version}" if version else None, layer)


class ImageAnalyzer:
    def __init__(self, *, max_layer_bytes: int = MAX_LAYER_BYTES, max_image_bytes: int = MAX_IMAGE_BYTES) -> None:
        self.max_layer_bytes = max_layer_bytes
        self.max_image_bytes = max_image_bytes

    def analyze(self, data: bytes, filename: str = "image.tar") -> ImageReport:
        report = ImageReport()
        if len(data) > self.max_image_bytes:
            report.complete = False
            report.findings.append(_finding(Code.EXTRACTION_ABORTED, Severity.high,
                                            "Image archive exceeds the configured size limit",
                                            {"reason": "image_too_large", "size": len(data)}))
            return report

        outer = SafeArchiveReader(max_binary_file_bytes=self.max_layer_bytes,
                                  max_binary_bytes=self.max_image_bytes,
                                  max_declared_bytes=self.max_image_bytes).read(data, filename, strip_top=False)
        if outer.aborted:
            report.complete = False
            report.findings.append(_finding(Code.EXTRACTION_ABORTED, Severity.high,
                                            "Image archive failed safe-extraction checks",
                                            {"reason": outer.aborted_reason}))
            return report

        config_path, layer_paths = _locate(outer, report)
        if config_path is None or not layer_paths:
            report.complete = False
            report.findings.append(_finding(Code.EXTRACTION_ABORTED, Severity.high,
                                            "Not a docker-save or OCI image archive (no manifest found)",
                                            {"reason": "no_image_manifest"}))
            return report
        if len(layer_paths) > MAX_LAYERS:
            report.warnings.append(f"only the first {MAX_LAYERS} of {len(layer_paths)} layers were analysed")
            report.complete = False
            layer_paths = layer_paths[:MAX_LAYERS]
        report.layer_count = len(layer_paths)

        config = _json_member(outer, config_path)
        if isinstance(config, dict):
            self._apply_config(config, report, config_path)
        else:
            report.complete = False
            report.warnings.append("image config could not be read")

        self._read_layers(outer, layer_paths, report)
        return report

    # ------------------------------------------------------------------ config
    def _apply_config(self, config: dict, report: ImageReport, config_path: str) -> None:
        digest = config_path.rsplit("/", 1)[-1].removesuffix(".json")
        report.config_digest = f"sha256:{digest}" if re.fullmatch(r"[0-9a-f]{64}", digest) else None
        report.architecture = sanitize_text(config.get("architecture") or "", max_len=40) or None
        report.os = sanitize_text(config.get("os") or "", max_len=40) or None
        runtime = config.get("config") if isinstance(config.get("config"), dict) else {}
        user = str(runtime.get("User") or "")
        report.user = sanitize_text(user, max_len=100) or None
        report.exposed_ports = sorted(sanitize_text(p, max_len=20) for p in (runtime.get("ExposedPorts") or {}))[:50]
        if user.strip().lower() in _ROOT_USERS:
            report.findings.append(_finding(Code.DOCKERFILE_ROOT_USER, Severity.medium,
                                            "The image runs as root (no non-root user configured)",
                                            {"user": report.user or "(default: root)"}))
        for item in (runtime.get("Env") or [])[:500]:
            if not isinstance(item, str):
                continue
            key, _, value = item.partition("=")
            if value and looks_like_secret(key, value):
                report.findings.append(_finding(
                    Code.DOCKERFILE_SECRET_IN_ENV, Severity.high,
                    f"The image environment sets {key} to a secret-like value",
                    {"name": sanitize_text(key, max_len=100), "source": "image_config"},
                    confidence=0.9 if find_secrets(value) else 0.7,
                ))

    # ------------------------------------------------------------------ layers
    def _read_layers(self, outer: ExtractionResult, layer_paths: list[str], report: ImageReport) -> None:
        # Path -> (layer index, kind, mode, text or bytes) for the files the analysis uses, after whiteouts.
        live: dict[str, tuple[int, Any]] = {}
        setuid: dict[str, int] = {}
        secret_hits: list[Finding] = []
        reader = SafeArchiveReader(max_declared_bytes=self.max_layer_bytes * 4)
        for index, path in enumerate(layer_paths):
            blob = outer.binaries.get(path)
            if blob is None:
                report.complete = False
                report.findings.append(_finding(Code.EXTRACTION_ABORTED, Severity.high,
                                                "A layer was not available for analysis (missing or over budget)",
                                                {"reason": "layer_not_retained", "layer": index}))
                continue
            layer = reader.read(blob, "layer.tar", strip_top=False)
            if layer.aborted:
                report.complete = False
                report.findings.append(_finding(Code.EXTRACTION_ABORTED, Severity.high,
                                                "A layer failed safe-extraction checks",
                                                {"reason": layer.aborted_reason, "layer": index}))
            skipped = sum(1 for e in layer.inventory if e.skipped_reason and e.kind == "file")
            if skipped:
                report.warnings.append(f"layer {index}: {skipped} file(s) were not read (budget or path limits)")

            for entry in layer.inventory:
                name = entry.relpath.rsplit("/", 1)[-1]
                parent = entry.relpath.rsplit("/", 1)[0] if "/" in entry.relpath else ""
                if name == ".wh..wh..opq":
                    prefix = parent + "/"
                    for key in [k for k in live if k.startswith(prefix)]:
                        del live[key]
                    for key in [k for k in setuid if k.startswith(prefix)]:
                        del setuid[key]
                    continue
                if name.startswith(".wh."):
                    target = (parent + "/" if parent else "") + name[4:]
                    for store in (live, setuid):
                        for key in [k for k in store if k == target or k.startswith(target + "/")]:
                            del store[key]
                    continue
                if entry.kind == "file" and entry.mode is not None and entry.mode & 0o6000 and \
                        entry.mode & 0o111:
                    setuid[entry.relpath] = index
                if entry.relpath in (_DPKG_STATUS, _APK_INSTALLED) or _DIST_INFO_RE.search(entry.relpath):
                    raw = _member_bytes(layer, entry.relpath)
                    if raw is None:
                        report.complete = False
                        report.warnings.append(f"package database {entry.relpath} could not be read")
                    else:
                        live[entry.relpath] = (index, raw.decode("utf-8", "replace"))

            for source in layer.files:
                if len(secret_hits) >= MAX_SECRET_FINDINGS:
                    break
                detectors = sorted({d for d, *_ in find_secrets(source.text)})
                if detectors:
                    secret_hits.append(_finding(
                        Code.SECRET_DETECTED, Severity.high,
                        f"Credential-format value in image file ({', '.join(detectors)})",
                        {"detectors": detectors, "layer": index}, file=sanitize_text(source.relpath, max_len=300),
                        confidence=0.8,
                    ))

        components: list[ImageComponent] = []
        for relpath, (index, text) in sorted(live.items()):
            if relpath == _DPKG_STATUS:
                components.extend(_parse_dpkg(text, index))
            elif relpath == _APK_INSTALLED:
                components.extend(_parse_apk(text, index))
            else:
                component = _parse_metadata(text, index)
                if component:
                    components.append(component)
        components.sort(key=lambda c: (c.type, c.name.lower(), c.version or ""))
        if len(components) > MAX_COMPONENTS:
            report.warnings.append(f"component list truncated to {MAX_COMPONENTS}")
            components = components[:MAX_COMPONENTS]
        report.components = [ImageComponent(c.type, sanitize_text(c.name, max_len=214),
                                             sanitize_text(c.version, max_len=64) if c.version else None,
                                             sanitize_text(c.purl, max_len=400) if c.purl else None, c.layer)
                             for c in components]
        report.findings.extend(secret_hits)
        if setuid:
            listed = sorted(setuid)[:MAX_SETUID_LISTED]
            report.findings.append(_finding(
                Code.CONTAINER_MISCONFIG, Severity.low,
                f"{len(setuid)} set-uid/set-gid executable(s) in the image",
                {"check": "setuid_binaries", "count": len(setuid),
                 "paths": [sanitize_text(p, max_len=200) for p in listed]},
                confidence=0.95,
            ))
