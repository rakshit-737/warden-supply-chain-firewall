"""Provenance & trust analyzer: PEP 740 attestations, repository consistency, maintainer transitions, dormancy.

This analyzer provides trust signals about *who published* the analysed release and whether the
published provenance describes the bytes Warden analysed. It never executes package code and treats
every input as attacker-influenced: registry metadata, the Integrity API response and the content of
each attestation are validated structurally and bounded before use.

Attestation state (``evidence["state"]``)
=========================================

* ``verified`` — **reserved; never emitted.** It would require cryptographic verification of the
  attestation signature over the in-toto statement, of the Sigstore certificate (chain and identity
  policy) and of transparency-log inclusion. That verification is *not implemented* in this version.
* ``partially_verified`` — the registry sha256 matches the downloaded bytes (``hash_verified``) *and*
  every examined attestation is a structurally valid PEP 740 attestation whose in-toto subject names the
  analysed distribution file and whose subject sha256 equals the sha256 of the downloaded bytes. The
  subject binding is checked; the signature is not. Emitted as ``PROVENANCE_ATTESTED``.
* ``failed`` — an attestation subject (sha256, or distribution filename compared as parsed filenames, as
  PEP 740 requires) differs from the analysed artifact, or the Integrity API served a provenance document
  for the file that is malformed (not JSON, not a PEP 740 provenance object, wrongly typed fields,
  undecodable statement, missing subject digest, ...). Emitted as ``PROVENANCE_FAILED``. A registry-digest
  mismatch is already reported by the fetcher as ``HASH_MISMATCH``; it is referenced (``related`` and
  ``hash_mismatch_reported``), never re-emitted.
* ``unknown`` — no usable attestation: the Integrity API has no provenance for the file (404); the lookup
  failed (network error, refused or oversized response, error status — a lookup failure is never
  reported as ``failed``); lookups are switched off (offline scan, ``INTEL_OFFLINE``,
  ``PROVENANCE_ENABLED=false`` or the scan's ``provenance`` option); no artifact was analysed; the
  document or its attestations use a well-typed format version Warden does not support (document or
  attestation ``version`` other than 1, in-toto Statement other than v1 — a format change is not evidence of
  tampering, and a 404 would read ``unknown`` anyway) or exceed Warden's examination bounds; or an
  attestation binds the downloaded bytes but the registry digest is missing or disagrees with them.
  Emitted as ``PROVENANCE_UNVERIFIED``; ``evidence["reason"]`` says which case applies.

Exactly one of those three findings is emitted per scan, so the pipeline's provenance summary always has
a decisive finding.

Other findings
==============

* ``REPO_MISMATCH`` — a GitHub/GitLab publisher repository from a structurally valid provenance document
  matches none of the source repositories the project declares in ``project_urls`` / ``home_page``
  (github.com and gitlab.com URLs normalised: scheme, ``www.``, case, ``.git``, sub-pages, scp-style
  SSH). No declared forge repository → no finding. Different owner: high, weight 6, confidence 0.7.
  Same owner with another repository name (renames and sibling release repositories are common), or the
  same path on the other forge (mirrors): medium, weight 3, confidence 0.5.
* ``DORMANT_REVIVAL`` — the gap to the previous release exceeds ``DORMANCY_THRESHOLD_DAYS`` and the
  analysed release is under 30 days old. Uses the Warden-derived ``_days_since_previous_release`` and
  ``_age_days`` metadata, so it works offline. Mature libraries also release after long pauses: medium,
  weight 4, confidence 0.5.
* ``MAINTAINER_CHANGED`` — network only. The analysed release's identity metadata is compared with the
  previous release's (``pypi_client.PyPIClient.previous_release_metadata``). Names and e-mail addresses are parsed
  from ``author`` / ``maintainer`` / ``*_email`` (display names inside e-mail fields count, so a PEP 621
  migration that moves a name into ``author_email`` is not a change); placeholders such as ``UNKNOWN``
  are ignored; names match when equal or when their distinctive words overlap (``Python Packaging
  Authority`` ~ ``The Python Packaging Authority``). Complete replacement corroborated by e-mail addresses
  (no shared address, name or organisation domain) or disjoint ownership users: high, weight 5,
  confidence 0.6. Weaker transitions — only names to compare, a name kept but every address moved to another
  domain, or everything replaced inside one organisation e-mail domain: medium, weight 2, confidence 0.4.
  Additions, partial overlaps and releases lacking comparable identity data produce no finding (no request is
  made when the analysed release has no identity data). E-mail addresses appear in evidence only masked
  (``j***@example.org``).

Every finding carries ``evidence["provenance_summary"]`` = ``{state, hash_verified, attestation_present,
publisher, checked_at}``. ``attestation_present`` is ``True`` when the Integrity API served a provenance
document for the analysed file, ``False`` on 404 and ``None`` when not known; ``checked_at`` is the UTC
time (whole seconds) of the Integrity API lookup, ``None`` when none was attempted. Because it is part of
the evidence, finding ids of network-checked scans include that time.

Limitations
===========

* No cryptographic verification (see ``verified`` above); a forged document served over a compromised
  channel with a matching subject digest would read as ``partially_verified``.
* Only the analysed artifact (normally the sdist) is checked, not every wheel of the release.
* PyPI's ``ownership`` roles describe the project *now*, so an ownership change between releases is only
  visible if the metadata passed in carries historical roles.
* Maintainer comparison is heuristic: registry identity fields are self-declared by the publisher.

Work is bounded: at most 2 HTTP requests per scan (Integrity API + previous release JSON) through
:class:`~app.core.http.SafeHttpClient` with a short total budget; at most ``MAX_BUNDLES`` bundles and
``MAX_ATTESTATIONS`` attestations are examined, statements over ``MAX_STATEMENT_CHARS`` are skipped, and
URLs / identity fields / ownership lists are cut to fixed sizes. Findings carry no source location
(they describe the release, not a file).
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import math
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit

from packaging.utils import InvalidSdistFilename, InvalidWheelFilename, parse_sdist_filename, parse_wheel_filename
from packaging.version import InvalidVersion

# Imported as a module, not by name: the analyzer package and the acquisition package import
# each other, so binding names at import time breaks whichever module is imported first.
from app.analysis.acquisition import pypi as pypi_client
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, ScanOptions, ToolStatus
from app.analysis.findings import Category, Finding, Provenance, Severity
from app.analysis.signals import Code
from app.core.config import settings
from app.core.errors import AnalysisError
from app.core.http import SafeHttpClient

ANALYZER_VERSION = "1.0.0"
# Analyzer name the orchestrator stamps onto fetcher context signals (app.analysis.orchestrator.
# FETCH_STAGE_NAME; not imported to avoid an import cycle, pinned by a test).
FETCH_STAGE_NAME = "acquisition"

INTOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
PYPI_PUBLISH_PREDICATE_V1 = "https://docs.pypi.org/attestations/publish/v1"
SLSA_PROVENANCE_PREDICATE_V1 = "https://slsa.dev/provenance/v1"
KNOWN_PREDICATE_TYPES = frozenset({PYPI_PUBLISH_PREDICATE_V1, SLSA_PROVENANCE_PREDICATE_V1})

# --- work bounds (the whole provenance document is capped by pypi_client.PyPIClient at MAX_PROVENANCE_BYTES) ---
MAX_BUNDLES = 8
MAX_ATTESTATIONS_PER_BUNDLE = 8
MAX_ATTESTATIONS = 16
MAX_STATEMENT_CHARS = 64 * 1024  # base64 text of one in-toto statement (real ones are < 1 KiB)
MAX_SUBJECT_NAME_CHARS = 255
MAX_PUBLISHER_FIELD_CHARS = 200
MAX_EVIDENCE_ITEMS = 5
MAX_DECLARED_URLS = 64
MAX_URL_CHARS = 2000
MAX_GITLAB_PATH_SEGMENTS = 20
MAX_IDENTITY_FIELD_CHARS = 2000
MAX_IDENTITIES = 20
MAX_OWNERSHIP_ROLES = 50
RECENT_RELEASE_DAYS = 30.0

# --- finding grades: (severity, weight, confidence) ---
ATTESTED_GRADE = (Severity.info, 0.0, 0.9)
UNVERIFIED_GRADE = (Severity.info, 0.0, 1.0)
FAILED_GRADE = (Severity.critical, 10.0, 0.9)
REPO_MISMATCH_STRONG = (Severity.high, 6.0, 0.7)
REPO_MISMATCH_WEAK = (Severity.medium, 3.0, 0.5)
MAINTAINER_CHANGED_STRONG = (Severity.high, 5.0, 0.6)
MAINTAINER_CHANGED_WEAK = (Severity.medium, 2.0, 0.4)
DORMANT_REVIVAL_GRADE = (Severity.medium, 4.0, 0.5)


class ProvenanceState:
    """Attestation states reported in ``evidence["state"]`` (semantics in the module docstring)."""

    # Reserved for cryptographic verification of signature + Sigstore certificate: NOT implemented, never emitted.
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    UNKNOWN = "unknown"
    FAILED = "failed"
    EMITTED = frozenset({PARTIALLY_VERIFIED, UNKNOWN, FAILED})


class _Malformed(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Unexaminable(Exception):
    """An attestation Warden cannot examine: a format version it does not support, or over a work bound."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _UnsupportedDocument(_Unexaminable):
    """A provenance document whose (well-typed) format version Warden does not support."""


_SHA256_HEX_RE = re.compile(r"[0-9A-Fa-f]{64}")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _non_empty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _number(value: object) -> float | None:
    """A finite, non-negative real number, else ``None`` (booleans and strings are rejected)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    out = float(value)
    return out if math.isfinite(out) and out >= 0 else None


def _compact(mapping: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in mapping.items() if v is not None}


# =============================================================================== attestations
@dataclass(frozen=True)
class PublisherIdentity:
    """Trusted Publisher identity as served by the Integrity API (``attestation_bundles[].publisher``)."""

    kind: str
    repository: str | None = None
    workflow: str | None = None
    environment: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {"kind": self.kind, "repository": self.repository, "workflow": self.workflow,
                "environment": self.environment}


def _optional_str(value: object, reason: str, *, strict: bool) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        if strict:
            raise _Malformed(reason)
        return None
    return value.strip()[:MAX_PUBLISHER_FIELD_CHARS] or None


def _parse_publisher(raw: object) -> PublisherIdentity:
    if not isinstance(raw, Mapping):
        raise _Malformed("publisher_not_object")
    kind = raw.get("kind")
    if not _non_empty_str(kind) or len(kind) > 64:
        raise _Malformed("publisher_kind_invalid")
    kind = kind.strip()
    # Field types are only enforced for the GitHub / GitLab publisher models Warden compares; PEP 740 lets
    # other publisher kinds carry arbitrary extra fields, which must not turn into a FAILED verdict.
    strict = kind.lower() in _PUBLISHER_FORGES
    # GitHub publishers carry ``workflow``; GitLab publishers ``workflow_filepath``.
    workflow_key = "workflow" if "workflow" in raw else "workflow_filepath"
    return PublisherIdentity(
        kind=kind,
        repository=_optional_str(raw.get("repository"), "publisher_repository_invalid", strict=strict),
        workflow=_optional_str(raw.get(workflow_key), "publisher_workflow_invalid", strict=strict),
        environment=_optional_str(raw.get("environment"), "publisher_environment_invalid", strict=strict),
    )


@dataclass
class _ParsedDocument:
    bundles: list[tuple[PublisherIdentity, list[Any]]]
    bundles_not_examined: int
    attestations_not_examined: int


def _parse_document(document: object) -> _ParsedDocument:
    if not isinstance(document, Mapping):
        raise _Malformed("document_not_object")
    version = document.get("version")
    if not _is_int(version):
        raise _Malformed("document_version_invalid")
    if version != 1:
        raise _UnsupportedDocument("document_version_unsupported")
    bundles = document.get("attestation_bundles")
    if not isinstance(bundles, list):
        raise _Malformed("attestation_bundles_not_list")
    if not bundles:
        raise _Malformed("no_attestation_bundles")
    parsed: list[tuple[PublisherIdentity, list[Any]]] = []
    kept_total = declared_total = skipped = 0
    for bundle in bundles[:MAX_BUNDLES]:
        if not isinstance(bundle, Mapping):
            raise _Malformed("bundle_not_object")
        publisher = _parse_publisher(bundle.get("publisher"))
        attestations = bundle.get("attestations")
        if not isinstance(attestations, list):
            raise _Malformed("attestations_not_list")
        kept = attestations[:max(0, min(MAX_ATTESTATIONS_PER_BUNDLE, MAX_ATTESTATIONS - kept_total))]
        kept_total += len(kept)
        declared_total += len(attestations)
        skipped += len(attestations) - len(kept)
        parsed.append((publisher, kept))
    bundles_skipped = max(0, len(bundles) - MAX_BUNDLES)
    if declared_total == 0 and not bundles_skipped:
        raise _Malformed("no_attestations")
    return _ParsedDocument(parsed, bundles_skipped, skipped)


def _decode_statement(encoded: str) -> Mapping[str, Any]:
    compact = "".join(encoded.split())
    raw: bytes | None = None
    urlsafe = (compact + "=" * (-len(compact) % 4)).replace("-", "+").replace("_", "/")
    for candidate in (compact, urlsafe):
        try:
            raw = base64.b64decode(candidate, validate=True)
            break
        except (binascii.Error, ValueError):
            continue
    if raw is None:
        raise _Malformed("statement_not_base64")
    try:
        statement = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _Malformed("statement_not_json") from None
    if not isinstance(statement, Mapping):
        raise _Malformed("statement_not_object")
    return statement


def _parse_attestation(attestation: object) -> tuple[str, str, str]:
    """``(subject name, lower-case subject sha256, predicateType)`` of one PEP 740 attestation."""
    if not isinstance(attestation, Mapping):
        raise _Malformed("attestation_not_object")
    version = attestation.get("version")
    if not _is_int(version):
        raise _Malformed("attestation_version_invalid")
    if version != 1:
        raise _Unexaminable("attestation_version_unsupported")
    material = attestation.get("verification_material")
    if not isinstance(material, Mapping):
        raise _Malformed("verification_material_missing")
    if not _non_empty_str(material.get("certificate")):
        raise _Malformed("certificate_missing")
    entries = material.get("transparency_entries")
    if not isinstance(entries, list) or not entries:
        raise _Malformed("transparency_entries_missing")
    envelope = attestation.get("envelope")
    if not isinstance(envelope, Mapping):
        raise _Malformed("envelope_missing")
    if not _non_empty_str(envelope.get("signature")):
        raise _Malformed("signature_missing")
    encoded = envelope.get("statement")
    if not _non_empty_str(encoded):
        raise _Malformed("statement_missing")
    if len(encoded) > MAX_STATEMENT_CHARS:
        raise _Unexaminable("statement_too_large")
    statement = _decode_statement(encoded)
    statement_type = statement.get("_type")
    if not _non_empty_str(statement_type):
        raise _Malformed("statement_type_missing")
    if statement_type != INTOTO_STATEMENT_V1:
        raise _Unexaminable("statement_type_unsupported")
    predicate_type = statement.get("predicateType")
    if not _non_empty_str(predicate_type):
        raise _Malformed("predicate_type_missing")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:  # PEP 740: exactly one subject
        raise _Malformed("subject_count_invalid")
    subject = subjects[0]
    if not isinstance(subject, Mapping):
        raise _Malformed("subject_not_object")
    name = subject.get("name")
    if not _non_empty_str(name) or len(name) > MAX_SUBJECT_NAME_CHARS:
        raise _Malformed("subject_name_invalid")
    digest = subject.get("digest")
    sha256 = digest.get("sha256") if isinstance(digest, Mapping) else None
    if not isinstance(sha256, str) or not _SHA256_HEX_RE.fullmatch(sha256):
        raise _Malformed("subject_sha256_invalid")
    return name, sha256.lower(), predicate_type[:200]


def _distribution_identity(filename: str) -> tuple | None:
    if len(filename) > MAX_SUBJECT_NAME_CHARS:
        return None
    try:
        if filename.lower().endswith(".whl"):
            name, version, build, tags = parse_wheel_filename(filename)
            return ("wheel", name, version, build, tags)
        name, version = parse_sdist_filename(filename)
        return ("sdist", name, version, ".zip" if filename.lower().endswith(".zip") else ".tar.gz")
    except (InvalidSdistFilename, InvalidWheelFilename, InvalidVersion, ValueError):
        return None


def same_distribution(subject_name: str, filename: str) -> bool:
    """True when an attestation subject name denotes the distribution file ``filename``.

    Names are compared as parsed distribution filenames (normalised project name, version, and wheel
    build/tags), like pypa's reference implementation; unparseable names must match case-insensitively.
    """
    if subject_name == filename:
        return True
    left, right = _distribution_identity(subject_name), _distribution_identity(filename)
    if left is not None and right is not None:
        return left == right
    return subject_name.casefold() == filename.casefold()


@dataclass
class AttestationAssessment:
    """Result of checking a provenance document against the analysed artifact."""

    state: str
    reason: str
    publishers: list[PublisherIdentity] = field(default_factory=list)
    malformed_reason: str | None = None
    examined: int = 0
    bound: int = 0
    mismatched: int = 0
    not_examinable: int = 0
    not_examinable_reasons: list[str] = field(default_factory=list)
    not_examined: int = 0
    bundles_not_examined: int = 0
    predicate_types: list[str] = field(default_factory=list)
    mismatch: dict[str, Any] | None = None

    @property
    def structurally_valid(self) -> bool:
        return self.malformed_reason is None

    def evidence(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "verification": "subject_binding_only",
            "signature_verified": False,
            "malformed_reason": self.malformed_reason,
            "publishers": [p.to_dict() for p in self.publishers[:MAX_EVIDENCE_ITEMS]] or None,
        }
        if self.structurally_valid:
            out.update({
                "attestations_examined": self.examined,
                "attestations_bound": self.bound,
                "attestations_mismatched": self.mismatched,
                "attestations_not_examinable": self.not_examinable or None,
                "not_examinable_reasons": sorted(self.not_examinable_reasons) or None,
                "attestations_not_examined": self.not_examined or None,
                "bundles_not_examined": self.bundles_not_examined or None,
                "predicate_types": self.predicate_types or None,
                "unrecognised_predicate_types": sorted(set(self.predicate_types) - KNOWN_PREDICATE_TYPES) or None,
                "mismatch": self.mismatch,
            })
        return _compact(out)


def assess_attestations(
    document: object,
    *,
    filename: str,
    downloaded_sha256: str | None,
    hash_verified: bool | None,
) -> AttestationAssessment:
    """Check a (hostile) Integrity API provenance document against the analysed artifact.

    Pure and deterministic. See the module docstring for the state rules; the attestation signature is
    never verified.
    """
    try:
        parsed = _parse_document(document)
    except _UnsupportedDocument as exc:
        # A newer, well-typed format is not evidence of tampering (a 404 would read UNKNOWN too).
        return AttestationAssessment(ProvenanceState.UNKNOWN, "unsupported_format",
                                     not_examinable_reasons=[exc.reason])
    except _Malformed as exc:
        return AttestationAssessment(ProvenanceState.FAILED, "malformed_document", malformed_reason=exc.reason)

    publishers: list[PublisherIdentity] = []
    for publisher, _ in parsed.bundles:
        if publisher not in publishers:
            publishers.append(publisher)
    out = AttestationAssessment(
        ProvenanceState.UNKNOWN, "", publishers=publishers,
        not_examined=parsed.attestations_not_examined, bundles_not_examined=parsed.bundles_not_examined,
    )
    downloaded = downloaded_sha256.lower() if (
        isinstance(downloaded_sha256, str) and _SHA256_HEX_RE.fullmatch(downloaded_sha256)) else None
    predicate_types: set[str] = set()
    for _, attestations in parsed.bundles:
        for attestation in attestations:
            try:
                subject_name, subject_sha256, predicate_type = _parse_attestation(attestation)
            except _Unexaminable as exc:
                out.not_examinable += 1
                if exc.reason not in out.not_examinable_reasons:
                    out.not_examinable_reasons.append(exc.reason)
                continue
            except _Malformed as exc:
                return AttestationAssessment(ProvenanceState.FAILED, "malformed_document", publishers=publishers,
                                             malformed_reason=exc.reason)
            out.examined += 1
            predicate_types.add(predicate_type)
            if downloaded is None:
                continue
            name_matches = same_distribution(subject_name, filename)
            digest_matches = hmac.compare_digest(subject_sha256, downloaded)
            if name_matches and digest_matches:
                out.bound += 1
                continue
            out.mismatched += 1
            if out.mismatch is None:
                out.mismatch = {
                    "subject_name": subject_name,
                    "name_matches": name_matches,
                    "digest_matches": digest_matches,
                    "subject_digest_prefix": subject_sha256[:12],
                    "artifact_digest_prefix": downloaded[:12],
                }
    out.predicate_types = sorted(predicate_types)[:MAX_EVIDENCE_ITEMS]

    if out.mismatched:
        out.state, out.reason = ProvenanceState.FAILED, "subject_mismatch"
    elif out.examined == 0:
        out.reason = "attestation_not_examinable"
    elif downloaded is None:
        out.reason = "artifact_digest_unavailable"
    elif hash_verified is True:
        out.state, out.reason = ProvenanceState.PARTIALLY_VERIFIED, "subject_digest_bound"
    elif hash_verified is False:
        out.reason = "registry_digest_mismatch"
    else:
        out.reason = "registry_digest_unavailable"
    return out


# =============================================================================== repositories
_FORGE_HOSTS = {"github.com": "github", "www.github.com": "github", "gitlab.com": "gitlab", "www.gitlab.com": "gitlab"}
_PUBLISHER_FORGES = {"github": "github", "gitlab": "gitlab"}
_REPO_URL_SCHEMES = frozenset({"http", "https", "ssh", "git"})
_SEGMENT_RE = re.compile(r"[A-Za-z0-9_.\-]{1,100}")
_SCP_RE = re.compile(r"(?:[A-Za-z0-9_.\-]{1,64}@)?((?:www\.)?(?:github|gitlab)\.com):(.*)", re.IGNORECASE)
# First path segments of github.com / gitlab.com URLs that are site pages, not repository owners.
_GITHUB_RESERVED = frozenset({
    "about", "advisories", "apps", "codespaces", "collections", "customer-stories", "enterprise", "events",
    "explore", "features", "issues", "join", "login", "marketplace", "new", "notifications", "organizations",
    "orgs", "pricing", "pulls", "search", "security", "settings", "site", "sponsors", "topics", "trending",
    "users",
})
_GITLAB_RESERVED = frozenset({"dashboard", "explore", "groups", "help", "projects", "search", "users"})


@dataclass(frozen=True)
class DeclaredRepository:
    forge: str  # github | gitlab
    path: str  # lower-case owner/repo (GitLab: full namespace path)
    source: str  # metadata key the URL came from

    def to_dict(self) -> dict[str, str]:
        return {"forge": self.forge, "repository": self.path, "source": self.source}


def _valid_segment(segment: str) -> bool:
    return bool(_SEGMENT_RE.fullmatch(segment)) and segment not in {".", ".."}


def _strip_repo_suffix(segment: str) -> str:
    segment = segment.split("@", 1)[0]  # pip VCS URLs: repo.git@v1.0
    return segment[:-4] if segment.lower().endswith(".git") else segment


def _forge_path(forge: str, path: str) -> tuple[str, str] | None:
    segments = [unquote(s) for s in path.split("/") if s]
    if forge == "github":
        if len(segments) < 2 or segments[0].lower() in _GITHUB_RESERVED:
            return None
        chosen = [segments[0], _strip_repo_suffix(segments[1])]
    else:
        if "-" in segments:  # GitLab sub-pages: /group/project/-/tree/main
            segments = segments[:segments.index("-")]
        if not 2 <= len(segments) <= MAX_GITLAB_PATH_SEGMENTS or segments[0].lower() in _GITLAB_RESERVED:
            return None
        chosen = [*segments[:-1], _strip_repo_suffix(segments[-1])]
    if not all(_valid_segment(s) for s in chosen):
        return None
    return forge, "/".join(chosen).lower()


def normalise_repository_url(url: object) -> tuple[str, str] | None:
    """``(forge, lower-case repository path)`` for a github.com / gitlab.com repository URL, else ``None``.

    Accepts http(s)/ssh/git URLs, ``git+`` VCS prefixes, scp-style ``git@github.com:owner/repo.git`` and
    scheme-less ``github.com/owner/repo``; ignores ``www.``, case, ``.git``, query, fragment and sub-pages.
    Site pages (``github.com/sponsors/...``), user pages, other hosts (including ``*.github.io``) and
    anything with unexpected characters yield ``None``.
    """
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text or len(text) > MAX_URL_CHARS:
        return None
    if text[:4].lower() == "git+":
        text = text[4:]
    if "://" not in text:
        scp = _SCP_RE.fullmatch(text)
        if scp:
            forge = _FORGE_HOSTS.get(scp.group(1).lower())
            return _forge_path(forge, scp.group(2)) if forge else None
        text = "https://" + text
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return None
    forge = _FORGE_HOSTS.get(host)
    if forge is None or parts.scheme.lower() not in _REPO_URL_SCHEMES:
        return None
    return _forge_path(forge, parts.path)


def publisher_repository(publisher: PublisherIdentity) -> tuple[str, str] | None:
    """``(forge, lower-case path)`` of a GitHub/GitLab publisher's repository claim, else ``None``."""
    forge = _PUBLISHER_FORGES.get(publisher.kind.lower())
    repository = publisher.repository
    if forge is None or not repository:
        return None
    segments = repository.split("/")
    if "://" in repository or segments[0].lower() in _FORGE_HOSTS:
        normalised = normalise_repository_url(repository)
        return normalised if normalised is not None and normalised[0] == forge else None
    low, high = (2, 2) if forge == "github" else (2, MAX_GITLAB_PATH_SEGMENTS)
    if not low <= len(segments) <= high or not all(_valid_segment(s) for s in segments):
        return None
    return forge, "/".join(segments).lower()


def declared_repositories(metadata: Mapping[str, Any]) -> list[DeclaredRepository]:
    """Forge repositories the project declares in ``home_page`` / ``project_urls`` (de-duplicated, sorted)."""
    candidates: list[tuple[str, object]] = [("home_page", metadata.get("home_page"))]
    urls = metadata.get("project_urls")
    if isinstance(urls, Mapping):
        for key, value in list(urls.items())[:MAX_DECLARED_URLS]:
            if isinstance(key, str):
                candidates.append((f"project_urls.{key[:60]}", value))
    found: dict[tuple[str, str], str] = {}
    for source, url in candidates:
        normalised = normalise_repository_url(url)
        if normalised is not None and normalised not in found:
            found[normalised] = source
    return [DeclaredRepository(forge, path, found[(forge, path)]) for forge, path in sorted(found)]


def compare_repository(publisher_repo: tuple[str, str], declared: list[DeclaredRepository]) -> str | None:
    """``None`` when consistent (or nothing declared); otherwise the mismatch tier.

    Tiers: ``unrelated`` (strong), ``same_owner`` / ``same_path_other_forge`` (weak).
    """
    if not declared:
        return None
    forge, path = publisher_repo
    for repo in declared:
        # Legacy GitLab URLs without "/-/" may append routes (group/project/issues): prefix match.
        if repo.forge == forge and (repo.path == path or (forge == "gitlab" and repo.path.startswith(path + "/"))):
            return None
    owner = path.split("/", 1)[0]
    for repo in declared:
        if repo.forge == forge and repo.path.split("/", 1)[0] == owner:
            return "same_owner"
    for repo in declared:
        if repo.forge != forge and repo.path == path:
            return "same_path_other_forge"
    return "unrelated"


# =============================================================================== maintainers
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){1,8}")
_NAME_SPLIT_RE = re.compile(r"\s*(?:,|;|&|\band\b)\s*", re.IGNORECASE)
_PLACEHOLDER_NAMES = frozenset({"", "unknown", "none", "null", "n/a", "na", "-", "tbd", "todo", "author",
                                "maintainer", "your name"})
_NAME_TOKEN_RE = re.compile(r"[^\W_]+")
# Words that say nothing about *which* person or organisation a name denotes.
_GENERIC_NAME_TOKENS = frozenset({
    "the", "and", "of", "for", "team", "dev", "devs", "developer", "developers", "contributor", "contributors",
    "author", "authors", "maintainer", "maintainers", "project", "projects", "community", "group", "org",
    "inc", "llc", "ltd", "gmbh", "corp", "co", "foundation", "software", "labs", "lab", "open", "source",
})
MAX_NAME_TOKENS = 16
# Shared-mailbox providers: two addresses there say nothing about belonging to the same organisation.
_FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "protonmail.com", "proton.me", "pm.me", "tutanota.com",
    "fastmail.com", "zoho.com", "hey.com", "gmx.com", "gmx.de", "gmx.net", "web.de", "mail.ru", "yandex.ru",
    "yandex.com", "qq.com", "163.com", "126.com", "foxmail.com", "naver.com", "users.noreply.github.com",
    "noreply.github.com", "users.noreply.gitlab.com",
})


@dataclass(frozen=True)
class Identities:
    names: frozenset[str]
    emails: frozenset[str]
    owners: frozenset[str]

    @property
    def empty(self) -> bool:
        return not (self.names or self.emails)


def _bounded_field(value: object) -> str:
    return value[:MAX_IDENTITY_FIELD_CHARS] if isinstance(value, str) else ""


def extract_identities(metadata: Mapping[str, Any]) -> Identities:
    """Normalised names, e-mail addresses and ownership users from (hostile) registry metadata."""
    names: set[str] = set()
    emails: set[str] = set()
    for key in ("author", "author_email", "maintainer", "maintainer_email"):
        value = _bounded_field(metadata.get(key))
        if not value:
            continue
        emails.update(m.lower() for m in _EMAIL_RE.findall(value)[:MAX_IDENTITIES])
        remainder = _EMAIL_RE.sub(" ", value).replace("<", " ").replace(">", " ")
        for part in _NAME_SPLIT_RE.split(remainder)[:MAX_IDENTITIES]:
            name = " ".join(part.strip(" \t\"'()").split()).casefold()[:200]
            if name not in _PLACEHOLDER_NAMES and any(ch.isalnum() for ch in name):
                names.add(name)
    owners: set[str] = set()
    ownership = metadata.get("ownership")
    roles = ownership.get("roles") if isinstance(ownership, Mapping) else None
    if isinstance(roles, list):
        for role in roles[:MAX_OWNERSHIP_ROLES]:
            user = role.get("user") if isinstance(role, Mapping) else None
            if _non_empty_str(user):
                owners.add(user.strip()[:100].casefold())
    return Identities(
        names=frozenset(sorted(names)[:MAX_IDENTITIES]),
        emails=frozenset(sorted(emails)[:MAX_IDENTITIES]),
        owners=frozenset(sorted(owners)[:MAX_OWNERSHIP_ROLES]),
    )


def _name_tokens(name: str) -> frozenset[str]:
    tokens = _NAME_TOKEN_RE.findall(name)[:MAX_NAME_TOKENS]
    return frozenset(t for t in tokens if len(t) >= 2 and t not in _GENERIC_NAME_TOKENS)


def names_overlap(previous: frozenset[str], current: frozenset[str]) -> bool:
    """True when some name in ``previous`` plausibly denotes the same person/organisation as one in ``current``.

    Exact (normalised) equality, or distinctive-word overlap: the names share a word of at least 3 characters
    and at least half of their combined distinctive words ("Python Packaging Authority" ~ "The Python Packaging
    Authority", "Jane Doe" ~ "J. Doe"; not "Jane Doe" ~ "Jane Smith"). Inputs are bounded by ``Identities``.
    """
    if previous & current:
        return True
    current_tokens = [_name_tokens(n) for n in sorted(current)]
    for name in sorted(previous):
        left = _name_tokens(name)
        for right in current_tokens:
            shared = left & right
            if shared and any(len(t) >= 3 for t in shared) and 2 * len(shared) >= len(left | right):
                return True
    return False


def shared_organisation_domains(previous: frozenset[str], current: frozenset[str]) -> list[str]:
    """E-mail domains (excluding shared-mailbox providers) used in both releases, sorted."""
    def domains(emails: frozenset[str]) -> set[str]:
        return {e.rpartition("@")[2] for e in emails} - _FREEMAIL_DOMAINS

    return sorted(domains(previous) & domains(current))


@dataclass(frozen=True)
class MaintainerChange:
    # ownership_replaced | identity_replaced (strong); email_replaced | names_replaced | same_domain_replaced (weak)
    tier: str
    previous: Identities
    current: Identities
    shared_domains: tuple[str, ...] = ()


STRONG_MAINTAINER_TIERS = frozenset({"ownership_replaced", "identity_replaced"})


def diff_maintainers(previous: Mapping[str, Any], current: Mapping[str, Any]) -> MaintainerChange | None:
    """The maintainer transition between two releases' metadata, or ``None`` (no change / not comparable).

    * ``ownership_replaced`` — both carry ownership users and none is shared (strong);
    * ``identity_replaced`` — e-mail addresses on both sides, none shared, no overlapping name and no shared
      organisation domain (strong);
    * ``same_domain_replaced`` — as above, but an organisation e-mail domain is shared (weak: rotation inside
      one organisation, which an outside attacker cannot easily obtain an address in);
    * ``names_replaced`` — only names are comparable and none overlaps (weak: free text, no address to
      corroborate);
    * ``email_replaced`` — a name overlaps but every address changed to another domain (weak).

    A shared address, or an overlapping name with a shared organisation domain, is no change. Additions and
    partial overlaps are not changes.
    """
    prev, cur = extract_identities(previous), extract_identities(current)
    if prev.owners and cur.owners and not prev.owners & cur.owners:
        return MaintainerChange("ownership_replaced", prev, cur)
    names_comparable = bool(prev.names and cur.names)
    emails_comparable = bool(prev.emails and cur.emails)
    if not (names_comparable or emails_comparable):
        return None
    if emails_comparable and prev.emails & cur.emails:
        return None
    domains = tuple(shared_organisation_domains(prev.emails, cur.emails)[:MAX_EVIDENCE_ITEMS])
    if names_comparable and names_overlap(prev.names, cur.names):
        return MaintainerChange("email_replaced", prev, cur) if emails_comparable and not domains else None
    if not emails_comparable:
        return MaintainerChange("names_replaced", prev, cur)
    if domains:
        return MaintainerChange("same_domain_replaced", prev, cur, domains)
    return MaintainerChange("identity_replaced", prev, cur)


def identities_comparable(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    prev, cur = extract_identities(previous), extract_identities(current)
    return bool((prev.owners and cur.owners) or (prev.names and cur.names) or (prev.emails and cur.emails))


def mask_email(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}"


# =============================================================================== dormancy
def assess_dormancy(metadata: Mapping[str, Any], threshold_days: object) -> tuple[str, dict[str, Any] | None]:
    """``(status, evidence)``; evidence is set only for status ``revival``.

    Statuses: ``revival``, ``not_dormant`` (gap ≤ threshold), ``not_recent`` (release ≥ 30 days old),
    ``insufficient_data`` and ``disabled`` (threshold not a positive number).
    """
    threshold = _number(threshold_days)
    if threshold is None or threshold <= 0:
        return "disabled", None
    gap = _number(metadata.get("_days_since_previous_release"))
    age = _number(metadata.get("_age_days"))
    if gap is None or age is None:
        return "insufficient_data", None
    if gap <= threshold:
        return "not_dormant", None
    if age >= RECENT_RELEASE_DAYS:
        return "not_recent", None
    previous = metadata.get("_previous_version")
    return "revival", {
        "days_since_previous_release": gap,
        "age_days": age,
        "threshold_days": threshold,
        "recent_release_days": RECENT_RELEASE_DAYS,
        "previous_version": previous[:128] if isinstance(previous, str) else None,
    }


# =============================================================================== analyzer
def lookup_block_reason(options: ScanOptions) -> str | None:
    """Why registry lookups (Integrity API, previous-release metadata) must not be made, or ``None``."""
    if options.offline:
        return "offline scan"
    if settings.INTEL_OFFLINE:
        return "INTEL_OFFLINE=true"
    if not settings.PROVENANCE_ENABLED:
        return "PROVENANCE_ENABLED=false"
    if not options.provenance:
        return "provenance lookups switched off for this scan"
    return None


def default_client() -> pypi_client.PyPIClient:
    """A PyPI client for this analyzer: registry host allowlist, short total budget, and no downloads."""
    budget = max(1.0, min(float(settings.FETCH_TIMEOUT_SECONDS), float(settings.ANALYZER_TIMEOUT_SECONDS) / 3.0))
    registry = SafeHttpClient(
        name="pypi-provenance", allowed_hosts=settings.REGISTRY_HOST_ALLOWLIST,
        max_response_bytes=settings.MAX_METADATA_BYTES, timeout=budget, retries=1, rate_limit_per_second=5.0,
        total_timeout=budget,
    )
    # This analyzer never downloads artifacts: an empty allowlist refuses every artifact request.
    no_downloads = SafeHttpClient(name="pypi-provenance-no-downloads", allowed_hosts=(), max_response_bytes=1,
                                  timeout=budget, retries=0)
    return pypi_client.PyPIClient(registry_http=registry, artifact_http=no_downloads)


def _iso_seconds(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _stamped_id(finding: Finding) -> str:
    """The id a fetcher context signal will have once the orchestrator stamps it."""
    return finding.finding_id if finding.analyzer else replace(finding, analyzer=FETCH_STAGE_NAME).finding_id


_UNKNOWN_MESSAGES = {
    "lookup_disabled": "Attestations were not looked up for {artifact} ({detail}); provenance is unknown",
    "unsupported_ecosystem": "Attestation lookup is implemented for PyPI only; provenance of {artifact} is unknown",
    "no_analyzed_artifact": "No artifact was analysed, so no attestation could be bound; provenance is unknown",
    "no_attestation": "The PyPI Integrity API has no provenance for {artifact}; trust rests on registry metadata only",
    "lookup_error": "Attestation lookup for {artifact} failed ({detail}); provenance is unknown, not failed",
    "invalid_coordinates": "Attestation lookup for {artifact} was skipped ({detail}); provenance is unknown",
    "attestation_not_examinable": "Attestations for {artifact} could not be examined (unsupported format version "
                                  "or over Warden's examination bounds); provenance is unknown",
    "unsupported_format": "The provenance document for {artifact} uses a format version Warden does not support; "
                          "provenance is unknown",
    "artifact_digest_unavailable": "An attestation exists for {artifact} but the analysed bytes have no recorded "
                                   "sha256; provenance is unknown",
    "registry_digest_mismatch": "An attestation binds the downloaded bytes of {artifact}, but they differ from the "
                                "registry digest (see HASH_MISMATCH); provenance is unknown",
    "registry_digest_unavailable": "An attestation binds the downloaded bytes of {artifact}, but the registry "
                                   "published no sha256 to confirm them; provenance is unknown",
}


@dataclass
class _AttestationOutcome:
    state: str
    reason: str
    lookup: pypi_client.ProvenanceLookup | None = None
    assessment: AttestationAssessment | None = None
    detail: str | None = None
    checked_at: str | None = None

    @property
    def attestation_present(self) -> bool | None:
        if self.lookup is None:
            return None
        if self.lookup.status in (pypi_client.LOOKUP_FOUND, pypi_client.LOOKUP_MALFORMED):
            return True
        return False if self.lookup.status == pypi_client.LOOKUP_NOT_FOUND else None

    @property
    def publisher(self) -> dict[str, str | None] | None:
        if self.assessment is None or not self.assessment.publishers:
            return None
        return self.assessment.publishers[0].to_dict()


class ProvenanceAnalyzer(BaseAnalyzer):
    """Designed to provide provenance and publisher-trust signals; see the module docstring."""

    name = "provenance"
    version = ANALYZER_VERSION
    # Runs in offline scans too (dormancy needs no network); lookups are gated in ``analyze``.
    requires_network = False

    def __init__(
        self,
        client: pypi_client.PyPIClient | None = None,
        *,
        client_factory: Callable[[], pypi_client.PyPIClient] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._client = client
        self._client_factory = client_factory or default_client
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()

    @property
    def client(self) -> pypi_client.PyPIClient:
        """The PyPI client, constructed on first use (never at import or construction time)."""
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = self._client_factory()
        return self._client

    def availability(self) -> ToolStatus:
        blocked = lookup_block_reason(ScanOptions())
        if blocked:
            detail = f"metadata checks only; attestation and maintainer lookups off ({blocked})"
        else:
            detail = "PyPI Integrity API attestations (subject binding; signatures not verified), release metadata"
        return ToolStatus(self.name, True, self.version, detail)

    # ------------------------------------------------------------------ entry point
    def analyze(self, ctx: PackageContext) -> list[Finding]:
        metadata = ctx.metadata if isinstance(ctx.metadata, Mapping) else {}
        options = ctx.options if isinstance(ctx.options, ScanOptions) else ScanOptions()
        artifact = ctx.analyzed_artifact
        hash_mismatches = [s for s in (ctx.context_signals or []) if isinstance(s, Finding)
                           and s.code == Code.HASH_MISMATCH]
        hash_verified = artifact.hash_verified if artifact is not None and isinstance(
            artifact.hash_verified, bool) else None
        if hash_mismatches:
            hash_verified = False
        related = tuple(dict.fromkeys(_stamped_id(s) for s in hash_mismatches))
        is_pypi = str(ctx.ecosystem).strip().lower() == "pypi"
        blocked = lookup_block_reason(options)

        outcome = self._attestation(ctx, artifact, hash_verified, is_pypi, blocked)
        summary = {
            "state": outcome.state,
            "hash_verified": hash_verified,
            "attestation_present": outcome.attestation_present,
            "publisher": outcome.publisher,
            "checked_at": outcome.checked_at,
        }
        maintainer_status, maintainer_finding = self._maintainer(ctx, metadata, is_pypi, blocked, summary)
        dormancy_status, dormancy = assess_dormancy(metadata, settings.DORMANCY_THRESHOLD_DAYS)

        findings = [self._attestation_finding(outcome, artifact, summary, related, bool(hash_mismatches),
                                              {"maintainer": maintainer_status, "dormancy": dormancy_status})]
        repo_mismatch = self._repo_mismatch(outcome, metadata, summary)
        if repo_mismatch is not None:
            findings.append(repo_mismatch)
        if maintainer_finding is not None:
            findings.append(maintainer_finding)
        if dormancy is not None:
            findings.append(self._dormancy_finding(dormancy, summary))
        return findings

    # ------------------------------------------------------------------ attestation
    def _attestation(self, ctx: PackageContext, artifact: Any, hash_verified: bool | None, is_pypi: bool,
                     blocked: str | None) -> _AttestationOutcome:
        unknown = ProvenanceState.UNKNOWN
        if not is_pypi:
            return _AttestationOutcome(unknown, "unsupported_ecosystem")
        if blocked:
            return _AttestationOutcome(unknown, "lookup_disabled", detail=blocked)
        if artifact is None:
            return _AttestationOutcome(unknown, "no_analyzed_artifact")
        checked_at = _iso_seconds(self._clock())
        lookup = self.client.provenance_lookup(ctx.name, ctx.version, artifact.filename)
        if lookup.status == pypi_client.LOOKUP_NOT_FOUND:
            return _AttestationOutcome(unknown, "no_attestation", lookup, checked_at=checked_at)
        if lookup.status == pypi_client.LOOKUP_INVALID_INPUT:
            return _AttestationOutcome(unknown, "invalid_coordinates", lookup, detail=lookup.error_kind,
                                       checked_at=checked_at)
        if lookup.status == pypi_client.LOOKUP_MALFORMED:
            assessment = AttestationAssessment(ProvenanceState.FAILED, "malformed_document",
                                               malformed_reason=lookup.error_kind or "malformed")
            return _AttestationOutcome(ProvenanceState.FAILED, "malformed_document", lookup, assessment,
                                       checked_at=checked_at)
        # Lookup errors and anything unexpected read as unknown, never as failed.
        if lookup.status != pypi_client.LOOKUP_FOUND:
            status = f", HTTP {lookup.http_status}" if lookup.http_status else ""
            return _AttestationOutcome(unknown, "lookup_error", lookup,
                                       detail=f"{lookup.error_kind or pypi_client.LOOKUP_ERROR}{status}",
                                       checked_at=checked_at)
        assessment = assess_attestations(lookup.document, filename=artifact.filename,
                                         downloaded_sha256=artifact.downloaded_sha256, hash_verified=hash_verified)
        return _AttestationOutcome(assessment.state, assessment.reason, lookup, assessment, checked_at=checked_at)

    def _attestation_finding(self, outcome: _AttestationOutcome, artifact: Any, summary: dict[str, Any],
                             related: tuple[str, ...], hash_mismatch: bool, checks: dict[str, str]) -> Finding:
        filename = artifact.filename if artifact is not None else None
        lookup = outcome.lookup
        evidence: dict[str, Any] = _compact({
            "state": outcome.state,
            "reason": outcome.reason,
            "artifact": filename,
            "lookup": lookup.status if lookup is not None else "not_attempted",
            "lookup_disabled_reason": outcome.detail if outcome.reason == "lookup_disabled" else None,
            "error_kind": (lookup.error_kind
                           if lookup is not None and lookup.status != pypi_client.LOOKUP_FOUND else None),
            "http_status": lookup.http_status if lookup is not None else None,
            "hash_mismatch_reported": hash_mismatch or None,
        })
        if outcome.assessment is not None:
            evidence.update(outcome.assessment.evidence())
        evidence["checks"] = checks
        evidence["provenance_summary"] = summary
        shown = filename or "the analysed release"

        if outcome.state == ProvenanceState.PARTIALLY_VERIFIED:
            publisher = outcome.publisher or {}
            source = publisher.get("repository") or "no repository claim"
            message = (f"PEP 740 attestation for {shown} from {publisher.get('kind', 'unknown')} publisher "
                       f"({source}) binds the analysed bytes: the in-toto subject sha256 equals the registry-verified "
                       "digest. The attestation signature and Sigstore certificate were not cryptographically verified")
            code, grade = Code.PROVENANCE_ATTESTED, ATTESTED_GRADE
        elif outcome.state == ProvenanceState.FAILED:
            if outcome.reason == "subject_mismatch":
                mismatch = (outcome.assessment.mismatch if outcome.assessment else None) or {}
                what = "sha256 digest" if not mismatch.get("digest_matches") else "distribution filename"
                message = (f"Attestation subject {what} does not match the analysed artifact {shown}; the published "
                           "provenance does not describe these bytes")
            else:
                reason = outcome.assessment.malformed_reason if outcome.assessment else None
                message = (f"The PyPI Integrity API reports provenance for {shown}, but the provenance document is "
                           f"malformed ({reason or 'malformed'})")
            if hash_mismatch:
                message += " (see HASH_MISMATCH)"
            code, grade = Code.PROVENANCE_FAILED, FAILED_GRADE
        else:
            template = _UNKNOWN_MESSAGES.get(outcome.reason, "Provenance of {artifact} is unknown")
            message = template.format(artifact=shown, detail=outcome.detail or "")
            code, grade = Code.PROVENANCE_UNVERIFIED, UNVERIFIED_GRADE
        severity, weight, confidence = grade
        return Finding(code, severity, weight, message, evidence, confidence=confidence,
                       category=Category.PROVENANCE, provenance=Provenance.REGISTRY, related=related)

    # ------------------------------------------------------------------ repository consistency
    def _repo_mismatch(self, outcome: _AttestationOutcome, metadata: Mapping[str, Any],
                       summary: dict[str, Any]) -> Finding | None:
        assessment = outcome.assessment
        if assessment is None or not assessment.structurally_valid or not assessment.publishers:
            return None
        declared = declared_repositories(metadata)
        if not declared:
            return None
        mismatches: list[tuple[int, str, str, str, PublisherIdentity]] = []
        for publisher in assessment.publishers:
            claimed = publisher_repository(publisher)
            tier = compare_repository(claimed, declared) if claimed is not None else None
            if tier is not None:
                rank = 0 if tier == "unrelated" else 1
                mismatches.append((rank, claimed[0], claimed[1], tier, publisher))
        if not mismatches:
            return None
        _, forge, path, tier, publisher = sorted(mismatches, key=lambda m: m[:3])[0]
        severity, weight, confidence = REPO_MISMATCH_STRONG if tier == "unrelated" else REPO_MISMATCH_WEAK
        shown = ", ".join(f"{r.forge}:{r.path}" for r in declared[:3])
        evidence = {
            "tier": tier,
            "publisher_kind": publisher.kind,
            "publisher_repository": f"{forge}:{path}",
            "declared_repositories": [r.to_dict() for r in declared[:MAX_EVIDENCE_ITEMS]],
            "attestation_state": outcome.state,
            "provenance_summary": summary,
        }
        message = (f"Attested publisher repository {forge}:{path} differs from the declared source repository "
                   f"({shown})")
        return Finding(Code.REPO_MISMATCH, severity, weight, message, evidence, confidence=confidence,
                       category=Category.PROVENANCE, provenance=Provenance.REGISTRY)

    # ------------------------------------------------------------------ maintainers
    def _maintainer(self, ctx: PackageContext, metadata: Mapping[str, Any], is_pypi: bool, blocked: str | None,
                    summary: dict[str, Any]) -> tuple[str, Finding | None]:
        if not is_pypi:
            return "unsupported_ecosystem", None
        if blocked:
            return "lookup_disabled", None
        previous_version = metadata.get("_previous_version")
        if not _non_empty_str(previous_version):
            return "no_previous_release", None
        current = extract_identities(metadata)
        if current.empty and not current.owners:  # nothing to compare: skip the request
            return "insufficient_identity", None
        try:
            previous = self.client.previous_release_metadata(ctx.name, previous_version)
        except AnalysisError as exc:
            return f"error:{exc.code}", None
        if previous is None:
            return "previous_release_not_found", None
        change = diff_maintainers(previous, metadata)
        if change is None:
            return ("compared" if identities_comparable(previous, metadata) else "insufficient_identity"), None
        return "changed", self._maintainer_finding(change, previous_version[:128], summary)

    @staticmethod
    def _maintainer_finding(change: MaintainerChange, previous_version: str, summary: dict[str, Any]) -> Finding:
        prev, cur = change.previous, change.current
        strong = change.tier in STRONG_MAINTAINER_TIERS
        severity, weight, confidence = MAINTAINER_CHANGED_STRONG if strong else MAINTAINER_CHANGED_WEAK

        def masked(emails: frozenset[str]) -> list[str]:
            return [mask_email(e) for e in sorted(emails)[:MAX_EVIDENCE_ITEMS]]

        evidence = _compact({
            "tier": change.tier,
            "previous_version": previous_version,
            "previous_names": sorted(prev.names)[:MAX_EVIDENCE_ITEMS],
            "current_names": sorted(cur.names)[:MAX_EVIDENCE_ITEMS],
            "removed_emails": masked(prev.emails - cur.emails),
            "added_emails": masked(cur.emails - prev.emails),
            "removed_owners": sorted(prev.owners - cur.owners)[:MAX_EVIDENCE_ITEMS] or None,
            "added_owners": sorted(cur.owners - prev.owners)[:MAX_EVIDENCE_ITEMS] or None,
            "shared_domains": list(change.shared_domains) or None,
            "provenance_summary": summary,
        })
        described = {
            "ownership_replaced": "All project ownership users differ",
            "identity_replaced": "All author/maintainer names and e-mail addresses differ",
            "same_domain_replaced": "All author/maintainer names and e-mail addresses differ (addresses share an "
                                    "organisation domain)",
            "names_replaced": "All author/maintainer names differ (no e-mail addresses to compare)",
            "email_replaced": "All author/maintainer e-mail addresses differ (names unchanged)",
        }[change.tier]
        message = f"{described} from the previous release {previous_version}"
        return Finding(Code.MAINTAINER_CHANGED, severity, weight, message, evidence, confidence=confidence,
                       category=Category.PROVENANCE, provenance=Provenance.REGISTRY)

    # ------------------------------------------------------------------ dormancy
    @staticmethod
    def _dormancy_finding(dormancy: dict[str, Any], summary: dict[str, Any]) -> Finding:
        severity, weight, confidence = DORMANT_REVIVAL_GRADE
        previous = dormancy.get("previous_version") or "the previous release"
        message = (f"Release published {int(dormancy['age_days'])} day(s) ago after "
                   f"{int(dormancy['days_since_previous_release'])} days without a release (previous: {previous})")
        return Finding(Code.DORMANT_REVIVAL, severity, weight, message, {**dormancy, "provenance_summary": summary},
                       confidence=confidence, category=Category.PROVENANCE, provenance=Provenance.REGISTRY)


__all__ = [
    "ANALYZER_VERSION",
    "AttestationAssessment",
    "DeclaredRepository",
    "Identities",
    "MaintainerChange",
    "ProvenanceAnalyzer",
    "ProvenanceState",
    "PublisherIdentity",
    "assess_attestations",
    "assess_dormancy",
    "compare_repository",
    "declared_repositories",
    "diff_maintainers",
    "extract_identities",
    "mask_email",
    "names_overlap",
    "normalise_repository_url",
    "publisher_repository",
    "same_distribution",
    "shared_organisation_domains",
]
