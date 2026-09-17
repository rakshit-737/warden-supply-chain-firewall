"""SPDX 2.3 JSON builder for a :class:`~app.sbom.models.ProjectInventory`.

* ``SPDXID`` values are built only from the SPDX idstring charset (``[A-Za-z0-9.-]``) plus a short
  digest of the component's bom-ref, so hostile names cannot break references or collide.
* ``documentNamespace`` is deterministic: a UUIDv5 over the canonical document content.
* Relationships: the document ``DESCRIBES`` the project package; ``DEPENDS_ON`` follows the
  inventory edges (project -> direct dependencies, and component -> component).
* ``licenseConcluded`` is always ``NOASSERTION`` (Warden does not perform license analysis) and
  ``licenseDeclared`` is ``NOASSERTION`` unless a data source stated a syntactically valid SPDX
  expression. ``downloadLocation`` and ``copyrightText`` are ``NOASSERTION``: nothing is invented.
* Checksums are the distribution-file digests recorded by the manifests; when a package has more
  than one (one per wheel/sdist) the package comment says so.
* Vulnerabilities become ``SECURITY``/``advisory`` external references; Warden risk data becomes
  an ``OTHER`` annotation.
* Inventory strings (names, versions, purls, the namespace slug) are secret-redacted *before* being
  reduced to the SPDX id charset, so stripping characters cannot hide a secret from redaction.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from app.sbom.cyclonedx import (
    advisory_urls,
    canonical_json,
    component_hashes,
    findings_summary,
    format_timestamp,
    osv_url,
    risk_entry,
    spdx_expression,
    text,
    vulnerability_dicts,
)
from app.sbom.models import Component, ProjectInventory

SPDX_VERSION = "SPDX-2.3"
DEFAULT_NAMESPACE_BASE = "https://github.com/rakshit-737/warden-supply-chain-firewall/spdxdocs"
DOCUMENT_ID = "SPDXRef-DOCUMENT"
ROOT_ID = "SPDXRef-Project"
NOASSERTION = "NOASSERTION"
_NAMESPACE_UUID = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/rakshit-737/warden-supply-chain-firewall/spdx")
_CHECKSUM_ALGS = {"sha256": "SHA256", "sha384": "SHA384", "sha512": "SHA512"}
_ID_UNSAFE_RE = re.compile(r"[^A-Za-z0-9.-]+")


def sanitize_id_part(value: str) -> str:
    """Restrict to the SPDX idstring charset ``[A-Za-z0-9.-]``."""
    return _ID_UNSAFE_RE.sub("-", value).strip("-.") or "x"


def build(
    inventory: ProjectInventory,
    *,
    findings_by_ref: Mapping[str, Iterable[object]] | None = None,
    vulns_by_ref: Mapping[str, Iterable[object]] | None = None,
    risk_by_ref: Mapping[str, object] | None = None,
    timestamp: datetime | str | None = None,
    tool_version: str = "2.0.0",
    namespace_base: str = DEFAULT_NAMESPACE_BASE,
) -> dict:
    """Build an SPDX 2.3 JSON document (as a dict) for ``inventory``."""
    created = format_timestamp(timestamp)
    tool = f"Tool: warden-{sanitize_id_part(tool_version)}"
    components: dict[str, Component] = {}
    for c in sorted(inventory.components, key=lambda c: c.bom_ref):
        components.setdefault(c.bom_ref, c)
    ids = _assign_ids(components)
    vulns = vulnerability_dicts(vulns_by_ref, set(components))
    vulns_for: dict[str, list[dict]] = {}
    for record, refs in vulns:
        for ref in refs:
            vulns_for.setdefault(ref, []).append(record)

    root: dict[str, Any] = {
        "SPDXID": ROOT_ID,
        "name": text(inventory.project_name, 200),
        "downloadLocation": NOASSERTION,
        "filesAnalyzed": False,
        "licenseConcluded": NOASSERTION,
        "licenseDeclared": NOASSERTION,
        "copyrightText": NOASSERTION,
        "primaryPackagePurpose": "APPLICATION",
    }
    if inventory.project_version:
        root["versionInfo"] = text(inventory.project_version, 64)
    packages = [root]
    for ref, c in components.items():
        packages.append(_package(c, ids[ref], vulns_for.get(ref, []), (findings_by_ref or {}).get(ref),
                                 (risk_by_ref or {}).get(ref), created, tool))

    relationships = {(DOCUMENT_ID, "DESCRIBES", ROOT_ID)}
    for e in inventory.edges:
        parent = ROOT_ID if e.parent == inventory.root_ref else ids.get(e.parent)
        child = ids.get(e.child)
        if parent and child and parent != child:
            relationships.add((parent, "DEPENDS_ON", child))

    doc: dict[str, Any] = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": DOCUMENT_ID,
        "name": text(f"{inventory.project_name} dependencies", 200),
        "creationInfo": {"created": created, "creators": [tool]},
        "packages": packages,
        "relationships": [
            {"spdxElementId": a, "relationshipType": rel, "relatedSpdxElement": b}
            for a, rel, b in sorted(relationships, key=lambda r: (r[1] != "DESCRIBES", r[0], r[1], r[2]))
        ],
    }
    slug = sanitize_id_part(text(inventory.project_name, 120)).lower()[:60]
    digest = uuid.uuid5(_NAMESPACE_UUID, canonical_json(doc))
    ordered = {"spdxVersion": doc.pop("spdxVersion"), "dataLicense": doc.pop("dataLicense"),
               "SPDXID": doc.pop("SPDXID"), "name": doc.pop("name"),
               "documentNamespace": f"{namespace_base.rstrip('/')}/{slug}-{digest}"}
    ordered.update(doc)
    return ordered


def _assign_ids(components: Mapping[str, Component]) -> dict[str, str]:
    ids: dict[str, str] = {}
    used = {DOCUMENT_ID, ROOT_ID}
    for ref, c in components.items():
        digest = hashlib.sha256(ref.encode("utf-8", "surrogatepass")).hexdigest()
        # Redact first: stripping "_" etc. would otherwise hide a secret from the redaction patterns.
        name_part = sanitize_id_part(text(c.normalized_name, 100))[:100]
        version_part = sanitize_id_part(text(c.version or "unversioned", 64))[:64]
        base = f"SPDXRef-Package-{name_part}-{version_part}"
        width = 8
        candidate = f"{base}-{digest[:width]}"
        while candidate in used and width < len(digest):
            width += 8
            candidate = f"{base}-{digest[:width]}"
        used.add(candidate)
        ids[ref] = candidate
    return ids


def _package(c: Component, spdx_id: str, vulns: list[dict], findings: Iterable[object] | None, risk: object,
             created: str, tool: str) -> dict:
    pkg: dict[str, Any] = {"SPDXID": spdx_id, "name": text(c.name, 214)}
    if c.version:
        pkg["versionInfo"] = text(c.version, 64)
    pkg["downloadLocation"] = NOASSERTION
    pkg["filesAnalyzed"] = False
    hashes = component_hashes(c)
    if hashes:
        pkg["checksums"] = [{"algorithm": _CHECKSUM_ALGS[alg], "checksumValue": digest} for alg, digest in hashes]
    licenses = [lic for lic in c.licenses if isinstance(lic, str) and lic.strip()]
    declared = spdx_expression(licenses[0]) if len(licenses) == 1 else None
    pkg["licenseConcluded"] = NOASSERTION
    pkg["licenseDeclared"] = declared or NOASSERTION
    pkg["copyrightText"] = NOASSERTION
    pkg["primaryPackagePurpose"] = "LIBRARY"

    external: list[dict] = []
    if c.purl:
        external.append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                         "referenceLocator": text(c.purl, 300)})
    for record in vulns:
        sources = [s.lower() for s in record.get("sources", []) if isinstance(s, str)] \
            if isinstance(record.get("sources"), list) else []
        locator = osv_url(record["id"]) if "osv" in sources else next(iter(advisory_urls(record)), None)
        if locator:
            external.append({"referenceCategory": "SECURITY", "referenceType": "advisory",
                             "referenceLocator": locator, "comment": text(record["id"], 100)})
    if external:
        pkg["externalRefs"] = external

    notes = [f"scope={c.scope}", f"direct={'true' if c.direct else 'false'}", f"resolution={c.resolution}"]
    if c.depth is not None:
        notes.append(f"depth={c.depth}")
    if len(hashes) > 1:
        notes.append(f"checksums are {len(hashes)} distribution-file digests recorded by the manifests")
    pkg["comment"] = text("warden: " + "; ".join(notes), 500)

    annotation_parts = []
    risk_values = risk_entry(risk)
    for key in ("risk_score", "decision", "severity"):
        if key in risk_values:
            annotation_parts.append(f"warden:{key}={risk_values[key]}")
    if findings is not None:
        count, worst = findings_summary(findings)
        annotation_parts.append(f"warden:finding_count={count}")
        if worst:
            annotation_parts.append(f"warden:max_finding_severity={worst}")
    if annotation_parts:
        pkg["annotations"] = [{"annotationDate": created, "annotationType": "OTHER", "annotator": tool,
                               "comment": text("; ".join(annotation_parts), 500)}]
    return pkg
