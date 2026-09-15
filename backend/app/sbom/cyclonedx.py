"""CycloneDX 1.6 JSON builder for a :class:`~app.sbom.models.ProjectInventory`.

Output is deterministic for identical inputs and ``timestamp``: components, dependencies and
vulnerabilities are sorted, and ``serialNumber`` is a UUIDv5 over the canonical JSON of the rest
of the document. (CycloneDX recommends a unique serial per BOM; with a fresh timestamp every
generation still gets one, while a reproducible build with a fixed timestamp gets the same one.)

Honesty rules:

* Hashes are only the digests recorded by lock files / ``--hash`` options; licenses only what a
  data source stated. Nothing is inferred or invented.
* ``dependencies`` lists every component. Whether an empty ``dependsOn`` means "no dependencies"
  or "not known" is stated in ``compositions`` (``complete`` for components whose dependencies
  came from a lock file or the resolver, ``unknown`` otherwise).
* Warden-specific data (risk score, decision, depth, direct) travels as ``warden:*`` properties.
* Every string taken from the inventory is sanitised: control characters escaped, secret patterns
  redacted, bom-refs kept unique. Redaction can only recognise a secret in the form it is given;
  the manifest parsers refuse credential-like names and versions before they are normalised.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from app.analysis.findings import Severity
from app.core.redaction import sanitize_text
from app.sbom.models import Component, ProjectInventory

SPEC_VERSION = "1.6"
SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"
TOOL_NAME = "Warden X"
_SERIAL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/rakshit-737/warden-supply-chain-firewall/cyclonedx")

_SCOPE_MAP = {"required": "required", "optional": "optional", "dev": "excluded"}
_HASH_ALGS = {"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
_HEX_LENGTHS = {"sha256": 64, "sha384": 96, "sha512": 128}
_RATING_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "none", "unknown"})
_LICENSE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_CWE_RE = re.compile(r"^(?:CWE-)?(\d{1,6})$", re.IGNORECASE)
_MAX_DECLARED_PROPS = 20
_MAX_ADVISORIES = 50


# ======================================================================================
# Shared helpers (also used by the SPDX builder)
# ======================================================================================
def format_timestamp(value: datetime | str | None = None) -> str:
    """UTC ISO-8601 timestamp with second precision (``2026-09-15T12:00:00Z``)."""
    if value is None:
        dt = datetime.now(UTC)
    elif isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    else:
        raise TypeError("timestamp must be a datetime, an ISO-8601 string or None")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def optional_timestamp(value: object) -> str | None:
    if not isinstance(value, (str, datetime)):
        return None
    try:
        return format_timestamp(value)
    except (ValueError, TypeError):
        return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def text(value: object, max_len: int = 300) -> str:
    return sanitize_text(value, max_len=max_len)


def spdx_expression(value: object) -> str | None:
    """Return ``value`` when it is syntactically an SPDX license expression over license ids.

    Only a syntax check (ids, ``AND``/``OR``/``WITH``, balanced parentheses). ``LicenseRef-`` /
    ``DocumentRef-`` references are rejected because the documents carry no extracted texts.
    """
    if not isinstance(value, str):
        return None
    s = " ".join(value.split())
    if not s or len(s) > 200:
        return None
    depth, expect_operand = 0, True
    for token in re.findall(r"\(|\)|[^\s()]+", s):
        # bandit B105 false positives (here and below): SPDX-expression parenthesis tokens, not credentials.
        if token == "(":  # nosec B105
            if not expect_operand:
                return None
            depth += 1
        elif token == ")":  # nosec B105
            if expect_operand or depth == 0:
                return None
            depth -= 1
        elif token in ("AND", "OR", "WITH"):
            if expect_operand:
                return None
            expect_operand = True
        else:
            if not expect_operand or not _LICENSE_ID_RE.match(token) or token.startswith(("LicenseRef-",
                                                                                        "DocumentRef-")):
                return None
            expect_operand = False
    return s if not expect_operand and depth == 0 else None


def safe_refs(refs: Iterable[str]) -> dict[str, str]:
    """Map every inventory reference to a display-safe, unique output reference.

    References built by the parsers are purls and pass through unchanged. A hostile reference
    (control characters, secret-looking text) is sanitised; if that makes it collide with another
    reference, a digest of the original is appended so references stay unique and deterministic.
    """
    ordered = sorted(set(refs))
    out: dict[str, str] = {}
    used: set[str] = set()
    for ref in ordered:
        if text(ref, 300) == ref and ref not in used:
            out[ref] = ref
            used.add(ref)
    for ref in ordered:
        if ref in out:
            continue
        safe = text(ref, 280)
        if safe in used:
            safe = f"{safe}#{hashlib.sha256(ref.encode('utf-8', 'surrogatepass')).hexdigest()[:16]}"
        out[ref] = safe
        used.add(safe)
    return out


def component_hashes(component: Component) -> list[tuple[str, str]]:
    """``(algorithm, hex)`` pairs recorded for a component, validated and sorted."""
    tokens = set(component.file_hashes)
    for alg, digest in component.hashes.items():
        tokens.add(f"{alg.lower()}:{digest}")
    out = set()
    for token in tokens:
        alg, _, digest = str(token).partition(":")
        alg = alg.lower()
        if _HEX_LENGTHS.get(alg) == len(digest) and re.fullmatch(r"[0-9a-fA-F]+", digest):
            out.add((alg, digest.lower()))
    return sorted(out)


def risk_entry(value: object) -> dict[str, object]:
    """Normalise a ``risk_by_ref`` value (number, mapping, or object with attributes)."""
    out: dict[str, object] = {}
    if isinstance(value, bool) or value is None:
        return out
    if isinstance(value, (int, float)):
        score, decision, severity = value, None, None
    elif isinstance(value, Mapping):
        score = next((value[k] for k in ("risk_score", "final_score", "score") if k in value), None)
        decision, severity = value.get("decision"), value.get("severity")
    else:
        score = getattr(value, "risk_score", None)
        decision, severity = getattr(value, "decision", None), getattr(value, "severity", None)
    if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score):
        out["risk_score"] = int(round(min(100.0, max(0.0, float(score)))))
    if isinstance(decision, str) and decision.strip():
        out["decision"] = text(decision, 40)
    if isinstance(severity, str) and severity.strip():
        out["severity"] = text(severity, 20)
    return out


def findings_summary(items: Iterable[object] | None) -> tuple[int, str | None]:
    count, best = 0, None
    for item in items or ():
        raw = item.get("severity") if isinstance(item, Mapping) else getattr(item, "severity", None)
        count += 1
        try:
            severity = Severity.coerce(raw)
        except (ValueError, TypeError):
            continue
        if best is None or severity.rank > best.rank:
            best = severity
    return count, best.value if best else None


# Record fields that intelligence derives from the *queried package's* own affected[] entry.
PACKAGE_SPECIFIC_VULNERABILITY_FIELDS = (
    "severity", "cvss_score", "cvss_vector", "cvss_version", "fixed_versions", "affected_ranges",
    "database_specific_severity",
)


def vulnerability_dicts(vulns_by_ref: Mapping[str, Iterable[object]] | None,
                        known_refs: set[str]) -> list[tuple[dict, list[str]]]:
    """Group vulnerability records across components: ``[(record, sorted affected refs)]``.

    Records are grouped by id *and* by their package-specific data (ratings, fixed versions,
    affected ranges). One advisory that covers several packages with different data therefore
    yields one entry per variant, so no component is shown another package's severity or fix.
    """
    grouped: dict[tuple[str, str], tuple[dict, set[str]]] = {}
    for ref in sorted(vulns_by_ref or {}):
        if ref not in known_refs:
            continue
        for item in vulns_by_ref[ref] or ():
            data = item.to_dict() if hasattr(item, "to_dict") else item
            if not isinstance(data, Mapping):
                continue
            vid = data.get("id")
            if not isinstance(vid, str) or not vid.strip() or data.get("withdrawn"):
                continue
            vid = text(vid.strip(), 100)
            variant = canonical_json({key: data.get(key) for key in PACKAGE_SPECIFIC_VULNERABILITY_FIELDS})
            entry = grouped.setdefault((vid, variant), (dict(data), set()))
            entry[1].add(ref)
    return [(grouped[k][0] | {"id": k[0]}, sorted(grouped[k][1])) for k in sorted(grouped)]


def advisory_urls(record: Mapping) -> list[str]:
    urls: list[str] = []
    refs = record.get("references")
    for ref in refs if isinstance(refs, list) else []:
        url = ref.get("url") if isinstance(ref, Mapping) else ref
        if isinstance(url, str) and url.startswith(("https://", "http://")) and " " not in url and len(url) <= 2000:
            if url not in urls:
                urls.append(url)
        if len(urls) >= _MAX_ADVISORIES:
            break
    return urls


def osv_url(vuln_id: str) -> str:
    return f"https://osv.dev/vulnerability/{quote(vuln_id, safe='')}"


def _sources(record: Mapping) -> list[str]:
    sources = record.get("sources")
    return [s.lower() for s in sources if isinstance(s, str)] if isinstance(sources, list) else []


# ======================================================================================
# Builder
# ======================================================================================
def build(
    inventory: ProjectInventory,
    *,
    findings_by_ref: Mapping[str, Iterable[object]] | None = None,
    vulns_by_ref: Mapping[str, Iterable[object]] | None = None,
    risk_by_ref: Mapping[str, object] | None = None,
    timestamp: datetime | str | None = None,
    tool_version: str = "2.0.0",
) -> dict:
    """Build a CycloneDX 1.6 JSON document (as a dict) for ``inventory``."""
    components: dict[str, Component] = {}
    for c in sorted(inventory.components, key=lambda c: c.bom_ref):
        components.setdefault(c.bom_ref, c)
    root_ref = inventory.root_ref or "warden:project"
    if root_ref in components:
        root_ref = f"{root_ref}#project"
    refs = safe_refs([*components, root_ref])

    metadata_component: dict[str, Any] = {"type": "application", "bom-ref": refs[root_ref],
                                          "name": text(inventory.project_name, 200)}
    if inventory.project_version:
        metadata_component["version"] = text(inventory.project_version, 64)
    metadata: dict[str, Any] = {
        "timestamp": format_timestamp(timestamp),
        "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": text(tool_version, 40)}]},
        "component": metadata_component,
    }
    manifest_props = [
        {"name": "warden:manifest",
         "value": text(f"{m.get('file')} ({m.get('type')}){' sha256:' + m['sha256'] if m.get('sha256') else ''}")}
        for m in inventory.manifests
    ]
    if manifest_props:
        metadata["properties"] = manifest_props

    doc: dict[str, Any] = {
        "$schema": SCHEMA_URL,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": metadata,
        "components": [
            _component(c, refs[ref], (findings_by_ref or {}).get(ref), (risk_by_ref or {}).get(ref))
            for ref, c in components.items()
        ],
        "dependencies": _dependencies(inventory, components, root_ref, refs),
    }
    compositions = _compositions(inventory, components, root_ref, refs)
    if compositions:
        doc["compositions"] = compositions
    vulnerabilities = [_vulnerability(record, [refs[ref] for ref in affected])
                       for record, affected in vulnerability_dicts(vulns_by_ref, set(components))]
    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities

    serial = uuid.uuid5(_SERIAL_NAMESPACE, canonical_json(doc))
    ordered: dict[str, Any] = {}
    for key in ("$schema", "bomFormat", "specVersion"):
        ordered[key] = doc.pop(key)
    ordered["serialNumber"] = f"urn:uuid:{serial}"
    ordered.update(doc)
    return ordered


def _component(c: Component, ref: str, findings: Iterable[object] | None, risk: object) -> dict:
    entry: dict[str, Any] = {"type": "library", "bom-ref": ref, "name": text(c.name, 214)}
    if c.version:
        entry["version"] = text(c.version, 64)
    entry["scope"] = _SCOPE_MAP.get(c.scope, "required")
    hashes = component_hashes(c)
    if hashes:
        entry["hashes"] = [{"alg": _HASH_ALGS[alg], "content": digest} for alg, digest in hashes]
    licenses = [lic for lic in c.licenses if isinstance(lic, str) and lic.strip()]
    if len(licenses) == 1 and spdx_expression(licenses[0]):
        entry["licenses"] = [{"expression": spdx_expression(licenses[0])}]
    elif licenses:
        entry["licenses"] = [{"license": {"name": text(lic, 200)}} for lic in sorted(set(licenses))]
    if c.purl:
        entry["purl"] = text(c.purl, 300)

    props: list[tuple[str, str]] = [
        ("warden:direct", "true" if c.direct else "false"),
        ("warden:resolution", text(c.resolution, 20)),
    ]
    if c.depth is not None:
        props.append(("warden:depth", str(c.depth)))
    if c.specifier:
        props.append(("warden:specifier", text(c.specifier, 200)))
    for decl in c.declared_at[:_MAX_DECLARED_PROPS]:
        where = f"{decl.get('file')}:{decl['line']}" if decl.get("line") else f"{decl.get('file')}"
        props.append(("warden:declared_at", text(where, 300)))
    risk_values = risk_entry(risk)
    if "risk_score" in risk_values:
        props.append(("warden:risk_score", str(risk_values["risk_score"])))
    if "decision" in risk_values:
        props.append(("warden:decision", str(risk_values["decision"])))
    if "severity" in risk_values:
        props.append(("warden:severity", str(risk_values["severity"])))
    if findings is not None:
        count, worst = findings_summary(findings)
        props.append(("warden:finding_count", str(count)))
        if worst:
            props.append(("warden:max_finding_severity", worst))
    entry["properties"] = [{"name": name, "value": value} for name, value in props]
    return entry


def _dependencies(inventory: ProjectInventory, components: Mapping[str, Component], root_ref: str,
                  refs: Mapping[str, str]) -> list[dict]:
    children: dict[str, set[str]] = {root_ref: set(), **{ref: set() for ref in components}}
    for e in inventory.edges:
        parent = root_ref if e.parent == inventory.root_ref else e.parent
        if parent in children and e.child in components and e.child != parent:
            children[parent].add(e.child)
    entries = [{"ref": refs[root_ref], "dependsOn": sorted(refs[c] for c in children.pop(root_ref))}]
    entries.extend({"ref": refs[ref], "dependsOn": sorted(refs[c] for c in children[ref])} for ref in sorted(children))
    return entries


def _compositions(inventory: ProjectInventory, components: Mapping[str, Component], root_ref: str,
                  refs: Mapping[str, str]) -> list[dict]:
    known = sorted(refs[ref] for ref, c in components.items() if c.dependencies_known)
    unknown = sorted(refs[ref] for ref, c in components.items() if not c.dependencies_known)
    out = [{"aggregate": "incomplete" if inventory.warnings else "complete", "dependencies": [refs[root_ref]]}]
    if known:
        out.append({"aggregate": "complete", "dependencies": known})
    if unknown:
        out.append({"aggregate": "unknown", "dependencies": unknown})
    return out


def _vulnerability(record: Mapping, refs: list[str]) -> dict:
    vid = record["id"]
    entry: dict[str, Any] = {"id": vid}
    sources = _sources(record)
    source = None
    if "osv" in sources:
        source = {"name": "OSV", "url": osv_url(vid)}
    elif "nvd" in sources and vid.upper().startswith("CVE-"):
        source = {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{quote(vid, safe='')}"}
    if source:
        entry["source"] = source
        aliases = record.get("aliases")
        refs_out = [{"id": text(a, 100), "source": {"name": source["name"], "url": osv_url(a)}}
                    for a in sorted({a for a in aliases if isinstance(a, str) and a.strip() and a != vid})] \
            if isinstance(aliases, list) and source["name"] == "OSV" else []
        if refs_out:
            entry["references"] = refs_out[:_MAX_ADVISORIES]
    rating = _rating(record)
    if rating:
        entry["ratings"] = [rating]
    cwes = _cwes(record)
    if cwes:
        entry["cwes"] = cwes
    summary = record.get("summary") or record.get("details")
    if isinstance(summary, str) and summary.strip():
        entry["description"] = text(summary, 1000)
    advisories = advisory_urls(record)
    if advisories:
        entry["advisories"] = [{"url": url} for url in advisories]
    published, modified = optional_timestamp(record.get("published")), optional_timestamp(record.get("modified"))
    if published:
        entry["published"] = published
    if modified:
        entry["updated"] = modified
    entry["affects"] = [{"ref": ref} for ref in refs]
    props: list[dict] = []
    if isinstance(record.get("kev"), bool):
        props.append({"name": "warden:kev", "value": "true" if record["kev"] else "false"})
    if isinstance(record.get("kev_date_added"), str) and record["kev_date_added"].strip():
        props.append({"name": "warden:kev_date_added", "value": text(record["kev_date_added"], 40)})
    for key, name in (("epss_score", "warden:epss"), ("epss_percentile", "warden:epss_percentile")):
        value = record.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
            props.append({"name": name, "value": f"{float(value):.5f}".rstrip("0").rstrip(".") or "0"})
    fixed = record.get("fixed_versions")
    if isinstance(fixed, list) and fixed:
        props.append({"name": "warden:fixed_versions",
                      "value": text(", ".join(str(v) for v in fixed[:20] if isinstance(v, str)), 300)})
    if props:
        entry["properties"] = props
    return entry


def _rating(record: Mapping) -> dict | None:
    rating: dict[str, Any] = {}
    score = record.get("cvss_score")
    if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score):
        rating["score"] = float(score)
    severity = record.get("severity")
    if isinstance(severity, str):
        sev = severity.strip().lower()
        sev = "medium" if sev == "moderate" else sev
        if sev in _RATING_SEVERITIES and sev != "unknown":
            rating["severity"] = sev
    if not rating:
        return None
    vector = record.get("cvss_vector")
    rating["method"] = score_method(record.get("cvss_version"), vector)
    if isinstance(vector, str) and vector.strip():
        rating["vector"] = text(vector.strip(), 200)
    return rating


def score_method(version: object, vector: object) -> str:
    v = str(version).strip() if version is not None else ""
    vec = vector.strip() if isinstance(vector, str) else ""
    if vec.startswith("CVSS:3.1/") or v == "3.1":
        return "CVSSv31"
    if vec.startswith("CVSS:3.0/") or v in ("3.0", "3"):
        return "CVSSv3"
    if vec.startswith("CVSS:4.0/") or v.startswith("4"):
        return "CVSSv4"
    if v.startswith("2") or ("/Au:" in vec and vec.startswith("AV:")):
        return "CVSSv2"
    return "other"


def _cwes(record: Mapping) -> list[int]:
    raw = record.get("cwes", record.get("cwe_ids", record.get("cwe")))
    values = raw if isinstance(raw, list) else [raw] if raw is not None else []
    out: set[int] = set()
    for value in values:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
            out.add(value)
        elif isinstance(value, str):
            m = _CWE_RE.match(value.strip())
            if m and int(m.group(1)) >= 1:
                out.add(int(m.group(1)))
    return sorted(out)
