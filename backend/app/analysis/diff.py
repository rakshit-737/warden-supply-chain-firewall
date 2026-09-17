"""Release-to-release differential analysis.

Compares two analysed releases of the same package and reports what changed in behaviour, not in
text: risk and per-dimension scores, capabilities, findings, the file inventory, and the declared
maintainers. The comparison works on :class:`~app.analysis.orchestrator.AnalysisResult` values (or
their ``asdict`` form), so both releases go through the full analysis pipeline first and no package
code is ever executed.

Findings are matched by ``(code, file)`` rather than by finding id: an id includes evidence such as
line numbers that legitimately move between releases, while a new *kind* of behaviour in a file is
exactly what a reviewer needs to see.

The result is advisory. ``verdict`` is ``escalated`` when the newer release is materially riskier
(a higher severity band, a new high or critical finding, a new capability, a new executable binary,
a changed install-time file or a maintainer change), ``reduced`` when its score dropped by at least
:data:`SCORE_CHANGE_THRESHOLD` with nothing new, and ``unchanged`` otherwise. A file comparison
that is not possible (one side has no inventory, e.g. a result cached by an older Warden) is
reported as unavailable rather than as "no changes".
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from app.core.redaction import sanitize_text

SCORE_CHANGE_THRESHOLD = 10
MAX_LISTED = 200

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Files that run or shape what runs at install / import time.
_INSTALL_TIME_NAMES = frozenset({"setup.py", "setup.cfg", "pyproject.toml", "__init__.py", "conftest.py"})
_INSTALL_TIME_SUFFIXES = (".pth",)


def _as_dict(result: Any) -> dict[str, Any]:
    if is_dataclass(result) and not isinstance(result, type):
        return asdict(result)
    if isinstance(result, dict):
        return result
    raise TypeError("expected an AnalysisResult or its dict form")


def is_install_time_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    if name.endswith(_INSTALL_TIME_SUFFIXES):
        return True
    depth = path.count("/")
    if name == "__init__.py":
        # A top-level package initialiser (``pkg/__init__.py``) runs on a plain ``import``.
        return depth == 1
    return name in _INSTALL_TIME_NAMES and depth == 0


def _finding_key(signal: dict) -> tuple[str, str]:
    location = signal.get("location") or {}
    return str(signal.get("code") or ""), str(location.get("file") or "")


def _finding_view(signal: dict) -> dict[str, Any]:
    location = signal.get("location") or {}
    return {
        "code": signal.get("code"),
        "severity": signal.get("severity"),
        "file": location.get("file"),
        "line": location.get("line"),
        "message": sanitize_text(signal.get("message") or "", max_len=300),
    }


def _index_findings(signals: list[dict]) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for signal in signals or []:
        key = _finding_key(signal)
        current = out.get(key)
        if current is None or _SEVERITY_RANK.get(signal.get("severity"), 0) > _SEVERITY_RANK.get(
                current.get("severity"), 0):
            out[key] = signal
    return out


def _compare_findings(old: list[dict], new: list[dict]) -> dict[str, Any]:
    before, after = _index_findings(old), _index_findings(new)
    added = [after[k] for k in sorted(after.keys() - before.keys())]
    removed = [before[k] for k in sorted(before.keys() - after.keys())]
    escalated = []
    for key in sorted(after.keys() & before.keys()):
        was, now = before[key].get("severity"), after[key].get("severity")
        if _SEVERITY_RANK.get(now, 0) > _SEVERITY_RANK.get(was, 0):
            escalated.append({**_finding_view(after[key]), "previous_severity": was})
    added.sort(key=lambda s: (-_SEVERITY_RANK.get(s.get("severity"), 0), _finding_key(s)))
    return {
        "added": [_finding_view(s) for s in added[:MAX_LISTED]],
        "removed": [_finding_view(s) for s in removed[:MAX_LISTED]],
        "escalated": escalated[:MAX_LISTED],
        "added_count": len(added),
        "removed_count": len(removed),
    }


def _strip_root(path: str) -> str:
    """Drop the ``name-version/`` directory sdists wrap everything in, so releases line up."""
    head, sep, rest = path.partition("/")
    if sep and "-" in head and any(ch.isdigit() for ch in head):
        return rest
    return path


def _compare_files(old: list[dict], new: list[dict]) -> dict[str, Any]:
    if not old or not new:
        return {"available": False, "reason": "file inventory missing for one release"}
    before = {_strip_root(r["path"]): r for r in old if r.get("kind") == "file"}
    after = {_strip_root(r["path"]): r for r in new if r.get("kind") == "file"}
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    changed = sorted(
        p for p in after.keys() & before.keys()
        if after[p].get("sha256") and before[p].get("sha256") and after[p]["sha256"] != before[p]["sha256"]
    )
    new_binaries = sorted(p for p in added if after[p].get("executable"))
    newly_executable = sorted(
        p for p in after.keys() & before.keys() if after[p].get("executable") and not before[p].get("executable")
    )
    install_time = sorted(p for p in [*added, *changed] if is_install_time_file(p))
    return {
        "available": True,
        "added": added[:MAX_LISTED],
        "removed": removed[:MAX_LISTED],
        "changed": changed[:MAX_LISTED],
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "new_executable_binaries": [*new_binaries, *newly_executable][:MAX_LISTED],
        "install_time_changes": install_time[:MAX_LISTED],
    }


def _maintainer_names(intel: dict) -> set[str] | None:
    info = (intel or {}).get("maintainers") or {}
    names: set[str] = set()
    for key in ("author", "maintainer"):
        if isinstance(info.get(key), str) and info[key].strip():
            names.add(info[key].strip().lower())
    listed = info.get("maintainers")
    if isinstance(listed, list):
        for item in listed:
            value = item.get("username") or item.get("name") if isinstance(item, dict) else item
            if isinstance(value, str) and value.strip():
                names.add(value.strip().lower())
    return names or None


def _compare_dimensions(old: dict, new: dict) -> dict[str, Any]:
    out = {}
    before = (old or {}).get("dimensions") or {}
    after = (new or {}).get("dimensions") or {}
    for name in sorted(set(before) | set(after)):
        was = (before.get(name) or {}).get("score")
        now = (after.get(name) or {}).get("score")
        if was != now:
            delta = now - was if isinstance(was, (int, float)) and isinstance(now, (int, float)) else None
            out[name] = {"from": was, "to": now, "delta": delta}
    return out


def diff_results(old_result: Any, new_result: Any) -> dict[str, Any]:
    old, new = _as_dict(old_result), _as_dict(new_result)
    if (old.get("ecosystem"), old.get("name")) != (new.get("ecosystem"), new.get("name")):
        raise ValueError("a release diff compares two versions of the same package")

    old_score, new_score = int(old.get("risk_score") or 0), int(new.get("risk_score") or 0)
    old_sev, new_sev = old.get("severity") or "low", new.get("severity") or "low"
    capabilities_added = sorted(set(new.get("capabilities") or []) - set(old.get("capabilities") or []))
    capabilities_removed = sorted(set(old.get("capabilities") or []) - set(new.get("capabilities") or []))
    findings = _compare_findings(old.get("signals") or [], new.get("signals") or [])
    files = _compare_files(old.get("file_inventory") or [], new.get("file_inventory") or [])

    old_maint, new_maint = _maintainer_names(old.get("package_intel")), _maintainer_names(new.get("package_intel"))
    maintainers: dict[str, Any] = {"available": old_maint is not None and new_maint is not None}
    if maintainers["available"]:
        maintainers.update(added=sorted(new_maint - old_maint), removed=sorted(old_maint - new_maint))

    reasons: list[str] = []
    if _SEVERITY_RANK.get(new_sev, 0) > _SEVERITY_RANK.get(old_sev, 0):
        reasons.append(f"severity rose from {old_sev} to {new_sev}")
    serious = [f for f in findings["added"] if f["severity"] in ("high", "critical")]
    if serious:
        reasons.append(f"{len(serious)} new high or critical finding(s)")
    if findings["escalated"]:
        reasons.append(f"{len(findings['escalated'])} finding(s) became more severe")
    if capabilities_added:
        reasons.append("new capabilities: " + ", ".join(capabilities_added))
    if files.get("available"):
        if files["new_executable_binaries"]:
            reasons.append(f"{len(files['new_executable_binaries'])} new executable binary file(s)")
        if files["install_time_changes"]:
            reasons.append("install-time files changed: " + ", ".join(files["install_time_changes"][:5]))
    if maintainers.get("added"):
        reasons.append("new maintainer(s) declared")

    if reasons:
        verdict = "escalated"
    elif old_score - new_score >= SCORE_CHANGE_THRESHOLD:
        verdict = "reduced"
    else:
        verdict = "unchanged"

    return {
        "ecosystem": new.get("ecosystem"),
        "name": new.get("name"),
        "from_version": old.get("version"),
        "to_version": new.get("version"),
        "verdict": verdict,
        "reasons": reasons,
        "risk": {
            "from": old_score, "to": new_score, "delta": new_score - old_score,
            "from_severity": old_sev, "to_severity": new_sev,
            "dimensions": _compare_dimensions(old.get("risk") or {}, new.get("risk") or {}),
        },
        "capabilities": {"added": capabilities_added, "removed": capabilities_removed},
        "findings": findings,
        "files": files,
        "maintainers": maintainers,
    }
