"""Release diff engine: behavioural changes between two analysed releases."""

from __future__ import annotations

import json

import pytest

from app.analysis.diff import diff_results, is_install_time_file


def result(version: str, *, score: int = 10, severity: str = "low", capabilities=(), signals=(),
           files=None, maintainers=("alice",), dimensions=None) -> dict:
    return {
        "ecosystem": "pypi",
        "name": "demo",
        "version": version,
        "risk_score": score,
        "severity": severity,
        "capabilities": list(capabilities),
        "signals": list(signals),
        "file_inventory": [] if files is None else [
            {"path": f"demo-{version}/{path}", "size": 1, "sha256": sha, "kind": "file", "executable": exe}
            for path, sha, exe in files
        ],
        "package_intel": {"maintainers": {"author": None, "maintainer": None,
                                          "maintainers": [{"username": m} for m in maintainers]}},
        "risk": {"dimensions": dimensions or {}},
    }


def signal(code: str, severity: str, file: str | None = None, message: str = "seen") -> dict:
    return {"code": code, "severity": severity, "message": message,
            "location": {"file": file, "line": 3} if file else None}


BASE_FILES = [("setup.py", "a1", False), ("demo/__init__.py", "b1", False), ("demo/core.py", "c1", False)]


def test_identical_releases_are_unchanged():
    diff = diff_results(result("1.0", files=BASE_FILES), result("1.1", files=BASE_FILES))
    assert diff["verdict"] == "unchanged" and diff["reasons"] == []
    assert diff["files"]["available"] and diff["files"]["changed"] == []
    assert diff["from_version"] == "1.0" and diff["to_version"] == "1.1"


def test_new_install_hook_and_network_capability_escalate():
    old = result("1.0", files=BASE_FILES)
    new = result("1.1", score=72, severity="high", capabilities=["network"],
                 signals=[signal("INSTALL_HOOK_EXEC", "critical", "setup.py")],
                 files=[("setup.py", "a2", False), *BASE_FILES[1:]])
    diff = diff_results(old, new)
    assert diff["verdict"] == "escalated"
    assert diff["capabilities"]["added"] == ["network"]
    assert diff["findings"]["added"][0]["code"] == "INSTALL_HOOK_EXEC"
    assert diff["files"]["install_time_changes"] == ["setup.py"]
    assert diff["risk"]["delta"] == 62
    assert any("severity rose" in r for r in diff["reasons"])


def test_moved_lines_do_not_count_as_new_findings():
    old = result("1.0", signals=[signal("NETWORK_EGRESS", "medium", "demo/core.py")])
    moved = signal("NETWORK_EGRESS", "medium", "demo/core.py")
    moved["location"]["line"] = 90
    diff = diff_results(old, result("1.1", signals=[moved]))
    assert diff["findings"]["added"] == [] and diff["verdict"] == "unchanged"


def test_severity_escalation_of_an_existing_finding_is_reported():
    old = result("1.0", signals=[signal("OBFUSCATION", "low", "demo/core.py")])
    new = result("1.1", signals=[signal("OBFUSCATION", "high", "demo/core.py")])
    diff = diff_results(old, new)
    assert diff["findings"]["escalated"][0]["previous_severity"] == "low"
    assert diff["verdict"] == "escalated"


def test_new_executable_binary_escalates():
    new_files = [*BASE_FILES, ("demo/_helper.so", "d1", True)]
    diff = diff_results(result("1.0", files=BASE_FILES), result("1.1", files=new_files))
    assert diff["files"]["new_executable_binaries"] == ["demo/_helper.so"]
    assert diff["verdict"] == "escalated"


def test_maintainer_change_escalates():
    diff = diff_results(result("1.0"), result("1.1", maintainers=("alice", "mallory")))
    assert diff["maintainers"]["added"] == ["mallory"]
    assert diff["verdict"] == "escalated"


def test_missing_inventory_is_unavailable_not_clean():
    diff = diff_results(result("1.0"), result("1.1", files=BASE_FILES))
    assert diff["files"] == {"available": False, "reason": "file inventory missing for one release"}


def test_score_drop_is_reduced():
    diff = diff_results(result("1.0", score=50, severity="medium"), result("1.1", score=20))
    assert diff["verdict"] == "reduced"


def test_dimension_deltas():
    old = result("1.0", dimensions={"behavioral": {"score": 10}, "secret": {"score": 0}})
    new = result("1.1", dimensions={"behavioral": {"score": 40}, "secret": {"score": 0}})
    assert diff_results(old, new)["risk"]["dimensions"] == {"behavioral": {"from": 10, "to": 40, "delta": 30}}


def test_different_packages_are_rejected():
    other = result("1.0")
    other["name"] = "other"
    with pytest.raises(ValueError):
        diff_results(result("1.0"), other)


def test_hostile_messages_are_sanitised():
    token = "gh" + "p_" + "B" * 36
    new = result("1.1", signals=[signal("ENV_HARVEST", "high", "demo/core.py", message="\x1b[31m" + token)])
    text = json.dumps(diff_results(result("1.0"), new))
    assert token not in text and "\\u001b" not in text


@pytest.mark.parametrize(("path", "expected"), [
    ("setup.py", True), ("pyproject.toml", True), ("demo/__init__.py", True), ("evil.pth", True),
    ("demo/sub/__init__.py", False), ("docs/setup.py", False), ("demo/core.py", False),
])
def test_install_time_files(path, expected):
    assert is_install_time_file(path) is expected
