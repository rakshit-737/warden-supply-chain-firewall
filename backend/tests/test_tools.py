"""Tests for the external-tool runner and package workspace (app.analysis.tools).

These spawn only the test interpreter itself (``sys.executable``) — never package code and
never a network-facing tool — so they run offline on any host.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.analysis import tools
from app.analysis.analyzers.base import PackageContext, SourceFile
from app.analysis.tools import (
    ToolError,
    ToolNotFoundError,
    ToolResult,
    UnsafePathError,
    build_child_env,
    clear_tool_cache,
    find_tool,
    normalize_relpath,
    package_workspace,
    redact_argv,
    remove_tree,
    run_tool,
)

PY = sys.executable
IS_WINDOWS = os.name == "nt"


def _ctx(files: dict[str, str] | None = None, binaries: dict[str, bytes] | None = None) -> PackageContext:
    return PackageContext(
        ecosystem="pypi", name="pkg", version="1.0",
        files=[SourceFile(relpath=k, text=v, size=len(v)) for k, v in (files or {}).items()],
        binaries=dict(binaries or {}),
    )


# --------------------------------------------------------------------------- path validation
@pytest.mark.parametrize("bad", [
    "../evil.py",
    "pkg/../../evil.py",
    "..\\evil.py",
    "pkg\\..\\..\\evil.py",
    "/etc/passwd",
    "\\Windows\\win.ini",
    "C:\\Windows\\evil.dll",
    "c:evil.py",
    "\\\\server\\share\\x.py",
    "//server/share/x.py",
    "a/\x00b.py",
    "a/b\x1b[31m.py",
    "a/b\n.py",
    "x" * 600,
    "a/" * 40 + "x.py",
    "CON",
    "pkg/nul.txt",
    "pkg/Com1.py",
    "file.py:stream",
    "pkg/evil.",
    "pkg/evil ",
    "~/x.py",
    "a/<b>.py",
    "",
    ".",
    "./",
    "y" * 256 + "/x.py",
])
def test_normalize_relpath_rejects_unsafe_paths(bad):
    with pytest.raises(UnsafePathError):
        normalize_relpath(bad)


def test_normalize_relpath_rejects_non_strings():
    for bad in (None, b"pkg/mod.py", 3):
        with pytest.raises(UnsafePathError):
            normalize_relpath(bad)


def test_normalize_relpath_normalises_separators_and_dots():
    assert normalize_relpath("pkg\\sub/./mod.py") == "pkg/sub/mod.py"
    assert normalize_relpath("pkg//mod.py") == "pkg/mod.py"
    assert normalize_relpath("pkg/..hidden/mod.py") == "pkg/..hidden/mod.py"  # '..hidden' is a name, not traversal


# --------------------------------------------------------------------------- workspace
def test_workspace_materialises_text_and_binaries_then_cleans_up(tmp_path):
    ctx = _ctx({"pkg/mod.py": "print('hi')\n", "setup.py": "x = 1\n"}, {"pkg/lib.so": b"\x7fELF\x00\x01"})
    with package_workspace(ctx, base_dir=tmp_path) as ws:
        root = Path(ws)
        assert root.parent == tmp_path
        assert os.fspath(ws) == str(ws.root) == str(root)
        assert (root / "pkg" / "mod.py").read_text(encoding="utf-8") == "print('hi')\n"
        assert (ws / "pkg/lib.so").read_bytes() == b"\x7fELF\x00\x01"
        assert sorted(ws.files) == ["pkg/lib.so", "pkg/mod.py", "setup.py"]
        assert ws.skipped == []
        assert not any(p.is_symlink() for p in root.rglob("*"))
    assert not root.exists()


def test_workspace_refuses_traversal_and_never_writes_outside(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    ctx = _ctx({
        "../escape.py": "evil",
        "..\\escape2.py": "evil",
        "pkg/../../escape3.py": "evil",
        "/abs.py": "evil",
        "C:\\abs.py": "evil",
        "\\\\srv\\share\\x.py": "evil",
        "ok.py": "fine",
    }, {"../../bin.so": b"evil"})
    with package_workspace(ctx, base_dir=base) as ws:
        assert ws.files == ["ok.py"]
        reasons = {s["reason"] for s in ws.skipped}
        assert {"traversal", "absolute", "drive_letter"} <= reasons
        assert len(ws.skipped) == 7
        for written in tmp_path.rglob("*"):
            if written.is_file():
                assert ws.root in written.parents
    assert not any(p.name.startswith("escape") for p in tmp_path.rglob("*"))
    assert not (tmp_path / "bin.so").exists()


def test_workspace_skips_case_insensitive_duplicates_and_conflicts(tmp_path):
    ctx = _ctx({"Pkg/Mod.py": "first", "pkg/mod.py": "second", "a": "file", "a/b.py": "under-a-file"})
    with package_workspace(ctx, base_dir=tmp_path) as ws:
        assert ws.files == ["Pkg/Mod.py", "a"]
        assert (ws.root / "Pkg" / "Mod.py").read_text(encoding="utf-8") == "first"
        assert sorted(s["reason"] for s in ws.skipped) == ["duplicate", "path_conflict"]


def test_workspace_enforces_byte_budget(tmp_path):
    ctx = _ctx({"small.py": "12345", "big.py": "x" * 50})
    with package_workspace(ctx, base_dir=tmp_path, max_total_bytes=10) as ws:
        assert ws.files == ["small.py"]
        assert ws.skipped == [{"path": "big.py", "reason": "budget_exceeded"}]


def test_workspace_can_exclude_binaries(tmp_path):
    ctx = _ctx({"a.py": "x"}, {"lib.so": b"\x00"})
    with package_workspace(ctx, base_dir=tmp_path, include_binaries=False) as ws:
        assert ws.files == ["a.py"]


def test_workspace_removed_when_body_raises(tmp_path):
    ctx = _ctx({"a.py": "x"})
    with pytest.raises(RuntimeError):
        with package_workspace(ctx, base_dir=tmp_path) as ws:
            root = ws.root
            raise RuntimeError("tool adapter failed")
    assert not root.exists()


def test_workspace_cleanup_handles_read_only_files(tmp_path):
    ctx = _ctx({"pkg/a.py": "x"})
    with package_workspace(ctx, base_dir=tmp_path) as ws:
        target = ws.root / "pkg" / "a.py"
        os.chmod(target, stat.S_IREAD)
        root = ws.root
    assert not root.exists()


@pytest.mark.skipif(IS_WINDOWS, reason="POSIX permission bits")
def test_workspace_permissions_are_owner_only(tmp_path):
    with package_workspace(_ctx({"pkg/a.py": "x"}), base_dir=tmp_path) as ws:
        assert stat.S_IMODE(os.stat(ws.root).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(ws.root / "pkg").st_mode) & 0o077 == 0
        assert stat.S_IMODE(os.stat(ws.root / "pkg" / "a.py").st_mode) & 0o077 == 0


def test_remove_tree_on_missing_path_is_ok(tmp_path):
    assert remove_tree(tmp_path / "does-not-exist") is True


# --------------------------------------------------------------------------- run_tool
def test_run_tool_captures_output_and_exit_code():
    result = run_tool([PY, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"], timeout=60)
    assert result.returncode == 3
    assert result.stdout.strip() == "out"
    assert result.stderr.strip() == "err"
    assert not result.timed_out and not result.truncated and not result.ok
    assert result.duration_ms >= 0


def test_run_tool_never_uses_a_shell(tmp_path):
    marker = tmp_path / "pwned"
    hostile = f"x; echo pwned > {marker} && echo pwned > {marker} | echo & echo pwned > {marker}"
    result = run_tool([PY, "-c", "import sys; print(sys.argv[1])", hostile], timeout=60)
    assert result.returncode == 0
    assert result.stdout.strip() == hostile  # delivered verbatim as one argument
    assert not marker.exists()


def test_run_tool_timeout_kills_sleeping_child():
    start = time.monotonic()
    result = run_tool([PY, "-c", "import time; time.sleep(120)"], timeout=1)
    elapsed = time.monotonic() - start
    assert result.timed_out is True
    assert result.returncode is not None  # the process was reaped, not abandoned
    assert elapsed < 30


def _process_alive(pid: int) -> bool:
    if IS_WINDOWS:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) != 0  # WAIT_OBJECT_0 == exited
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_run_tool_timeout_kills_the_whole_process_tree(tmp_path):
    pid_file = tmp_path / "grandchild.pid"
    grandchild = (
        "import os, time, pathlib; "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(120)"
    )
    child = (
        "import subprocess, sys, time, pathlib; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
        f"p = pathlib.Path({str(pid_file)!r}); "
        "deadline = time.time() + 20\n"
        "while not p.exists() and time.time() < deadline: time.sleep(0.05)\n"
        "print('ready', flush=True); time.sleep(120)"
    )
    result = run_tool([PY, "-c", child], timeout=10)
    assert result.timed_out is True
    assert pid_file.exists(), "grandchild never started"
    pid = int(pid_file.read_text())
    deadline = time.monotonic() + 15
    while _process_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    alive = _process_alive(pid)
    if alive:  # do not leak a process from the test run, then fail
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, check=False)
        else:
            os.kill(pid, 9)
    assert not alive, "grandchild survived the timeout kill"


def test_run_tool_caps_output_and_marks_truncation():
    code = "import sys; sys.stdout.write('A' * 2_000_000); sys.stdout.flush(); sys.stderr.write('B' * 10)"
    result = run_tool([PY, "-c", code], timeout=60, max_output_bytes=1024)
    assert result.returncode == 0
    assert result.truncated is True
    assert result.stdout == "A" * 1024
    assert result.stderr == "B" * 10


def test_run_tool_scrubs_secrets_from_child_environment(monkeypatch):
    secrets = {
        "AWS_SECRET_ACCESS_KEY": "fake-aws-secret-value-123",
        "GITHUB_TOKEN": "fake-github-token-value-456",
        "WARDEN_API_TOKEN": "fake-warden-token-789",
        "DATABASE_URL": "postgresql://user:fake-db-password@db/warden",
        "SECRET_KEY": "fake-app-secret-key",
    }
    for key, value in secrets.items():
        monkeypatch.setenv(key, value)
    result = run_tool(
        [PY, "-c", "import json, os; print(json.dumps(dict(os.environ)))"],
        timeout=60, extra_env={"WARDEN_TOOL_MODE": "scan"},
    )
    assert result.returncode == 0, result.stderr
    env = {k.upper(): v for k, v in json.loads(result.stdout).items()}
    for key, value in secrets.items():
        assert key not in env
        assert value not in result.stdout
    assert env["WARDEN_TOOL_MODE"] == "scan"
    assert "PATH" in env


def test_build_child_env_is_an_allowlist(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake")
    monkeypatch.setenv("SOME_RANDOM_VAR", "x")
    env = build_child_env()
    assert set(env) <= set(tools._ENV_ALLOWLIST)
    for bad in ({"BAD KEY": "x"}, {"OK": "nul\x00byte"}, {"OK": 1}, {"1BAD": "x"}):
        with pytest.raises(ValueError):
            build_child_env(bad)


@pytest.mark.parametrize("argv", ["python -c 1", b"python", [], [PY, 1], [PY, "a\x00b"], ["  "]])
def test_run_tool_rejects_invalid_argv(argv):
    with pytest.raises(ValueError):
        run_tool(argv, timeout=5)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_run_tool_rejects_invalid_timeout(timeout):
    with pytest.raises(ValueError):
        run_tool([PY, "-c", "pass"], timeout=timeout)


def test_run_tool_rejects_missing_cwd(tmp_path):
    with pytest.raises(ValueError):
        run_tool([PY, "-c", "pass"], timeout=5, cwd=tmp_path / "missing")


def test_run_tool_missing_executable_raises():
    with pytest.raises(ToolNotFoundError):
        run_tool(["warden-definitely-missing-tool-xyz"], timeout=5)


def test_run_tool_refuses_executable_planted_in_cwd(tmp_path):
    planted = tmp_path / ("semgrep.exe" if IS_WINDOWS else "semgrep")
    planted.write_bytes(b"#!/bin/sh\necho planted\n")
    planted.chmod(0o755)
    with pytest.raises(ToolError):
        run_tool([str(planted), "--version"], timeout=5, cwd=tmp_path)


@pytest.mark.skipif(not IS_WINDOWS, reason="batch-file argument injection is Windows-specific")
def test_run_tool_refuses_batch_files(tmp_path):
    bat = tmp_path / "tool.bat"
    bat.write_text("@echo off\r\necho hi\r\n")
    with pytest.raises(ToolError):
        run_tool([str(bat)], timeout=5)


def test_redact_argv_masks_credentials():
    token = "ghp_" + "a" * 36
    argv = ["semgrep", "--token", "s3cr3t-value", "--api-key=abc123xyz", "--config", "p/python", token,
            "--password"]
    redacted = redact_argv(argv)
    joined = " ".join(redacted)
    assert redacted[:4] == ["semgrep", "--token", "[REDACTED]", "--api-key=[REDACTED]"]
    assert redacted[4:6] == ["--config", "p/python"]
    assert "s3cr3t-value" not in joined and "abc123xyz" not in joined and token not in joined
    assert redacted[-1] == "--password"


# --------------------------------------------------------------------------- find_tool
def test_find_tool_probes_version_once_and_caches(monkeypatch):
    clear_tool_cache()
    calls: list = []
    real = tools.run_tool

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(tools, "run_tool", counting)
    try:
        first = find_tool(PY)
        second = find_tool(PY)
        assert first.available is True
        assert first.version == ".".join(str(p) for p in sys.version_info[:3])
        assert second is first
        assert len(calls) == 1
    finally:
        clear_tool_cache()


def test_find_tool_reports_missing_binary():
    clear_tool_cache()
    status = find_tool("warden-definitely-missing-tool-xyz")
    assert status.available is False
    assert status.detail == "not found on PATH"
    assert status.version is None


def test_find_tool_hanging_probe_is_unavailable(monkeypatch):
    clear_tool_cache()
    monkeypatch.setattr(tools, "run_tool", lambda *a, **k: ToolResult(None, "", "", True, 10_000, False))
    try:
        status = find_tool(PY, version_args=("--hang",))
        assert status.available is False
        assert status.detail == "version probe timed out"
    finally:
        clear_tool_cache()
