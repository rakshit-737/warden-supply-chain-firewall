"""External analysis-tool discovery and a hardened subprocess runner.

Several Warden analysis layers wrap external programs (semgrep, gitleaks, yara, syft,
grype, trivy). Those programs process attacker-controlled package contents, may be missing
from a host, and may misbehave. This module gives every adapter one audited way to use them.

``find_tool(binary)``
    Locates a binary with ``shutil.which`` and runs a bounded ``--version`` probe. Results
    are cached per process. A missing tool is reported as ``available=False`` — callers turn
    that into a ``TOOL_UNAVAILABLE`` status, never into fake "no findings".

``run_tool(argv, *, timeout, cwd=None, extra_env=None, max_output_bytes=8 MiB)``
    * **No shell.** ``argv`` is a list passed straight to ``subprocess.Popen``; ``argv[0]`` is
      resolved to an absolute path first. Windows batch files are refused because
      ``CreateProcess`` routes them through ``cmd.exe``, whose argument parsing enables
      injection even without ``shell=True``. A binary located inside ``cwd`` (for example a
      materialised package workspace) is refused so a package cannot plant the tool.
    * **Scrubbed environment.** The child receives only an allowlist of non-secret variables
      (PATH, SYSTEMROOT, TEMP/TMP, HOME/USERPROFILE, LANG, …) plus explicit ``extra_env``.
      Credentials in the server environment (``AWS_*``, ``GITHUB_TOKEN``, ``WARDEN_*``,
      database URLs) are never inherited.
    * **Bounded output.** stdout and stderr are drained by separate threads, each keeping at
      most ``max_output_bytes`` and discarding the rest (``truncated=True``), so a noisy or
      hostile tool can neither exhaust memory nor dead-lock on a full pipe.
    * **Hard timeout with process-tree kill.** The child starts in its own session/process
      group (POSIX ``start_new_session`` → ``killpg``; Windows ``CREATE_NEW_PROCESS_GROUP``
      → ``taskkill /T /F`` then ``kill``) so helpers it spawned die with it.
    * **Log hygiene.** Only the redacted argv, return code, duration and flags are logged;
      tool output is never logged.

``package_workspace(ctx)``
    Materialises a package's retained text files and binaries into a fresh private temporary
    directory for tools that need a filesystem. Every relative path is validated (no absolute
    paths, drive letters, UNC paths, ``..``, control characters, reserved device names,
    alternate data streams or over-long paths); files are created exclusively with
    ``O_EXCL``/``O_NOFOLLOW`` and owner-only permissions, and the directory is removed on exit
    even when the body raises. No symlinks are ever created.

These controls reduce risk from misbehaving tools; they are not a sandbox. Tools still run
with the server's user privileges and filesystem access.
"""

from __future__ import annotations

import contextlib
import math
import os
import re
import shutil
import signal
import stat

# bandit B404 reviewed: running optional external tools is this module's purpose; see run_tool's hardening.
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analysis.analyzers.base import ToolStatus
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import redact_text, sanitize_text

log = get_logger("warden.tools")

DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
VERSION_PROBE_TIMEOUT_SECONDS = 10.0
_VERSION_PROBE_MAX_BYTES = 64 * 1024
_READ_CHUNK = 64 * 1024
_KILL_GRACE_SECONDS = 2.0
_IS_WINDOWS = os.name == "nt"

# Non-secret variables a child process may inherit. Allowlist, never a denylist.
_ENV_ALLOWLIST = (
    "PATH", "HOME", "USERPROFILE", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
    "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATHEXT",
)
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SENSITIVE_FLAG_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|auth|credential|cookie)")
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+(?:[-+.][0-9A-Za-z.]+)?")

# Path validation for workspace materialisation.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_INVALID_CHARS = frozenset('<>:"|?*')
_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(10)}
    | {f"LPT{i}" for i in range(10)}
)
_MAX_COMPONENT_LENGTH = 255


class ToolError(RuntimeError):
    """A tool could not be launched. Messages are log-safe (no argv values, no output)."""


class ToolNotFoundError(ToolError):
    pass


class UnsafePathError(ValueError):
    """A package-relative path failed validation. ``reason`` is machine-readable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class ToolResult:
    returncode: int | None  # None only if the process could not be reaped
    stdout: str  # UTF-8 decoded with replacement, at most max_output_bytes of raw output
    stderr: str
    timed_out: bool
    duration_ms: int
    truncated: bool  # True if either stream exceeded max_output_bytes

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


# --------------------------------------------------------------------------- argv / env
def redact_argv(argv: Sequence[Any]) -> list[str]:
    """argv safe to log: secret patterns redacted, values of credential-like flags masked."""
    out: list[str] = []
    mask_next = False
    for raw in argv:
        arg = str(raw)
        if mask_next:
            out.append("[REDACTED]")
            mask_next = False
            continue
        if arg.startswith("-"):
            flag, sep, _value = arg.partition("=")
            if _SENSITIVE_FLAG_RE.search(flag):
                if sep:
                    out.append(f"{sanitize_text(flag, max_len=80)}=[REDACTED]")
                    continue
                mask_next = True
        out.append(sanitize_text(redact_text(arg), max_len=256))
    return out


def build_child_env(extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """The scrubbed environment passed to child processes."""
    env: dict[str, str] = {}
    for key in _ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    for key, value in (extra_env or {}).items():
        if not isinstance(key, str) or not _ENV_KEY_RE.match(key):
            raise ValueError("extra_env keys must be identifiers")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError("extra_env values must be strings without NUL")
        env[key] = value
    return env


def _validate_argv(argv: Sequence[Any]) -> list[str]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence) or not argv:
        raise ValueError("argv must be a non-empty list of strings (no shell command strings)")
    clean: list[str] = []
    for arg in argv:
        if not isinstance(arg, str):
            raise ValueError("argv items must be strings")
        if "\x00" in arg:
            raise ValueError("argv items must not contain NUL")
        clean.append(arg)
    if not clean[0].strip():
        raise ValueError("argv[0] must name an executable")
    return clean


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve_executable(name: str, cwd: str | None) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise ToolNotFoundError(f"executable not found: {sanitize_text(Path(name).name, max_len=80)}")
    exe = Path(resolved).resolve()
    if _IS_WINDOWS and exe.suffix.lower() in {".bat", ".cmd"}:
        raise ToolError("refusing to run a batch file (cmd.exe argument parsing is injectable)")
    if cwd is not None and _is_within(exe, Path(cwd).resolve()):
        raise ToolError("refusing to run an executable located inside the working directory")
    return str(exe)


# --------------------------------------------------------------------------- process control
class _BoundedReader(threading.Thread):
    """Drains a pipe, keeping at most ``limit`` bytes and discarding the remainder."""

    def __init__(self, stream: Any, limit: int, label: str) -> None:
        super().__init__(name=f"warden-tool-{label}", daemon=True)
        self._stream = stream
        self._limit = limit
        self._chunks: list[bytes] = []
        self._kept = 0
        self._lock = threading.Lock()
        self.truncated = False

    def run(self) -> None:
        read = getattr(self._stream, "read1", None) or self._stream.read
        try:
            while True:
                chunk = read(_READ_CHUNK)
                if not chunk:
                    break
                with self._lock:
                    room = self._limit - self._kept
                    if room > 0:
                        kept = chunk[:room]
                        self._chunks.append(kept)
                        self._kept += len(kept)
                    if len(chunk) > max(room, 0):
                        self.truncated = True
        except (OSError, ValueError):
            pass  # pipe closed underneath us (process killed / handle closed)
        finally:
            with contextlib.suppress(OSError, ValueError):
                self._stream.close()

    def text(self) -> str:
        with self._lock:
            data = b"".join(self._chunks)
        return data.decode("utf-8", errors="replace")


def _kill_tree(proc: subprocess.Popen) -> None:
    """Best-effort kill of the child and everything in its process group / tree."""
    if proc.poll() is not None and not _IS_WINDOWS:
        # The leader exited; its group may still hold helpers.
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        return
    if _IS_WINDOWS:
        taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
        if taskkill.is_file():
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                # Fixed absolute binary and an integer pid: no attacker-influenced arguments (bandit B603 reviewed).
                subprocess.run(  # nosec B603
                    [str(taskkill), "/F", "/T", "/PID", str(proc.pid)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
        with contextlib.suppress(OSError):
            proc.kill()
    else:
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(OSError):
            proc.kill()


def run_tool(
    argv: Sequence[str],
    *,
    timeout: float,
    cwd: str | os.PathLike[str] | None = None,
    extra_env: Mapping[str, str] | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> ToolResult:
    """Run an external tool with the controls described in the module docstring.

    Raises ``ToolNotFoundError`` if the executable cannot be found, ``ToolError`` if it
    cannot be launched or is refused, and ``ValueError`` for invalid arguments. A non-zero
    exit or a timeout is *not* an exception: inspect ``returncode`` / ``timed_out``.
    """
    args = _validate_argv(argv)
    timeout_s = float(timeout)
    if not (math.isfinite(timeout_s) and timeout_s > 0):
        raise ValueError("timeout must be a positive finite number of seconds")
    if not isinstance(max_output_bytes, int) or max_output_bytes < 0:
        raise ValueError("max_output_bytes must be a non-negative int")
    cwd_str: str | None = None
    if cwd is not None:
        cwd_str = os.fspath(cwd)
        if not os.path.isdir(cwd_str):
            raise ValueError("cwd must be an existing directory")
    env = build_child_env(extra_env)
    exe = _resolve_executable(args[0], cwd_str)
    safe_argv = redact_argv(args)

    popen_kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": cwd_str,
        "env": env,
        "shell": False,
        "close_fds": True,
    }
    if _IS_WINDOWS:
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
    else:
        popen_kwargs["start_new_session"] = True

    start = time.monotonic()
    try:
        # bandit B603 reviewed: shell=False, argv[0] resolved to an absolute path, allowlisted environment.
        proc = subprocess.Popen([exe, *args[1:]], **popen_kwargs)  # nosec B603
    except OSError as exc:
        log.warning("tool_launch_failed", argv=safe_argv, error_type=type(exc).__name__)
        raise ToolError(f"could not launch {sanitize_text(Path(exe).name, max_len=80)}") from exc

    out_reader = _BoundedReader(proc.stdout, max_output_bytes, "stdout")
    err_reader = _BoundedReader(proc.stderr, max_output_bytes, "stderr")
    out_reader.start()
    err_reader.start()

    deadline = start + timeout_s
    timed_out = False
    try:
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
    except BaseException:
        _kill_tree(proc)
        raise

    for reader in (out_reader, err_reader):
        remaining = max(0.0, deadline - time.monotonic())
        reader.join(remaining if not timed_out else _KILL_GRACE_SECONDS)
    if out_reader.is_alive() or err_reader.is_alive():
        # The leader exited but a descendant still holds the pipes open past the deadline.
        if not timed_out:
            timed_out = True
            _kill_tree(proc)
        for reader in (out_reader, err_reader):
            reader.join(_KILL_GRACE_SECONDS)

    returncode: int | None
    try:
        returncode = proc.wait(timeout=_KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        returncode = None

    duration_ms = int((time.monotonic() - start) * 1000)
    truncated = out_reader.truncated or err_reader.truncated
    log.info(
        "tool_run", tool=sanitize_text(Path(exe).name, max_len=80), argv=safe_argv, returncode=returncode,
        timed_out=timed_out, truncated=truncated, duration_ms=duration_ms,
    )
    return ToolResult(
        returncode=returncode,
        stdout=out_reader.text(),
        stderr=err_reader.text(),
        timed_out=timed_out,
        duration_ms=duration_ms,
        truncated=truncated,
    )


# --------------------------------------------------------------------------- discovery
_TOOL_CACHE: dict[tuple[str, tuple[str, ...]], ToolStatus] = {}
_TOOL_CACHE_LOCK = threading.Lock()


def clear_tool_cache() -> None:
    with _TOOL_CACHE_LOCK:
        _TOOL_CACHE.clear()


def _parse_version(text: str) -> str | None:
    for line in text.splitlines():
        match = _VERSION_RE.search(line)
        if match:
            return sanitize_text(match.group(0), max_len=64)
    return None


def find_tool(binary: str, *, version_args: Sequence[str] = ("--version",)) -> ToolStatus:
    """Locate ``binary`` and probe its version (cached per binary + probe arguments).

    ``available`` is False when the binary is not on PATH, cannot be launched, is refused by
    ``run_tool``'s safety checks, or hangs on the version probe. A probe that exits non-zero
    still counts as available (some tools print their version with a non-zero status); the
    version is reported only when one can be parsed from its output.
    """
    name = str(binary or "").strip()
    key = (name, tuple(version_args))
    with _TOOL_CACHE_LOCK:
        cached = _TOOL_CACHE.get(key)
    if cached is not None:
        return cached

    label = sanitize_text(Path(name).name or name, max_len=80)
    if not name or shutil.which(name) is None:
        status = ToolStatus(name=label, available=False, detail="not found on PATH")
    else:
        try:
            result = run_tool(
                [name, *version_args], timeout=VERSION_PROBE_TIMEOUT_SECONDS,
                max_output_bytes=_VERSION_PROBE_MAX_BYTES,
            )
        except (ToolError, ValueError) as exc:
            status = ToolStatus(name=label, available=False, detail=f"launch failed ({type(exc).__name__})")
        else:
            if result.timed_out:
                status = ToolStatus(name=label, available=False, detail="version probe timed out")
            else:
                version = _parse_version(result.stdout) or _parse_version(result.stderr)
                detail = None if result.returncode == 0 else f"version probe exited {result.returncode}"
                status = ToolStatus(name=label, available=True, version=version, detail=detail)
    with _TOOL_CACHE_LOCK:
        _TOOL_CACHE[key] = status
    return status


# --------------------------------------------------------------------------- workspace
def normalize_relpath(relpath: Any, *, max_length: int | None = None, max_depth: int | None = None) -> str:
    """Validate a package-relative path and return it with ``/`` separators.

    Raises :class:`UnsafePathError` for anything that could escape or alias the workspace
    root or misbehave on Windows/POSIX filesystems.
    """
    max_length = settings.MAX_PATH_LENGTH if max_length is None else max_length
    max_depth = settings.MAX_PATH_DEPTH if max_depth is None else max_depth
    if not isinstance(relpath, str) or not relpath:
        raise UnsafePathError("empty")
    if _CONTROL_CHARS_RE.search(relpath):
        raise UnsafePathError("control_character")
    if len(relpath) > max_length:
        raise UnsafePathError("too_long")
    if relpath.startswith(("/", "\\")):
        raise UnsafePathError("absolute")  # also covers UNC (\\server\share, //server/share)
    if _DRIVE_RE.match(relpath):
        raise UnsafePathError("drive_letter")
    parts = [p for p in relpath.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts:
        raise UnsafePathError("empty")
    if len(parts) > max_depth:
        raise UnsafePathError("too_deep")
    for part in parts:
        if part == "..":
            raise UnsafePathError("traversal")
        if part.startswith("~"):
            raise UnsafePathError("home_reference")
        if len(part) > _MAX_COMPONENT_LENGTH:
            raise UnsafePathError("component_too_long")
        if any(ch in _WINDOWS_INVALID_CHARS for ch in part):
            raise UnsafePathError("invalid_character")  # ':' also blocks NTFS alternate data streams
        if part.endswith((".", " ")):
            raise UnsafePathError("trailing_dot_or_space")
        if part.split(".")[0].upper() in _RESERVED_NAMES:
            raise UnsafePathError("reserved_name")
    return "/".join(parts)


@dataclass
class Workspace:
    """A materialised package tree. Path-like: usable wherever a directory path is."""

    root: Path
    files: list[str] = field(default_factory=list)  # normalised relpaths written
    skipped: list[dict] = field(default_factory=list)  # [{"path": sanitised, "reason": ...}]

    def __fspath__(self) -> str:
        return str(self.root)

    def __str__(self) -> str:
        return str(self.root)

    def __truediv__(self, other: str) -> Path:
        return self.root / other


_O_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _ensure_dirs(root: Path, parts: list[str]) -> Path:
    current = root
    for part in parts:
        current = current / part
        if os.path.lexists(current):
            if os.path.islink(current) or not current.is_dir():
                raise UnsafePathError("path_conflict")
        else:
            os.mkdir(current, 0o700)
    return current


def _write_member(root: Path, rel: str, data: bytes) -> None:
    parts = rel.split("/")
    parent = _ensure_dirs(root, parts[:-1])
    target = parent / parts[-1]
    real_root = os.path.realpath(root)
    if os.path.commonpath([real_root, os.path.realpath(parent)]) != real_root:
        raise UnsafePathError("escapes_root")
    fd = os.open(target, _O_FLAGS, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _on_rm_error(func: Any, path: str, _exc: Any) -> None:
    # Read-only files (common on Windows) block deletion: make writable and retry once.
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)


def remove_tree(path: str | os.PathLike[str], attempts: int = 3) -> bool:
    """Delete a directory tree robustly (never follows symlinks). Returns success."""
    target = os.fspath(path)
    for attempt in range(attempts):
        if not os.path.lexists(target):
            return True
        try:
            if sys.version_info >= (3, 12):
                shutil.rmtree(target, onexc=_on_rm_error)
            else:  # pragma: no cover - Python 3.11
                shutil.rmtree(target, onerror=_on_rm_error)
        except OSError:
            pass
        if not os.path.lexists(target):
            return True
        time.sleep(0.05 * (attempt + 1))  # a just-killed tool may still hold a handle (Windows)
    return not os.path.lexists(target)


@contextlib.contextmanager
def package_workspace(
    ctx: Any,
    *,
    include_binaries: bool = True,
    max_total_bytes: int | None = None,
    base_dir: str | os.PathLike[str] | None = None,
) -> Iterator[Workspace]:
    """Materialise ``ctx.files`` (UTF-8 text) and ``ctx.binaries`` into a private temp dir.

    Unsafe, duplicate (case-insensitively) or over-budget members are skipped and recorded
    in ``Workspace.skipped``; nothing is ever written outside the workspace root. The
    directory is deleted when the context exits, including on exceptions.
    """
    budget = settings.MAX_EXTRACTED_BYTES if max_total_bytes is None else max_total_bytes
    root = Path(tempfile.mkdtemp(prefix="warden-ws-", dir=os.fspath(base_dir) if base_dir else None))
    with contextlib.suppress(OSError):
        os.chmod(root, 0o700)
    workspace = Workspace(root=root)
    try:
        members: list[tuple[Any, bytes | str]] = [(f.relpath, f.text) for f in getattr(ctx, "files", []) or []]
        if include_binaries:
            members.extend((rel, data) for rel, data in (getattr(ctx, "binaries", {}) or {}).items())
        seen: set[str] = set()
        written = 0
        for raw_rel, content in members:
            try:
                rel = normalize_relpath(raw_rel)
                key = rel.casefold()
                if key in seen:
                    raise UnsafePathError("duplicate")
                data = content.encode("utf-8", errors="replace") if isinstance(content, str) else bytes(content)
                if written + len(data) > budget:
                    raise UnsafePathError("budget_exceeded")
                _write_member(root, rel, data)
            except UnsafePathError as exc:
                workspace.skipped.append({"path": sanitize_text(raw_rel, max_len=200), "reason": exc.reason})
                continue
            except OSError as exc:
                workspace.skipped.append({"path": sanitize_text(raw_rel, max_len=200),
                                          "reason": f"write_failed:{type(exc).__name__}"})
                continue
            seen.add(key)
            written += len(data)
            workspace.files.append(rel)
        if workspace.skipped:
            log.info("workspace_members_skipped", count=len(workspace.skipped))
        yield workspace
    finally:
        if not remove_tree(root):
            log.warning("workspace_cleanup_failed", path=str(root))


__all__ = [
    "DEFAULT_MAX_OUTPUT_BYTES",
    "ToolError",
    "ToolNotFoundError",
    "ToolResult",
    "UnsafePathError",
    "Workspace",
    "build_child_env",
    "clear_tool_cache",
    "find_tool",
    "normalize_relpath",
    "package_workspace",
    "redact_argv",
    "remove_tree",
    "run_tool",
]
