"""AST-based static behavioural analysis of Python source.

This analyzer parses each Python file into an abstract syntax tree and walks it looking for
behavioural indicators associated with malicious packages: install/runtime code execution,
network egress, process spawning, dynamic code evaluation, environment/credential
harvesting, and writes to sensitive filesystem locations.

Design choices:

* **AST, not regex.** Parsing gives structural context (an *import* of ``os`` vs. the
  substring "os"), dramatically reducing false positives compared with grep-style tools.
* **Never execute.** ``ast.parse`` compiles to a tree but runs nothing. Untrusted install
  hooks are read, not run.
* **Fail-safe.** A file that cannot be parsed (syntax error, too large) yields an
  ``UNPARSEABLE`` finding instead of an exception. The tree is walked with an explicit stack,
  not recursion: a valid but deeply nested file (``x = 0 + 1 + 1 ...`` with a thousand terms)
  parses fine but would exhaust the interpreter recursion limit in ``ast.NodeVisitor``, and
  the resulting crash would discard every finding from every other file of the package.
* **Real positions only.** Findings aggregate evidence across the whole package; each one
  carries the file and 1-based AST line of its *first* occurrence in ``location`` and up to
  ten earliest ``{file, line}`` positions in ``evidence["locations"]``. Positions come from
  the parser (``node.lineno``) and are never estimated.

Confidence values express how likely each finding is to indicate *malice*. Capabilities that
benign libraries use every day (network, subprocess) are deliberately low-confidence.
"""

from __future__ import annotations

import ast
import bisect

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.findings import Location
from app.analysis.signals import Capability, Code, Severity, Signal

ANALYZER_VERSION = "1.1.0"

# Modules whose mere import is a meaningful risk indicator.
DANGEROUS_IMPORTS = {
    "subprocess": Code.SUBPROCESS_EXEC,
    "socket": Code.NETWORK_EGRESS,
    "ctypes": Code.DANGEROUS_IMPORT,
    "pty": Code.SUBPROCESS_EXEC,
    "telnetlib": Code.NETWORK_EGRESS,
    "ftplib": Code.NETWORK_EGRESS,
    "smtplib": Code.NETWORK_EGRESS,
    "marshal": Code.DANGEROUS_IMPORT,
}
NETWORK_MODULES = {"requests", "urllib", "urllib2", "urllib3", "httpx", "http", "aiohttp"}
# `__import__` is deliberately excluded here: it is extremely common in benign optional-
# dependency handling and would swamp the signal with false positives. `eval`/`exec`/
# `compile` are the meaningful dynamic-execution primitives.
DYNAMIC_CALLS = {"eval", "exec", "compile"}
# Environment variables / paths that credential-stealers commonly read.
SENSITIVE_ENV = {
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "GH_TOKEN",
    "NPM_TOKEN", "PYPI_TOKEN", "DOCKER_PASSWORD", "SSH_AUTH_SOCK", "OPENAI_API_KEY",
}
# Specific credential-file paths only. Generic words like "credentials" were removed
# because they appear in benign docstrings and produced false positives (e.g. requests).
SENSITIVE_PATHS = (
    ".ssh/id_rsa", "id_rsa", "id_ed25519", ".aws/credentials", ".git-credentials",
    ".pypirc", ".npmrc", "/etc/passwd", "/etc/shadow", ".docker/config.json",
    "id_dsa", ".ssh/id_",
)

# Confidence that each finding indicates malicious intent (see SPEC "Finding conventions").
CONFIDENCE = {
    Code.NETWORK_EGRESS: 0.5,
    Code.SUBPROCESS_EXEC: 0.55,
    Code.DYNAMIC_EXEC: 0.6,
    Code.ENV_HARVEST: 0.65,
    Code.FS_SENSITIVE: 0.7,
    Code.DANGEROUS_IMPORT: 0.4,
    Code.UNPARSEABLE: 0.6,
}

MAX_EVIDENCE_LOCATIONS = 10


class LocationCollector:
    """Keeps the earliest ``limit`` distinct positions recorded under each key.

    Positions are ordered by ``(file_index, line)`` where ``file_index`` is the position of
    the file in the analyzer's iteration order, so "first occurrence" follows package file
    order and then source order — independent of AST traversal order (``ast.walk`` is
    breadth-first and ``NodeVisitor`` visits decorators after function bodies).

    Only real positions are accepted: a line must be a positive ``int`` or ``None`` ("file
    known, line unknown"). Memory is bounded to ``limit`` entries per key.
    """

    def __init__(self, limit: int = MAX_EVIDENCE_LOCATIONS) -> None:
        self._limit = max(1, limit)
        self._data: dict[str, list[tuple[int, int, str]]] = {}

    def add(self, key: str, file_index: int, relpath: str, line: int | None) -> None:
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            return
        # Line 0 sorts a line-less entry before any real line in the same file.
        item = (file_index, line or 0, relpath)
        entries = self._data.setdefault(key, [])
        if item in entries:
            return
        if len(entries) >= self._limit and item >= entries[-1]:
            return
        bisect.insort(entries, item)
        if len(entries) > self._limit:
            entries.pop()

    def add_node(self, key: str, file_index: int, relpath: str, node: ast.AST) -> None:
        self.add(key, file_index, relpath, getattr(node, "lineno", None))

    def _merged(self, keys: tuple[str, ...]) -> list[tuple[int, int, str]]:
        merged = sorted({item for k in keys for item in self._data.get(k, ())})
        return merged[: self._limit]

    def first(self, *keys: str) -> Location | None:
        merged = self._merged(keys)
        if not merged:
            return None
        _, line, relpath = merged[0]
        return Location(file=relpath, line=line or None)

    def evidence(self, *keys: str) -> list[dict]:
        return [{"file": relpath, "line": line or None} for _, line, relpath in self._merged(keys)]


class _Walker:
    """Collects indicators from AST nodes.

    :meth:`visit` performs the same pre-order traversal as ``ast.NodeVisitor`` (node first, then
    children in field order) but iteratively, so traversal depth is bounded only by memory.
    ``visit_*`` handlers therefore must not recurse into children themselves.
    """

    def __init__(self) -> None:
        self.imports: set[str] = set()
        self.dynamic_exec = 0
        self.network = 0
        self.subprocess = 0
        self.env_harvest = False
        self.fs_sensitive = False
        self.evidence: dict[str, list[str]] = {}
        self.locations = LocationCollector()
        self.file_index = 0
        self.relpath = ""

    def begin_file(self, index: int, relpath: str) -> None:
        self.file_index = index
        self.relpath = relpath

    def visit(self, tree: ast.AST) -> None:
        stack: list[ast.AST] = [tree]
        while stack:
            node = stack.pop()
            handler = getattr(self, f"visit_{type(node).__name__}", None)
            if handler is not None:
                handler(node)
            stack.extend(reversed(list(ast.iter_child_nodes(node))))

    def _loc(self, key: str, node: ast.AST) -> None:
        self.locations.add_node(key, self.file_index, self.relpath, node)

    def _note(self, key: str, detail: str) -> None:
        self.evidence.setdefault(key, [])
        if detail not in self.evidence[key] and len(self.evidence[key]) < 8:
            self.evidence[key].append(detail)

    def _import(self, top: str, node: ast.AST) -> None:
        self.imports.add(top)
        if top in NETWORK_MODULES:
            self.network += 1
            self._note("network_imports", top)
            self._loc(Code.NETWORK_EGRESS, node)
        if top in DANGEROUS_IMPORTS:
            self._loc(Code.DANGEROUS_IMPORT, node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._import(alias.name.split(".")[0], node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._import(node.module.split(".")[0], node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # Bare dynamic calls: eval(...), exec(...), compile(...)
        if isinstance(func, ast.Name) and func.id in DYNAMIC_CALLS:
            self.dynamic_exec += 1
            self._note("dynamic_exec", func.id)
            self._loc(Code.DYNAMIC_EXEC, node)
        # Attribute calls: os.system, subprocess.Popen, os.environ.get(...)
        if isinstance(func, ast.Attribute):
            attr = func.attr
            root = _attr_root(func)
            if root == "os" and attr in {"system", "popen", "execv", "execve", "spawnv"}:
                self.subprocess += 1
                self._note("process_calls", f"os.{attr}")
                self._loc(Code.SUBPROCESS_EXEC, node)
            if root == "subprocess" and attr in {"run", "call", "Popen", "check_output", "check_call"}:
                self.subprocess += 1
                self._note("process_calls", f"subprocess.{attr}")
                self._loc(Code.SUBPROCESS_EXEC, node)
            if root in NETWORK_MODULES and attr in {"get", "post", "urlopen", "request", "Request", "connect"}:
                self.network += 1
                self._note("network_calls", f"{root}.{attr}")
                self._loc(Code.NETWORK_EGRESS, node)
        # Environment variable harvesting: os.environ[...] / os.getenv(...)
        self._check_env_access(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # os.environ["AWS_SECRET_ACCESS_KEY"]
        val = node.value
        if isinstance(val, ast.Attribute) and val.attr == "environ":
            key = _const_str(node.slice)
            if key:
                self.env_harvest = True
                self._note("env_access", key)
                if key in SENSITIVE_ENV:
                    self._note("sensitive_env", key)
                    self._loc(Code.ENV_HARVEST, node)

    def _check_env_access(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"getenv"} and _attr_root(func) == "os":
            self.env_harvest = True
            if node.args:
                key = _const_str(node.args[0])
                if key:
                    self._note("env_access", key)
                    if key in SENSITIVE_ENV:
                        self._note("sensitive_env", key)
                        self._loc(Code.ENV_HARVEST, node)
        # Any string constant argument that references a sensitive path.
        for arg in node.args:
            s = _const_str(arg)
            if s and any(p in s for p in SENSITIVE_PATHS):
                self.fs_sensitive = True
                self._note("sensitive_paths", s)
                self._loc(Code.FS_SENSITIVE, arg)

    # NOTE: sensitive-path detection lives in `_check_env_access`, which inspects string
    # arguments to *calls* (open/read/expanduser/...). We deliberately do NOT flag bare
    # string constants — example paths like "file:///etc/passwd" routinely appear in
    # benign docstrings and would be false positives. We care about paths that are *used*.


def _attr_root(node: ast.Attribute) -> str | None:
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _with_locations(evidence: dict, walker: _Walker, code: str) -> dict:
    evidence["locations"] = walker.locations.evidence(code)
    return evidence


class StaticCodeAnalyzer(BaseAnalyzer):
    name = "static_code"
    version = ANALYZER_VERSION

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        agg = _Walker()
        parsed_any = False
        for index, f in enumerate(ctx.python_files()):
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
                # Fail-safe: a file we cannot parse becomes evidence, never a crash. CPython's
                # parser raises MemoryError ("parser stack overflowed") for pathologically
                # nested source; without this, one hostile file would abort the analyzer and
                # suppress the findings from every other file in the package.
                agg._note("unparseable", f.relpath)
                # SyntaxError carries the parser's own line number; other errors have none.
                line = exc.lineno if isinstance(exc, SyntaxError) else None
                agg.locations.add(Code.UNPARSEABLE, index, f.relpath, line if isinstance(line, int) else None)
                continue
            parsed_any = True
            agg.begin_file(index, f.relpath)
            agg.visit(tree)

        signals: list[Signal] = []

        def emit(code: str, severity: Severity, weight: float, message: str, evidence: dict,
                 capability: str | None = None) -> None:
            signals.append(Signal(
                code, severity, weight, message, _with_locations(evidence, agg, code), capability,
                confidence=CONFIDENCE[code], location=agg.locations.first(code),
            ))

        # Weights below are deliberately low for *generic capabilities* that legitimate
        # libraries routinely use (network, dynamic import, reading proxy env vars). The
        # high-signal detections — install-time exec, sensitive-credential access,
        # obfuscation, typosquat, IOC — live in their own analyzers and carry the weight.
        # This is what keeps precision high on benign popular packages.
        if agg.dynamic_exec:
            emit(Code.DYNAMIC_EXEC, Severity.medium, 4.0,
                 f"Dynamic code execution used {agg.dynamic_exec} time(s) (eval/exec/compile)",
                 {"calls": agg.evidence.get("dynamic_exec", [])},
                 capability=Capability.DYNAMIC_EXEC)
        if agg.network:
            emit(Code.NETWORK_EGRESS, Severity.low, 1.5,
                 "Network egress capability detected in package code",
                 {"imports": agg.evidence.get("network_imports", []),
                  "calls": agg.evidence.get("network_calls", [])},
                 capability=Capability.NETWORK)
        if agg.subprocess:
            emit(Code.SUBPROCESS_EXEC, Severity.medium, 3.0,
                 "Process/command execution capability detected",
                 {"calls": agg.evidence.get("process_calls", [])},
                 capability=Capability.SUBPROCESS)
        # Only sensitive-credential env access is a strong signal; reading generic env
        # vars (e.g. HTTP_PROXY) is normal and intentionally not flagged.
        if agg.env_harvest and agg.evidence.get("sensitive_env"):
            emit(Code.ENV_HARVEST, Severity.critical, 9.0,
                 "Reads sensitive credential environment variables (credential harvesting)",
                 {"env": agg.evidence.get("env_access", []),
                  "sensitive": agg.evidence.get("sensitive_env", [])},
                 capability=Capability.ENV_HARVEST)
        if agg.fs_sensitive:
            emit(Code.FS_SENSITIVE, Severity.high, 5.0,
                 "References sensitive filesystem paths (keys/credentials)",
                 {"paths": agg.evidence.get("sensitive_paths", [])})
        dangerous = sorted(agg.imports & set(DANGEROUS_IMPORTS))
        if dangerous:
            emit(Code.DANGEROUS_IMPORT, Severity.low, 0.8 * len(dangerous),
                 f"Imports high-risk modules: {', '.join(dangerous)}",
                 {"modules": dangerous})
        if not parsed_any and ctx.python_files():
            emit(Code.UNPARSEABLE, Severity.medium, 3.0,
                 "One or more Python files could not be parsed (possible anti-analysis)",
                 {"files": agg.evidence.get("unparseable", [])})
        return signals
