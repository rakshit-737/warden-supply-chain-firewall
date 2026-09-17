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

ANALYZER_VERSION = "1.3.0"

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
# Socket calls that open or use an outbound connection (only counted when ``socket`` is imported).
SOCKET_EGRESS_CALLS = {"create_connection", "connect", "connect_ex", "sendall", "sendto"}
# Calls that serialise or encode their argument; applied to the whole environment they package it
# up for sending somewhere, which ordinary configuration code does not do.
SERIALISING_CALLS = {"dumps", "dump", "b64encode", "urlencode", "str", "repr", "encode"}
# Substrings a credential-filtering comprehension over os.environ looks for.
CREDENTIAL_WORDS = ("KEY", "TOKEN", "SECRET", "PASS", "AWS", "CRED", "AUTH")
ENV_DUMP = "<entire environment>"
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
    Code.REVERSE_SHELL: 0.9,
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
        # os.dup2(<sock>.fileno(), 0|1|2) or pty.spawn(...): standard streams handed to something else.
        self.stdio_redirect = 0
        self.evidence: dict[str, list[str]] = {}
        self.locations = LocationCollector()
        self.file_index = 0
        self.relpath = ""
        # Per-file import aliases (``import os as _o`` -> {"_o": "os"}), so aliased calls are
        # resolved to the module they come from.
        self.aliases: dict[str, str] = {}

    def begin_file(self, index: int, relpath: str) -> None:
        self.file_index = index
        self.relpath = relpath
        self.aliases = {}

    def _root(self, node: ast.Attribute) -> str | None:
        root = _attr_root(node)
        return self.aliases.get(root, root) if root is not None else None

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
            top = alias.name.split(".")[0]
            if alias.asname:
                self.aliases[alias.asname] = top
            self._import(top, node)

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
        # getattr(builtins, "ex" + "ec"): a dynamic-execution name assembled from pieces.
        if isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2 and \
                not isinstance(node.args[1], ast.Constant):
            name = _fold_str(node.args[1])
            if name in DYNAMIC_CALLS:
                self.dynamic_exec += 1
                self._note("dynamic_exec", f"getattr:{name} (reconstructed)")
                self._loc(Code.DYNAMIC_EXEC, node)
        # Attribute calls: os.system, subprocess.Popen, os.environ.get(...)
        if isinstance(func, ast.Attribute):
            attr = func.attr
            root = self._root(func)
            if root == "os" and attr in {"system", "popen", "execv", "execve", "spawnv"}:
                self.subprocess += 1
                self._note("process_calls", f"os.{attr}")
                self._loc(Code.SUBPROCESS_EXEC, node)
            if root == "subprocess" and attr in {"run", "call", "Popen", "check_output", "check_call"}:
                self.subprocess += 1
                self._note("process_calls", f"subprocess.{attr}")
                self._loc(Code.SUBPROCESS_EXEC, node)
            if root in NETWORK_MODULES and attr in {"get", "post", "urlopen", "urlretrieve", "request", "Request",
                                                    "connect"}:
                self.network += 1
                self._note("network_calls", f"{root}.{attr}")
                self._loc(Code.NETWORK_EGRESS, node)
            elif attr in SOCKET_EGRESS_CALLS and "socket" in self.imports:
                self.network += 1
                self._note("network_calls", f"socket.{attr}")
                self._loc(Code.NETWORK_EGRESS, node)
        self._check_environment_dump(node)
        self._check_stdio_redirect(node)
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

    def _check_stdio_redirect(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        root = self._root(func)
        if root == "os" and func.attr == "dup2" and len(node.args) == 2:
            source, target = node.args
            if (isinstance(target, ast.Constant) and target.value in (0, 1, 2)
                    and isinstance(source, ast.Call) and isinstance(source.func, ast.Attribute)
                    and source.func.attr == "fileno"):
                self.stdio_redirect += 1
                self._note("stdio_redirect", f"os.dup2(...fileno(), {target.value})")
                self._loc(Code.REVERSE_SHELL, node)
        elif root == "pty" and func.attr == "spawn":
            self.stdio_redirect += 1
            self._note("stdio_redirect", "pty.spawn")
            self._loc(Code.REVERSE_SHELL, node)

    def _environment_dump(self, node: ast.AST) -> None:
        self.env_harvest = True
        self._note("env_access", ENV_DUMP)
        self._note("sensitive_env", ENV_DUMP)
        self._loc(Code.ENV_HARVEST, node)

    def _check_environment_dump(self, node: ast.Call) -> None:
        # json.dumps(os.environ), str(dict(os.environ)), base64.b64encode(repr(os.environ).encode()) ...
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else None
        if name not in SERIALISING_CALLS:
            return
        operands = [*node.args, func.value] if isinstance(func, ast.Attribute) else list(node.args)
        if any(_mentions_environ(arg, self.aliases) for arg in operands):
            self._environment_dump(node)

    def _visit_comprehension(self, node: ast.AST, generators: list[ast.comprehension]) -> None:
        # {k: v for k, v in os.environ.items() if "TOKEN" in k}
        for gen in generators:
            if _mentions_environ(gen.iter, self.aliases) and any(_has_credential_word(cond) for cond in gen.ifs):
                self._environment_dump(node)
                break

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node, node.generators)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node, node.generators)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node, node.generators)

    def _check_env_access(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"getenv"} and self._root(func) == "os":
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


MAX_OPERAND_NODES = 64  # bounded look into call operands, so nested calls cannot go quadratic


def _bounded_walk(node: ast.AST) -> list[ast.AST]:
    out: list[ast.AST] = []
    stack = [node]
    while stack and len(out) < MAX_OPERAND_NODES:
        current = stack.pop()
        out.append(current)
        stack.extend(ast.iter_child_nodes(current))
    return out


_ENV_WRAPPERS = {"dict", "list", "sorted", "tuple", "set"}
_ENV_METHODS = {"copy", "items", "values", "keys"}


def _mentions_environ(node: ast.AST, aliases: dict[str, str]) -> bool:
    """True when ``node`` evaluates to the whole environment: ``os.environ``, ``dict(os.environ)``,
    ``os.environ.copy()`` / ``.items()``, ``{**os.environ}``. A single lookup such as
    ``os.environ.get("DEBUG")`` or ``os.environ["HOME"]`` is not the whole environment."""
    current: ast.AST | None = node
    for _ in range(MAX_OPERAND_NODES):
        if isinstance(current, ast.Attribute) and current.attr == "environ":
            root = _attr_root(current)
            return aliases.get(root or "", root) == "os"
        if isinstance(current, ast.Call):
            func = current.func
            if isinstance(func, ast.Name) and func.id in _ENV_WRAPPERS and len(current.args) == 1:
                current = current.args[0]
                continue
            if isinstance(func, ast.Attribute) and func.attr in _ENV_METHODS and not current.args:
                current = func.value
                continue
            if isinstance(func, ast.Attribute) and func.attr == "encode":
                current = func.value
                continue
            return False
        if isinstance(current, ast.Dict):
            spread = [v for k, v in zip(current.keys, current.values, strict=False) if k is None]
            return any(_mentions_environ(v, aliases) for v in spread[:4])
        return False
    return False


def _has_credential_word(node: ast.AST) -> bool:
    for sub in _bounded_walk(node):
        text = _const_str(sub) if isinstance(sub, ast.Constant) else None
        if text and any(word in text.upper() for word in CREDENTIAL_WORDS):
            return True
    return False


def _attr_root(node: ast.Attribute) -> str | None:
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


MAX_FOLD_PARTS = 32


def _fold_str(node: ast.AST) -> str | None:
    """Constant-fold ``"a" + "b"`` / ``"".join(["a", "b"])`` / f-strings of constants (bounded)."""
    parts: list[str] = []
    stack = [node]
    while stack:
        if len(parts) > MAX_FOLD_PARTS:
            return None
        current = stack.pop()
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            parts.append(current.value)
        elif isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            stack.extend([current.right, current.left])
        elif isinstance(current, ast.JoinedStr):
            stack.extend(reversed(current.values))
        elif isinstance(current, ast.FormattedValue) and current.format_spec is None and current.conversion == -1:
            stack.append(current.value)
        elif (isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute)
              and current.func.attr == "join" and _const_str(current.func.value) == ""
              and len(current.args) == 1 and isinstance(current.args[0], (ast.List, ast.Tuple))):
            stack.extend(reversed(current.args[0].elts))
        else:
            return None
    return "".join(parts)


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
        # Standard streams redirected onto a socket (or a pty spawned) in a package that also opens
        # sockets: the shape of an interactive reverse shell. Terminal emulators use pty without a
        # socket, and servers use sockets without handing them to stdio, so both are required.
        if agg.stdio_redirect and "socket" in agg.imports:
            emit(Code.REVERSE_SHELL, Severity.critical, 12.0,
                 "Connects a socket to the standard streams of a process (reverse shell)",
                 {"redirects": agg.evidence.get("stdio_redirect", [])},
                 capability=Capability.SHELL)
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
