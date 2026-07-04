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
  ``UNPARSEABLE`` signal instead of an exception, so a hostile file cannot crash the pipe.
"""

from __future__ import annotations

import ast

from app.analysis.analyzers.base import PackageContext
from app.analysis.signals import Capability, Code, Severity, Signal

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


class _Walker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: set[str] = set()
        self.dynamic_exec = 0
        self.network = 0
        self.subprocess = 0
        self.env_harvest = False
        self.fs_sensitive = False
        self.evidence: dict[str, list[str]] = {}

    def _note(self, key: str, detail: str) -> None:
        self.evidence.setdefault(key, [])
        if detail not in self.evidence[key] and len(self.evidence[key]) < 8:
            self.evidence[key].append(detail)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            self.imports.add(top)
            if top in NETWORK_MODULES:
                self.network += 1
                self._note("network_imports", top)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            top = node.module.split(".")[0]
            self.imports.add(top)
            if top in NETWORK_MODULES:
                self.network += 1
                self._note("network_imports", top)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # Bare dynamic calls: eval(...), exec(...), compile(...)
        if isinstance(func, ast.Name) and func.id in DYNAMIC_CALLS:
            self.dynamic_exec += 1
            self._note("dynamic_exec", func.id)
        # Attribute calls: os.system, subprocess.Popen, os.environ.get(...)
        if isinstance(func, ast.Attribute):
            attr = func.attr
            root = _attr_root(func)
            if root == "os" and attr in {"system", "popen", "execv", "execve", "spawnv"}:
                self.subprocess += 1
                self._note("process_calls", f"os.{attr}")
            if root == "subprocess" and attr in {"run", "call", "Popen", "check_output", "check_call"}:
                self.subprocess += 1
                self._note("process_calls", f"subprocess.{attr}")
            if root in NETWORK_MODULES and attr in {"get", "post", "urlopen", "request", "Request", "connect"}:
                self.network += 1
                self._note("network_calls", f"{root}.{attr}")
        # Environment variable harvesting: os.environ[...] / os.getenv(...)
        self._check_env_access(node)
        self.generic_visit(node)

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
        self.generic_visit(node)

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
        # Any string constant argument that references a sensitive path.
        for arg in node.args:
            s = _const_str(arg)
            if s and any(p in s for p in SENSITIVE_PATHS):
                self.fs_sensitive = True
                self._note("sensitive_paths", s)

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


class StaticCodeAnalyzer:
    name = "static_code"

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        agg = _Walker()
        parsed_any = False
        for f in ctx.python_files():
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError, RecursionError):
                # Fail-safe: a file we cannot parse becomes evidence, never a crash.
                agg._note("unparseable", f.relpath)
                continue
            parsed_any = True
            agg.visit(tree)

        signals: list[Signal] = []

        # Weights below are deliberately low for *generic capabilities* that legitimate
        # libraries routinely use (network, dynamic import, reading proxy env vars). The
        # high-signal detections — install-time exec, sensitive-credential access,
        # obfuscation, typosquat, IOC — live in their own analyzers and carry the weight.
        # This is what keeps precision high on benign popular packages.
        if agg.dynamic_exec:
            signals.append(Signal(
                Code.DYNAMIC_EXEC, Severity.medium, 4.0,
                f"Dynamic code execution used {agg.dynamic_exec} time(s) (eval/exec/compile)",
                {"calls": agg.evidence.get("dynamic_exec", [])},
                capability=Capability.DYNAMIC_EXEC,
            ))
        if agg.network:
            signals.append(Signal(
                Code.NETWORK_EGRESS, Severity.low, 1.5,
                "Network egress capability detected in package code",
                {"imports": agg.evidence.get("network_imports", []),
                 "calls": agg.evidence.get("network_calls", [])},
                capability=Capability.NETWORK,
            ))
        if agg.subprocess:
            signals.append(Signal(
                Code.SUBPROCESS_EXEC, Severity.medium, 3.0,
                "Process/command execution capability detected",
                {"calls": agg.evidence.get("process_calls", [])},
                capability=Capability.SUBPROCESS,
            ))
        # Only sensitive-credential env access is a strong signal; reading generic env
        # vars (e.g. HTTP_PROXY) is normal and intentionally not flagged.
        if agg.env_harvest and agg.evidence.get("sensitive_env"):
            signals.append(Signal(
                Code.ENV_HARVEST, Severity.critical, 9.0,
                "Reads sensitive credential environment variables (credential harvesting)",
                {"env": agg.evidence.get("env_access", []),
                 "sensitive": agg.evidence.get("sensitive_env", [])},
                capability=Capability.ENV_HARVEST,
            ))
        if agg.fs_sensitive:
            signals.append(Signal(
                Code.FS_SENSITIVE, Severity.high, 5.0,
                "References sensitive filesystem paths (keys/credentials)",
                {"paths": agg.evidence.get("sensitive_paths", [])},
            ))
        dangerous = sorted(agg.imports & set(DANGEROUS_IMPORTS))
        if dangerous:
            signals.append(Signal(
                Code.DANGEROUS_IMPORT, Severity.low, 0.8 * len(dangerous),
                f"Imports high-risk modules: {', '.join(dangerous)}",
                {"modules": dangerous},
            ))
        if not parsed_any and ctx.python_files():
            signals.append(Signal(
                Code.UNPARSEABLE, Severity.medium, 3.0,
                "One or more Python files could not be parsed (possible anti-analysis)",
                {"files": agg.evidence.get("unparseable", [])},
            ))
        return signals
