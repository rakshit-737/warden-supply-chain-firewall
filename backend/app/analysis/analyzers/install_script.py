"""Install-time execution analyzer.

The single most dangerous behaviour in the Python packaging ecosystem is code that runs
during ``pip install`` — before any test, review, or import. This analyzer looks
specifically at ``setup.py`` and flags:

* imports of process/network/eval capabilities inside the build script,
* calls that execute commands, fetch URLs or evaluate code,
* ``cmdclass`` overrides that hook ``install``/``develop`` to run custom code.

A setup.py that merely calls ``setup(...)`` with static metadata is benign; one that
opens a socket or spawns a shell at import time is the classic supply-chain payload.

The script is parsed with ``ast`` and never executed. Findings are per build file and carry
the 1-based AST line of the first contributing statement in ``location`` plus up to ten
contributing ``{file, line}`` positions in ``evidence["locations"]``.
"""

from __future__ import annotations

import ast

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.analyzers.static_code import LocationCollector
from app.analysis.signals import Capability, Code, Severity, Signal

ANALYZER_VERSION = "1.2.0"

_CAP_MODULES = {"socket", "subprocess", "requests", "urllib", "os", "ctypes", "base64", "http"}
# Capability imports that on their own make a build script "active" (os/base64 do not).
_ACTIVE_MODULES = {"socket", "subprocess", "requests", "urllib", "http", "ctypes"}

# Not every kind of install-time activity is equally suspicious. Fetching a URL or evaluating
# code during installation is the classic supply-chain payload; running a *process* is also how
# every C-extension package invokes its compiler (psutil and numpy both do it). Grading the
# finding by what the script actually does keeps the vector visible without treating an
# ordinary native build as malware.
_NETWORK_MODULES = {"socket", "requests", "urllib", "http", "httpx", "ftplib", "telnetlib", "smtplib"}
_NETWORK_ATTRS = {"urlopen", "get", "post", "request", "connect", "urlretrieve"}
_PROCESS_ATTRS = {"system", "popen", "run", "Popen", "check_output", "check_call", "call", "spawnv", "spawnve"}
_SHELL_ATTRS = {"system", "popen"}
_DECODER_ATTRS = {"b64decode", "b32decode", "b16decode", "a85decode", "unhexlify", "decompress"}

KIND_NETWORK = "network"
KIND_DYNAMIC = "dynamic_execution"
KIND_PROCESS = "process"
KIND_SHELL = "shell"
KIND_NATIVE = "native_library"
_DYNAMIC = {"eval", "exec", "compile", "__import__"}
_SUSPICIOUS_ATTRS = {"system", "popen", "run", "Popen", "check_output", "urlopen", "get", "post"}

# Active behaviour in setup.py is strong structural evidence; a cmdclass override alone is
# common in legitimate native-extension builds, so it is a weaker indicator.
CONFIDENCE_ACTIVE = 0.85
CONFIDENCE_SHELL = 0.7
# A build script that only runs a process with ordinary arguments is usually calling a compiler.
CONFIDENCE_PROCESS_ONLY = 0.5
CONFIDENCE_CMDCLASS_ONLY = 0.6
CONFIDENCE_UNPARSEABLE = 0.6

_ACTIVE, _CMDCLASS = "active", "cmdclass"


def _import_kind(module: str) -> str:
    """Which behaviour an imported capability module implies."""
    if module in _NETWORK_MODULES:
        return KIND_NETWORK
    if module == "ctypes":
        return KIND_NATIVE
    return KIND_PROCESS


def _call_kinds(node: ast.Call, fn: ast.Attribute) -> set[str]:
    """Classify one attribute call inside a build script."""
    kinds: set[str] = set()
    attr = fn.attr
    root = fn.value.id if isinstance(fn.value, ast.Name) else None
    if attr in _NETWORK_ATTRS and root not in {"os", "subprocess"}:
        kinds.add(KIND_NETWORK)
    if attr in _PROCESS_ATTRS:
        kinds.add(KIND_PROCESS)
        shell = any(kw.arg == "shell" and getattr(kw.value, "value", False) is True for kw in node.keywords)
        if shell or attr in _SHELL_ATTRS:
            kinds.add(KIND_SHELL)
    if attr in _DECODER_ATTRS:
        kinds.add(KIND_DYNAMIC)
    return kinds


def _grade(kinds: set[str]) -> tuple[Severity, float, float, str]:
    """Severity, weight, confidence and message for the observed install-time behaviour."""
    if KIND_NETWORK in kinds or KIND_DYNAMIC in kinds:
        return (Severity.critical, 12.0, CONFIDENCE_ACTIVE,
                "setup.py fetches or evaluates content at install time - classic install-time RCE vector")
    if KIND_SHELL in kinds:
        return (Severity.high, 7.0, CONFIDENCE_SHELL,
                "setup.py runs a shell command at install time")
    if KIND_NATIVE in kinds:
        return (Severity.high, 6.0, CONFIDENCE_SHELL,
                "setup.py loads a native library at install time")
    # Process execution with ordinary arguments: how native extensions invoke their compiler.
    return (Severity.medium, 5.0, CONFIDENCE_PROCESS_ONLY,
            "setup.py runs a process at install time (common in native-extension builds)")

class InstallScriptAnalyzer(BaseAnalyzer):
    name = "install_script"
    version = ANALYZER_VERSION

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        build_files = ctx.find("setup.py")
        if not build_files:
            return []

        signals: list[Signal] = []
        for f in build_files:
            locations = LocationCollector()
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
                # Pathologically nested source makes the parser raise RecursionError or
                # MemoryError ("parser stack overflowed"); it is handled like a syntax error:
                # an unparseable build script is evidence, never a crash.
                line = exc.lineno if isinstance(exc, SyntaxError) and isinstance(exc.lineno, int) else None
                locations.add(Code.UNPARSEABLE, 0, f.relpath, line)
                signals.append(Signal(
                    Code.UNPARSEABLE, Severity.medium, 3.0,
                    f"{f.relpath} could not be parsed",
                    {"file": f.relpath, "locations": locations.evidence(Code.UNPARSEABLE)},
                    confidence=CONFIDENCE_UNPARSEABLE, location=locations.first(Code.UNPARSEABLE),
                ))
                continue

            suspicious_calls: list[str] = []
            cap_imports: set[str] = set()
            kinds: set[str] = set()
            has_install_hook = False

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        top = a.name.split(".")[0]
                        if top in _CAP_MODULES:
                            cap_imports.add(top)
                            if top in _ACTIVE_MODULES:
                                kinds.add(_import_kind(top))
                                locations.add_node(_ACTIVE, 0, f.relpath, node)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top = node.module.split(".")[0]
                    if top in _CAP_MODULES:
                        cap_imports.add(top)
                        if top in _ACTIVE_MODULES:
                            kinds.add(_import_kind(top))
                            locations.add_node(_ACTIVE, 0, f.relpath, node)
                elif isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name) and fn.id in _DYNAMIC:
                        suspicious_calls.append(fn.id)
                        kinds.add(KIND_DYNAMIC)
                        locations.add_node(_ACTIVE, 0, f.relpath, node)
                    if isinstance(fn, ast.Attribute) and fn.attr in _SUSPICIOUS_ATTRS:
                        suspicious_calls.append(fn.attr)
                        kinds.update(_call_kinds(node, fn))
                        locations.add_node(_ACTIVE, 0, f.relpath, node)
                # cmdclass=... hooking install/develop
                elif isinstance(node, ast.keyword) and node.arg == "cmdclass":
                    has_install_hook = True
                    locations.add_node(_CMDCLASS, 0, f.relpath, node)

            # Grade by what the build script actually does (see the kind constants above).
            if suspicious_calls or cap_imports & _ACTIVE_MODULES:
                severity, weight, confidence, description = _grade(kinds)
                signals.append(Signal(
                    Code.INSTALL_HOOK_EXEC, severity, weight, description,
                    {"file": f.relpath,
                     "kinds": sorted(kinds),
                     "capability_imports": sorted(cap_imports),
                     "calls": sorted(set(suspicious_calls))[:8],
                     "locations": locations.evidence(_ACTIVE)},
                    capability=Capability.INSTALL_EXEC,
                    confidence=confidence, location=locations.first(_ACTIVE),
                ))
            elif has_install_hook:
                signals.append(Signal(
                    Code.INSTALL_HOOK_EXEC, Severity.high, 6.0,
                    "setup.py overrides install/develop commands (cmdclass hook)",
                    {"file": f.relpath, "locations": locations.evidence(_CMDCLASS)},
                    capability=Capability.INSTALL_EXEC,
                    confidence=CONFIDENCE_CMDCLASS_ONLY, location=locations.first(_CMDCLASS),
                ))
        return signals
