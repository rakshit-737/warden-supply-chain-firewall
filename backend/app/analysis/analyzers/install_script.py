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

ANALYZER_VERSION = "1.1.0"

_CAP_MODULES = {"socket", "subprocess", "requests", "urllib", "os", "ctypes", "base64", "http"}
# Capability imports that on their own make a build script "active" (os/base64 do not).
_ACTIVE_MODULES = {"socket", "subprocess", "requests", "urllib", "http", "ctypes"}
_DYNAMIC = {"eval", "exec", "compile", "__import__"}
_SUSPICIOUS_ATTRS = {"system", "popen", "run", "Popen", "check_output", "urlopen", "get", "post"}

# Active behaviour in setup.py is strong structural evidence; a cmdclass override alone is
# common in legitimate native-extension builds, so it is a weaker indicator.
CONFIDENCE_ACTIVE = 0.85
CONFIDENCE_CMDCLASS_ONLY = 0.6
CONFIDENCE_UNPARSEABLE = 0.6

_ACTIVE, _CMDCLASS = "active", "cmdclass"


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
            has_install_hook = False

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        top = a.name.split(".")[0]
                        if top in _CAP_MODULES:
                            cap_imports.add(top)
                            if top in _ACTIVE_MODULES:
                                locations.add_node(_ACTIVE, 0, f.relpath, node)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top = node.module.split(".")[0]
                    if top in _CAP_MODULES:
                        cap_imports.add(top)
                        if top in _ACTIVE_MODULES:
                            locations.add_node(_ACTIVE, 0, f.relpath, node)
                elif isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name) and fn.id in _DYNAMIC:
                        suspicious_calls.append(fn.id)
                        locations.add_node(_ACTIVE, 0, f.relpath, node)
                    if isinstance(fn, ast.Attribute) and fn.attr in _SUSPICIOUS_ATTRS:
                        suspicious_calls.append(fn.attr)
                        locations.add_node(_ACTIVE, 0, f.relpath, node)
                # cmdclass=... hooking install/develop
                elif isinstance(node, ast.keyword) and node.arg == "cmdclass":
                    has_install_hook = True
                    locations.add_node(_CMDCLASS, 0, f.relpath, node)

            # A build script that pulls in capability modules or executes commands at
            # install time is high-to-critical risk.
            if suspicious_calls or cap_imports & _ACTIVE_MODULES:
                signals.append(Signal(
                    Code.INSTALL_HOOK_EXEC, Severity.critical, 12.0,
                    "setup.py performs active behaviour at install time "
                    "(network/process/eval) — classic install-time RCE vector",
                    {"file": f.relpath,
                     "capability_imports": sorted(cap_imports),
                     "calls": sorted(set(suspicious_calls))[:8],
                     "locations": locations.evidence(_ACTIVE)},
                    capability=Capability.INSTALL_EXEC,
                    confidence=CONFIDENCE_ACTIVE, location=locations.first(_ACTIVE),
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
