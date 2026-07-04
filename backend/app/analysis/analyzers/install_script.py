"""Install-time execution analyzer.

The single most dangerous behaviour in the Python packaging ecosystem is code that runs
during ``pip install`` — before any test, review, or import. This analyzer looks
specifically at ``setup.py`` and PEP 517 build hooks and flags:

* arbitrary statements at module top level beyond the conventional ``setup(...)`` call,
* imports of process/network/eval capabilities inside the build script,
* ``cmdclass`` overrides that hook ``install``/``develop`` to run custom code.

A setup.py that merely calls ``setup(...)`` with static metadata is benign; one that
opens a socket or spawns a shell at import time is the classic supply-chain payload.
"""

from __future__ import annotations

import ast

from app.analysis.analyzers.base import PackageContext
from app.analysis.signals import Capability, Code, Severity, Signal

_CAP_MODULES = {"socket", "subprocess", "requests", "urllib", "os", "ctypes", "base64", "http"}
_DYNAMIC = {"eval", "exec", "compile", "__import__"}


class InstallScriptAnalyzer:
    name = "install_script"

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        build_files = ctx.find("setup.py")
        if not build_files:
            return []

        signals: list[Signal] = []
        for f in build_files:
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError):
                signals.append(Signal(
                    Code.UNPARSEABLE, Severity.medium, 3.0,
                    f"{f.relpath} could not be parsed", {"file": f.relpath},
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
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top = node.module.split(".")[0]
                    if top in _CAP_MODULES:
                        cap_imports.add(top)
                elif isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name) and fn.id in _DYNAMIC:
                        suspicious_calls.append(fn.id)
                    if isinstance(fn, ast.Attribute) and fn.attr in {
                        "system", "popen", "run", "Popen", "check_output", "urlopen", "get", "post"
                    }:
                        suspicious_calls.append(fn.attr)
                # cmdclass=... hooking install/develop
                elif isinstance(node, ast.keyword) and node.arg == "cmdclass":
                    has_install_hook = True

            # A build script that pulls in capability modules or executes commands at
            # install time is high-to-critical risk.
            if suspicious_calls or cap_imports & {"socket", "subprocess", "requests", "urllib", "http", "ctypes"}:
                signals.append(Signal(
                    Code.INSTALL_HOOK_EXEC, Severity.critical, 12.0,
                    "setup.py performs active behaviour at install time "
                    "(network/process/eval) — classic install-time RCE vector",
                    {"file": f.relpath,
                     "capability_imports": sorted(cap_imports),
                     "calls": sorted(set(suspicious_calls))[:8]},
                    capability=Capability.INSTALL_EXEC,
                ))
            elif has_install_hook:
                signals.append(Signal(
                    Code.INSTALL_HOOK_EXEC, Severity.high, 6.0,
                    "setup.py overrides install/develop commands (cmdclass hook)",
                    {"file": f.relpath},
                    capability=Capability.INSTALL_EXEC,
                ))
        return signals
