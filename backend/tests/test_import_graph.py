"""Import-graph integration tests.

The analyzer registry (``app.analysis.analyzers``) imports every built-in analyzer, and some
analyzers depend on modules (``acquisition.pypi``, ``extraction.safe_archive``) that themselves
import ``app.analysis.analyzers.base`` — which initialises the registry package first. That is a
legal cycle only while no module in it does ``from <partially initialised module> import name``.
Inside one pytest process every module is already imported, so a regression is invisible; these
tests import each entry point *first* in a fresh interpreter, the way a worker, the CLI or a
one-off script would.
"""

from __future__ import annotations

import concurrent.futures as cf
import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
# Every module that participates in the registry cycle, plus the composition roots.
ENTRY_POINTS = (
    "app.analysis.acquisition.pypi",
    "app.analysis.acquisition",
    "app.analysis.extraction.safe_archive",
    "app.analysis.extraction",
    "app.analysis.analyzers.base",
    "app.analysis.analyzers.inventory",
    "app.analysis.analyzers.vulnerability",
    "app.analysis.analyzers",
    "app.analysis.fetcher",
    "app.analysis.orchestrator",
)


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    # The child imports app modules only; keep it offline and point Redis at a closed loopback port.
    env.update(INTEL_OFFLINE="true", PROVENANCE_ENABLED="false", ENV="development",
               REDIS_URL="redis://127.0.0.1:1/0", PYTHONDONTWRITEBYTECODE="1")
    return env


def _import_first(module: str) -> subprocess.CompletedProcess[str]:
    code = f"import {module}"
    return subprocess.run(
        [sys.executable, "-c", code], cwd=BACKEND, env=_child_env(), capture_output=True, text=True, timeout=180,
    )


def test_every_registry_cycle_member_imports_first_in_a_fresh_interpreter() -> None:
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(zip(ENTRY_POINTS, pool.map(_import_first, ENTRY_POINTS)))
    failures = {m: r.stderr.strip().splitlines()[-1:] for m, r in results.items() if r.returncode != 0}
    assert failures == {}


@pytest.mark.parametrize("first", ["app.analysis.extraction.safe_archive", "app.analysis.acquisition.pypi"])
def test_registry_lists_warden_x_analyzers_whatever_is_imported_first(first: str) -> None:
    code = (
        f"import {first}\n"
        "from app.analysis import analyzers as r\n"
        "print(','.join(a.name for a in r.ALL_ANALYZERS))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], cwd=BACKEND, env=_child_env(), capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    names = proc.stdout.strip().splitlines()[-1].split(",")
    assert names[:6] == ["metadata", "typosquat", "static_code", "install_script", "obfuscation", "ioc"]
    assert {"inventory", "vulnerability"} <= set(names)
