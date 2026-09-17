"""Analyzer registry.

``ALL_ANALYZERS`` is the ordered list of registered analyzer *instances* (kept under its v1
name for compatibility). Analyzers are shared across concurrent scans, so they must be
stateless: all per-scan state lives in local variables of ``analyze``.

``get_analyzers()`` returns the analyzers a scan should run, honouring
``settings.ENABLED_ANALYZERS`` (empty = all registered) and ``settings.DISABLED_ANALYZERS``.
Names are matched case-insensitively with ``-`` and ``_`` treated as equal. Registry order
is preserved because the orchestrator emits findings in registry order, which keeps scan
output deterministic even though analyzers run concurrently.

Built-in analyzers are listed in ``ALL_ANALYZERS`` below: the six v1 analyzers first (their
order is a compatibility contract), then the Warden analyzers. Constructing them performs
no I/O; the vulnerability analyzer resolves its intelligence service lazily and is skipped by
the orchestrator in offline scans (``requires_network``). Further analyzers (e.g. optional
external-tool adapters) can be added at runtime with :func:`register_analyzer`.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.analysis.analyzers.base import Analyzer, BaseAnalyzer, PackageContext
from app.analysis.analyzers.dependency_confusion import DependencyConfusionAnalyzer
from app.analysis.analyzers.install_script import InstallScriptAnalyzer
from app.analysis.analyzers.install_vectors import InstallVectorsAnalyzer
from app.analysis.analyzers.inventory import InventoryAnalyzer
from app.analysis.analyzers.ioc import IOCAnalyzer
from app.analysis.analyzers.metadata import MetadataAnalyzer
from app.analysis.analyzers.obfuscation import ObfuscationAnalyzer
from app.analysis.analyzers.provenance import ProvenanceAnalyzer
from app.analysis.analyzers.secrets import SecretsAnalyzer
from app.analysis.analyzers.semgrep_scan import SemgrepAnalyzer
from app.analysis.analyzers.static_code import StaticCodeAnalyzer
from app.analysis.analyzers.typosquat import TyposquatAnalyzer
from app.analysis.analyzers.vulnerability import VulnerabilityAnalyzer
from app.analysis.analyzers.yara_scan import YaraScanAnalyzer
from app.core.logging import get_logger

log = get_logger("warden.analyzers")

# Order is informational for detection (analyzers are independent) but defines the order
# in which findings are reported.
ALL_ANALYZERS: list[Analyzer] = [
    MetadataAnalyzer(),
    TyposquatAnalyzer(),
    StaticCodeAnalyzer(),
    InstallScriptAnalyzer(),
    ObfuscationAnalyzer(),
    IOCAnalyzer(),
    # Warden 2 analyzers. Names must match app.analysis.risk.DIMENSION_ANALYZERS /
    # VULNERABILITY_ANALYZER_NAMES so their dimensions read as "examined" when they ran.
    InventoryAnalyzer(),
    InstallVectorsAnalyzer(),
    SecretsAnalyzer(),
    DependencyConfusionAnalyzer(),
    ProvenanceAnalyzer(),
    # Optional external-tool layers: they report themselves unavailable (and the orchestrator
    # records TOOL_UNAVAILABLE) when the tool is not installed, rather than silently finding nothing.
    YaraScanAnalyzer(),
    SemgrepAnalyzer(),
    VulnerabilityAnalyzer(),
]


def normalize_analyzer_name(name: str) -> str:
    return str(name).strip().lower().replace("-", "_")


def all_analyzers() -> list[Analyzer]:
    """Every registered analyzer, enabled or not (a copy; mutate via register_analyzer)."""
    return list(ALL_ANALYZERS)


def register_analyzer(analyzer: Analyzer, *, replace: bool = False) -> Analyzer:
    """Append ``analyzer`` to the registry.

    Raises ``ValueError`` if an analyzer with the same (normalised) name is already
    registered, unless ``replace`` is true, in which case it takes the existing slot.
    """
    name = getattr(analyzer, "name", None)
    if not isinstance(name, str) or not name.strip():
        raise ValueError("analyzer must have a non-empty string 'name'")
    if not callable(getattr(analyzer, "analyze", None)):
        raise ValueError(f"analyzer {name!r} has no callable analyze()")
    key = normalize_analyzer_name(name)
    for i, existing in enumerate(ALL_ANALYZERS):
        if normalize_analyzer_name(existing.name) == key:
            if not replace:
                raise ValueError(f"analyzer already registered: {name}")
            ALL_ANALYZERS[i] = analyzer
            return analyzer
    ALL_ANALYZERS.append(analyzer)
    return analyzer


def get_analyzers(
    enabled: Iterable[str] | None = None,
    disabled: Iterable[str] | None = None,
) -> list[Analyzer]:
    """Registered analyzers filtered by the enable/disable lists (settings by default).

    An enabled name that matches no registered analyzer is logged, not silently ignored:
    a typo in ``ENABLED_ANALYZERS`` would otherwise quietly switch analysis layers off.
    """
    if enabled is None or disabled is None:
        from app.core.config import settings

        enabled = settings.ENABLED_ANALYZERS if enabled is None else enabled
        disabled = settings.DISABLED_ANALYZERS if disabled is None else disabled
    wanted = {normalize_analyzer_name(n) for n in enabled if str(n).strip()}
    blocked = {normalize_analyzer_name(n) for n in disabled if str(n).strip()}

    registered = {normalize_analyzer_name(a.name) for a in ALL_ANALYZERS}
    unknown = sorted(wanted - registered)
    if unknown:
        log.warning("unknown_enabled_analyzers", names=unknown)

    selected: list[Analyzer] = []
    for analyzer in ALL_ANALYZERS:
        key = normalize_analyzer_name(analyzer.name)
        if wanted and key not in wanted:
            continue
        if key in blocked:
            continue
        selected.append(analyzer)
    return selected


__all__ = [
    "ALL_ANALYZERS",
    "Analyzer",
    "BaseAnalyzer",
    "PackageContext",
    "all_analyzers",
    "get_analyzers",
    "normalize_analyzer_name",
    "register_analyzer",
]
