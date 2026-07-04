"""Analysis orchestrator.

Ties the pipeline together: cache lookup -> fetch -> run analyzers -> score. Returns a
plain, serialisable ``AnalysisResult`` that the API layer persists and the policy engine
consumes. The orchestrator owns caching and timing but contains no HTTP or DB code, which
keeps it unit-testable in isolation (see tests/test_scoring_policy.py, tests/test_api_scans.py).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field

from app.analysis.analyzers import ALL_ANALYZERS
from app.analysis.fetcher import RegistryFetcher
from app.analysis.scoring import RiskResult, score
from app.analysis.signals import Signal
from app.core.cache import cache
from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("warden.orchestrator")


@dataclass
class AnalysisResult:
    ecosystem: str
    name: str
    version: str
    rule_score: int
    ml_score: int
    risk_score: int
    severity: str
    features: dict
    signals: list[dict]
    analyzer_version: str
    duration_ms: int
    ml_available: bool
    cached: bool = False
    capabilities: list[str] = field(default_factory=list)


def _cache_key(ecosystem: str, name: str, version: str | None) -> str:
    raw = f"{ecosystem}:{name}:{version or 'latest'}:{settings.ANALYZER_VERSION}"
    return "verdict:" + hashlib.sha256(raw.encode()).hexdigest()


class Orchestrator:
    def __init__(self, fetcher: RegistryFetcher | None = None) -> None:
        # Lazily instantiated so constructing the orchestrator (done at import in the
        # router) performs no network-client setup.
        self._fetcher_override = fetcher
        self._fetcher_instance: RegistryFetcher | None = None

    @property
    def _fetcher(self) -> RegistryFetcher:
        if self._fetcher_override is not None:
            return self._fetcher_override
        if self._fetcher_instance is None:
            self._fetcher_instance = RegistryFetcher()
        return self._fetcher_instance

    def analyze(self, ecosystem: str, name: str, version: str | None) -> AnalysisResult:
        key = _cache_key(ecosystem, name, version)
        cached = cache.get_json(key)
        if cached:
            cached["cached"] = True
            return AnalysisResult(**cached)

        start = time.perf_counter()
        ctx = self._fetcher.build_context(name, version)

        signals: list[Signal] = list(ctx.context_signals)
        for analyzer in ALL_ANALYZERS:
            try:
                signals.extend(analyzer.analyze(ctx))
            except Exception as exc:  # one bad analyzer must not fail the whole scan
                log.error("analyzer_error", analyzer=analyzer.name, error=str(exc))

        result: RiskResult = score(signals, ctx)
        capabilities = sorted({s.capability for s in signals if s.capability})
        duration_ms = int((time.perf_counter() - start) * 1000)

        out = AnalysisResult(
            ecosystem=ecosystem,
            name=name,
            version=ctx.version,
            rule_score=result.rule_score,
            ml_score=result.ml_score,
            risk_score=result.risk_score,
            severity=result.severity.value,
            features=result.features,
            signals=[s.to_dict() for s in signals],
            analyzer_version=settings.ANALYZER_VERSION,
            duration_ms=duration_ms,
            ml_available=result.ml_available,
            capabilities=capabilities,
        )
        cache.set_json(key, asdict(out), settings.VERDICT_CACHE_TTL_SECONDS)
        log.info(
            "scan_complete", package=name, version=ctx.version,
            risk=out.risk_score, severity=out.severity, duration_ms=duration_ms,
        )
        return out
