"""Policy engine.

Maps a scored analysis result to an enforcement ``decision`` (allow / warn / block) given
the active organisational ``Policy``. Decisions are explainable: the engine returns the
exact list of rules that fired, which the CLI prints and the dashboard displays.

Evaluation order (first decisive rule wins for BLOCK):
1. explicit denylist  -> BLOCK
2. explicit allowlist -> ALLOW (overrides score-based warn/block, but never a hard IOC)
3. matched blocked-capability -> BLOCK
4. score >= block_threshold -> BLOCK
5. min-age violation -> BLOCK
6. score >= warn_threshold -> WARN
7. otherwise -> ALLOW

Note the deliberate exception: an IOC / known-malware match is never overridden by an
allowlist entry — allowlisting a name should not whitelist active malware served under it.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.orchestrator import AnalysisResult
from app.analysis.signals import Capability, Code
from app.db.models import Decision, Policy


@dataclass
class PolicyDecision:
    decision: Decision
    matched_rules: list[str]


# Sensible built-in default used when no policy row exists yet.
DEFAULT_POLICY = dict(
    warn_threshold=40,
    block_threshold=70,
    min_package_age_days=0,
    blocked_capabilities=[Capability.INSTALL_EXEC, Capability.IOC],
    allowlist=[],
    denylist=[],
)


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def evaluate(result: AnalysisResult, policy: Policy | None) -> PolicyDecision:
    warn_t = policy.warn_threshold if policy else DEFAULT_POLICY["warn_threshold"]
    block_t = policy.block_threshold if policy else DEFAULT_POLICY["block_threshold"]
    min_age = policy.min_package_age_days if policy else DEFAULT_POLICY["min_package_age_days"]
    blocked_caps = set(policy.blocked_capabilities if policy else DEFAULT_POLICY["blocked_capabilities"])
    allowlist = {_normalize(x) for x in (policy.allowlist if policy else [])}
    denylist = {_normalize(x) for x in (policy.denylist if policy else [])}

    name = _normalize(result.name)
    caps = set(result.capabilities)
    matched: list[str] = []

    # A hard malware/IOC hit is non-overridable.
    hard_malware = Capability.IOC in caps or any(
        s["code"] == Code.IOC_MATCH for s in result.signals
    )

    if name in denylist:
        matched.append("denylist")
        return PolicyDecision(Decision.block, matched)

    if hard_malware:
        matched.append("known_malicious_indicator")
        return PolicyDecision(Decision.block, matched)

    if name in allowlist:
        matched.append("allowlist")
        return PolicyDecision(Decision.allow, matched)

    blocked_hit = caps & blocked_caps
    if blocked_hit:
        matched.extend(f"blocked_capability:{c}" for c in sorted(blocked_hit))
        return PolicyDecision(Decision.block, matched)

    if result.risk_score >= block_t:
        matched.append("block_threshold")
        return PolicyDecision(Decision.block, matched)

    # Minimum-age enforcement (feature is inverted proximity; use the raw metadata age
    # via the NEW_PACKAGE signal evidence when present).
    if min_age > 0:
        age_days = _extract_age_days(result)
        if age_days is not None and age_days < min_age:
            matched.append("min_package_age")
            return PolicyDecision(Decision.block, matched)

    if result.risk_score >= warn_t:
        matched.append("warn_threshold")
        return PolicyDecision(Decision.warn, matched)

    matched.append("clean")
    return PolicyDecision(Decision.allow, matched)


def _extract_age_days(result: AnalysisResult) -> float | None:
    for s in result.signals:
        if s["code"] == Code.NEW_PACKAGE:
            return s.get("evidence", {}).get("age_days")
    return None
