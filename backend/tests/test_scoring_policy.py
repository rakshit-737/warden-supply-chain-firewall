from app.analysis.orchestrator import AnalysisResult
from app.analysis.scoring import compute_rule_score, score
from app.analysis.signals import Capability, Code, Severity, Signal
from app.db.models import Decision, Policy
from app.policy.engine import DEFAULT_POLICY, evaluate


def _sig(code, sev, w, cap=None):
    return Signal(code, sev, w, code, {}, capability=cap)


def test_rule_score_monotonic():
    low = [_sig(Code.NEW_PACKAGE, Severity.low, 2.0)]
    high = low + [_sig(Code.INSTALL_HOOK_EXEC, Severity.critical, 10.0, Capability.INSTALL_EXEC)]
    assert compute_rule_score(high) > compute_rule_score(low)


def test_rule_score_capped_at_100():
    huge = [_sig(Code.IOC_MATCH, Severity.critical, 100.0)] * 5
    assert compute_rule_score(huge) == 100


def test_support_signals_alone_cannot_reach_high():
    # Many generic capability signals (network, subprocess, dynamic, imports, provenance)
    # must stay out of the "high" band (>=60) — this is the false-positive control.
    support = [
        _sig(Code.NETWORK_EGRESS, Severity.low, 1.5, Capability.NETWORK),
        _sig(Code.SUBPROCESS_EXEC, Severity.medium, 3.0, Capability.SUBPROCESS),
        _sig(Code.DYNAMIC_EXEC, Severity.medium, 4.0, Capability.DYNAMIC_EXEC),
        _sig(Code.DANGEROUS_IMPORT, Severity.low, 2.0),
        _sig(Code.NEW_PACKAGE, Severity.low, 2.0),
        _sig(Code.SINGLE_MAINTAINER, Severity.low, 1.5),
    ]
    assert compute_rule_score(support) < 60


def test_single_primary_indicator_reaches_high():
    # One real malicious indicator (install-time exec) must reach the high band alone.
    primary = [_sig(Code.INSTALL_HOOK_EXEC, Severity.critical, 12.0, Capability.INSTALL_EXEC)]
    assert compute_rule_score(primary) >= 50


def test_score_uses_rules_when_model_absent(monkeypatch):
    # Force model-unavailable path.
    from app.analysis import scoring

    class _NoModel:
        available = False
        def predict(self, f):  # noqa: D401
            return 0, 0.0

    monkeypatch.setattr(scoring, "get_model_store", lambda: _NoModel())
    signals = [_sig(Code.TYPOSQUAT, Severity.high, 9.0, Capability.TYPOSQUAT)]

    class _Ctx:
        metadata = {}

    result = score(signals, _Ctx())
    assert result.risk_score == result.rule_score
    assert result.ml_available is False


def _result(risk, caps=None, name="pkg", signals=None):
    return AnalysisResult(
        ecosystem="pypi", name=name, version="1.0", rule_score=risk, ml_score=risk,
        risk_score=risk, severity="high", features={}, signals=signals or [],
        analyzer_version="1.0.0", duration_ms=1, ml_available=True,
        capabilities=caps or [],
    )


def _policy(**kw):
    base = dict(DEFAULT_POLICY)
    base.update(kw)
    return Policy(name="t", is_active=True, **base)


def test_block_threshold():
    d = evaluate(_result(85), _policy())
    assert d.decision == Decision.block and "block_threshold" in d.matched_rules


def test_warn_threshold():
    d = evaluate(_result(50, caps=[]), _policy(blocked_capabilities=[]))
    assert d.decision == Decision.warn


def test_blocked_capability_forces_block_even_if_low_score():
    d = evaluate(_result(10, caps=[Capability.INSTALL_EXEC]), _policy())
    assert d.decision == Decision.block


def test_denylist_blocks():
    d = evaluate(_result(0, name="evilpkg"), _policy(denylist=["evilpkg"]))
    assert d.decision == Decision.block


def test_allowlist_allows_but_not_over_ioc():
    ioc_signal = [{"code": Code.IOC_MATCH, "severity": "critical", "weight": 10,
                   "message": "x", "evidence": {}}]
    d = evaluate(
        _result(90, caps=[Capability.IOC], name="pkg", signals=ioc_signal),
        _policy(allowlist=["pkg"]),
    )
    assert d.decision == Decision.block  # IOC is non-overridable
