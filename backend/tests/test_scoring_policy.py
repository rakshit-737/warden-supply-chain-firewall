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


def test_ml_inference_is_timed_only_when_a_model_is_available(monkeypatch):
    from contextlib import contextmanager

    from app.analysis import scoring

    timed: list[str] = []

    @contextmanager
    def fake_time_ml():
        timed.append("inference")
        yield

    class _Model:
        def __init__(self, available: bool) -> None:
            self.available = available

        def predict(self, f):
            return (40, 0.5) if self.available else (0, 0.0)

    class _Ctx:
        metadata = {}

    monkeypatch.setattr(scoring.metrics, "time_ml", fake_time_ml)
    monkeypatch.setattr(scoring, "get_model_store", lambda: _Model(False))
    score([], _Ctx())
    assert timed == []  # the rules-only fallback is not an inference
    monkeypatch.setattr(scoring, "get_model_store", lambda: _Model(True))
    result = score([], _Ctx())
    assert timed == ["inference"] and result.ml_score == 40 and result.risk_score == 40


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


# --------------------------------------------------------------------------- policy engine v2 (additive)
def test_v1_evaluate_call_also_returns_the_v2_decision_fields():
    d = evaluate(_result(85), _policy())
    assert d.reasons[0]["rule"] == "block_threshold" and d.reasons[0]["effect"] == "block"
    assert d.exceptions_applied == [] and len(d.policy_hash) == 64
    assert evaluate(_result(85), _policy()).to_dict() == d.to_dict()


def test_v1_policy_decision_can_still_be_built_positionally():
    from app.policy.engine import PolicyDecision

    d = PolicyDecision(Decision.allow, ["clean"])
    assert d.reasons == [] and d.exceptions_applied == [] and d.policy_hash is None


def test_missing_policy_row_uses_the_default_policy():
    d = evaluate(_result(10, caps=[Capability.INSTALL_EXEC]), None)
    assert d.decision == Decision.block and d.matched_rules == ["blocked_capability:install_hook_exec"]
    assert evaluate(_result(10), None).matched_rules == ["clean"]


def test_allowlisted_package_with_high_score_is_allowed_without_ioc():
    d = evaluate(_result(95, caps=[], name="Pkg_Name"), _policy(allowlist=["pkg-name"], blocked_capabilities=[]))
    assert d.decision == Decision.allow and d.matched_rules == ["allowlist"]
