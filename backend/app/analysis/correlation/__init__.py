"""Attack-chain correlation: declarative chain templates (``chains``) and the engine (``engine``)."""

from app.analysis.correlation.chains import TEMPLATES, BoosterSpec, ChainTemplate, StepSpec
from app.analysis.correlation.engine import VERSION, AttackChain, ChainStep, CorrelationResult, correlate

__all__ = [
    "TEMPLATES",
    "VERSION",
    "AttackChain",
    "BoosterSpec",
    "ChainStep",
    "ChainTemplate",
    "CorrelationResult",
    "StepSpec",
    "correlate",
]
