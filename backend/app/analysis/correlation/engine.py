"""Attack-chain correlation engine — interface stub.

The attack-chain correlation engine is implemented in phase 2. It is intended to combine
individual findings (for example install-time execution + credential access + network
egress) into ordered attack chains and emit derived ``ATTACK_CHAIN`` findings that reference
their inputs via ``Finding.related``.

Until then ``correlate`` deliberately returns an empty result: it produces **no** chains and
**no** findings, so nothing downstream should interpret its output as "no attack chain
exists". The orchestrator already calls it at the correct pipeline stage, so the phase-2
implementation only has to replace this function body.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from app.analysis.findings import Finding

VERSION = "0.0.0-stub"


@dataclass
class CorrelationResult:
    # Serialisable chain descriptions (dicts, or objects exposing ``to_dict()``).
    chains: list = field(default_factory=list)
    # Derived findings (e.g. ``ATTACK_CHAIN``) to append to the scan's findings.
    findings: list[Finding] = field(default_factory=list)


def correlate(findings: Sequence[Finding]) -> CorrelationResult:
    """Stub: returns no chains and no findings (correlation is implemented in phase 2)."""
    return CorrelationResult(chains=[], findings=[])
