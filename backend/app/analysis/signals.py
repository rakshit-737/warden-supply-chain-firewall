"""Signal taxonomy.

A ``Signal`` is a single, explainable observation produced by one analyzer. Signals are
the common currency of the pipeline: analyzers emit them, the feature builder reduces them
to a numeric vector, the rule scorer sums their weights, and the policy engine matches on
their ``code`` and ``capability``. Keeping this one small, typed object at the centre is
what makes the whole system explainable end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass(frozen=True)
class Signal:
    code: str
    severity: Severity
    weight: float
    message: str
    evidence: dict = field(default_factory=dict)
    # Optional capability tag used by the policy engine for hard capability blocks.
    capability: str | None = None

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "weight": self.weight,
            "message": self.message,
            "evidence": self.evidence,
            "capability": self.capability,
        }


# Canonical signal codes (kept centralised so policies and tests reference constants).
class Code:
    # metadata
    NEW_PACKAGE = "NEW_PACKAGE"
    SINGLE_MAINTAINER = "SINGLE_MAINTAINER"
    NO_SOURCE_REPO = "NO_SOURCE_REPO"
    RELEASE_FLOOD = "RELEASE_FLOOD"
    VERSION_NOT_FOUND = "VERSION_NOT_FOUND"
    # static code
    INSTALL_HOOK_EXEC = "INSTALL_HOOK_EXEC"
    NETWORK_EGRESS = "NETWORK_EGRESS"
    SUBPROCESS_EXEC = "SUBPROCESS_EXEC"
    DYNAMIC_EXEC = "DYNAMIC_EXEC"
    ENV_HARVEST = "ENV_HARVEST"
    FS_SENSITIVE = "FS_SENSITIVE"
    DANGEROUS_IMPORT = "DANGEROUS_IMPORT"
    # obfuscation
    OBFUSCATION = "OBFUSCATION"
    ENCODED_EXEC = "ENCODED_EXEC"
    # typosquat
    TYPOSQUAT = "TYPOSQUAT"
    # ioc
    IOC_MATCH = "IOC_MATCH"
    # pipeline / fail-safe
    FETCH_FAILED = "FETCH_FAILED"
    EXTRACTION_ABORTED = "EXTRACTION_ABORTED"
    UNPARSEABLE = "UNPARSEABLE"


# Capability tags for policy hard-blocks.
class Capability:
    INSTALL_EXEC = "install_hook_exec"
    NETWORK = "network_egress"
    SUBPROCESS = "subprocess_exec"
    DYNAMIC_EXEC = "dynamic_exec"
    ENV_HARVEST = "env_harvest"
    OBFUSCATION = "obfuscation"
    TYPOSQUAT = "typosquat"
    IOC = "ioc"
