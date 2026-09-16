"""Declarative attack-chain templates for the correlation engine.

A :class:`ChainTemplate` describes one attack pattern as an ordered list of
:class:`StepSpec` s. Each step names the MITRE ATT&CK tactic/technique it corresponds to and
the finding codes that can satisfy it. ``required`` steps must all be satisfied for the
template to match; optional steps are shown in the chain when a finding satisfies them.
:class:`BoosterSpec` groups raise the chain's confidence when a finding matches them (see
:mod:`app.analysis.correlation.engine` for the confidence formula and emission guards).

Several patterns have more than one acceptable shape (for example an install-time dropper
is either "install vector + download-and-execute finding" or "install vector + network +
process execution in the same file"). Each shape is a separate template *variant* sharing
the same ``chain_id``; the engine reports at most one chain per ``chain_id``.

Templates are data, not detectors: they are designed to surface combinations of findings
that analyzers have already produced. They cannot find behaviour no analyzer reported.

ATT&CK identifiers used here must exist in :data:`app.analysis.taxonomy.ATTACK_TECHNIQUES`;
:func:`validate_templates` enforces that (and other structural rules) at import time.
Tactics use the ATT&CK enterprise tactic names in snake_case.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from app.analysis import taxonomy
from app.analysis.findings import Severity
from app.analysis.signals import Code

# --------------------------------------------------------------------------- vocabulary
INITIAL_ACCESS = "initial_access"
EXECUTION = "execution"
PERSISTENCE = "persistence"
DEFENSE_EVASION = "defense_evasion"
CREDENTIAL_ACCESS = "credential_access"
COMMAND_AND_CONTROL = "command_and_control"
EXFILTRATION = "exfiltration"
TACTICS = frozenset({
    INITIAL_ACCESS, EXECUTION, PERSISTENCE, DEFENSE_EVASION, CREDENTIAL_ACCESS, COMMAND_AND_CONTROL, EXFILTRATION,
})

# Step kinds. Only ``behavior`` steps take part in file co-location: ``identity`` steps describe
# the package name / registry history (no source file) and ``artifact`` steps describe shipped
# files (a binary is never "in the same file" as the code that loads it).
BEHAVIOR = "behavior"
IDENTITY = "identity"
ARTIFACT = "artifact"
STEP_KINDS = frozenset({BEHAVIOR, IDENTITY, ARTIFACT})

# Step context constraint: the matching finding must be observed in install-time context.
INSTALL_CONTEXT = "install"

# --------------------------------------------------------------------------- code groups
INSTALL_VECTOR_CODES = frozenset({Code.INSTALL_HOOK_EXEC, Code.PTH_STARTUP_HOOK, Code.BUILD_BACKEND_HOOK})
CREDENTIAL_ACCESS_CODES = frozenset({Code.ENV_HARVEST, Code.FS_SENSITIVE, Code.BROWSER_CREDENTIAL_ACCESS})
EGRESS_CODES = frozenset({Code.NETWORK_EGRESS, Code.DNS_EXFILTRATION, Code.IOC_MATCH})
EVASION_CODES = frozenset({
    Code.ENCODED_EXEC, Code.OBFUSCATION, Code.LAYERED_ENCODING, Code.STRING_RECONSTRUCTION, Code.REFLECTION_ABUSE,
})
LOADER_CODES = frozenset({Code.ENCODED_EXEC, Code.LAYERED_ENCODING})
EXEC_CODES = frozenset({Code.SUBPROCESS_EXEC, Code.SHELL_INVOCATION, Code.DYNAMIC_EXEC})
ARTIFACT_CODES = frozenset({Code.BINARY_EXECUTABLE, Code.NESTED_ARCHIVE})
TAKEOVER_CODES = frozenset({Code.MAINTAINER_CHANGED, Code.DORMANT_REVIVAL, Code.REPO_MISMATCH, Code.PROVENANCE_FAILED})
DEPENDENCY_CONFUSION_CODES = frozenset({Code.DEPENDENCY_CONFUSION, Code.NAMESPACE_COLLISION})

# Per-code (tactic, technique) refinements. ``None`` means "not honestly mappable".
_INSTALL_TECHNIQUES = {
    Code.INSTALL_HOOK_EXEC: (EXECUTION, "T1059.006"),
    Code.BUILD_BACKEND_HOOK: (EXECUTION, "T1059.006"),
    Code.PTH_STARTUP_HOOK: (PERSISTENCE, "T1546"),
}
_CREDENTIAL_TECHNIQUES = {
    Code.ENV_HARVEST: (CREDENTIAL_ACCESS, "T1552"),
    Code.FS_SENSITIVE: (CREDENTIAL_ACCESS, "T1552.001"),
    Code.BROWSER_CREDENTIAL_ACCESS: (CREDENTIAL_ACCESS, "T1555.003"),
}
_EXFIL_TECHNIQUES = {
    Code.NETWORK_EGRESS: (EXFILTRATION, "T1041"),
    Code.DNS_EXFILTRATION: (EXFILTRATION, "T1048"),
    Code.IOC_MATCH: (EXFILTRATION, "T1041"),
}
_EVASION_TECHNIQUES = {
    Code.ENCODED_EXEC: (DEFENSE_EVASION, "T1140"),
    Code.LAYERED_ENCODING: (DEFENSE_EVASION, "T1140"),
    Code.OBFUSCATION: (DEFENSE_EVASION, "T1027"),
    Code.STRING_RECONSTRUCTION: (DEFENSE_EVASION, "T1027"),
    Code.REFLECTION_ABUSE: (DEFENSE_EVASION, "T1027"),
}
_EXEC_TECHNIQUES = {
    Code.SUBPROCESS_EXEC: (EXECUTION, "T1059"),
    Code.SHELL_INVOCATION: (EXECUTION, "T1059"),
    Code.DYNAMIC_EXEC: (EXECUTION, "T1059.006"),
    Code.REFLECTION_ABUSE: (EXECUTION, "T1059.006"),
    Code.ENCODED_EXEC: (EXECUTION, "T1059.006"),
}
# An IOC can be a URL, IP, wallet or code fingerprint: no single tactic describes it honestly.
_IOC_UNMAPPED = {Code.IOC_MATCH: (None, None)}

# Keyword hints for the persistence mechanism (used only to *label* a PERSISTENCE finding with
# the matching ATT&CK sub-technique; ambiguous or absent hints leave the technique unmapped).
PERSISTENCE_HINTS: tuple[tuple[str, str], ...] = (
    ("crontab", "T1053.003"),
    ("cron.d", "T1053.003"),
    ("/etc/cron", "T1053.003"),
    ("systemd", "T1543.002"),
    ("systemctl", "T1543.002"),
    (".service", "T1543.002"),
    ("currentversion\\run", "T1547.001"),
    ("start menu\\programs\\startup", "T1547.001"),
    ("/autostart/", "T1547.001"),
    (".bashrc", "T1546.004"),
    (".bash_profile", "T1546.004"),
    (".zshrc", "T1546.004"),
    (".profile", "T1546.004"),
)


def _overrides(*maps: Mapping[str, tuple[str | None, str | None]]) -> Mapping[str, tuple[str | None, str | None]]:
    merged: dict[str, tuple[str | None, str | None]] = {}
    for m in maps:
        merged.update(m)
    return MappingProxyType(merged)


_NO_OVERRIDES: Mapping[str, tuple[str | None, str | None]] = MappingProxyType({})


# --------------------------------------------------------------------------- specs
@dataclass(frozen=True, eq=False)
class StepSpec:
    """One step of an attack chain.

    ``technique_id`` is the step's default ATT&CK technique; ``overrides`` refine
    ``(tactic, technique_id)`` by the code of the step's most confident finding. A ``None``
    technique is resolved from the finding's own single ATT&CK mapping or from
    ``technique_hints`` and otherwise stays unmapped (never guessed).
    """

    order: int
    tactic: str | None
    technique_id: str | None
    technique_name: str | None
    codes_any: frozenset[str]
    required: bool = True
    description: str = ""
    kind: str = BEHAVIOR
    context: str | None = None
    overrides: Mapping[str, tuple[str | None, str | None]] = field(default=_NO_OVERRIDES)
    technique_hints: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, eq=False)
class BoosterSpec:
    """A group of codes that corroborates a chain; each satisfied group adds a fixed bonus."""

    name: str
    codes_any: frozenset[str]
    description: str = ""


@dataclass(frozen=True, eq=False)
class ChainTemplate:
    chain_id: str
    title: str
    severity: Severity
    steps: tuple[StepSpec, ...]
    boosters: tuple[BoosterSpec, ...] = ()
    variant: str = "default"
    summary: str = ""
    # All located behaviour steps must share a file for this variant to match.
    require_colocation: bool = False

    @property
    def required_steps(self) -> tuple[StepSpec, ...]:
        return tuple(s for s in self.steps if s.required)


def _step(order: int, tactic: str | None, technique_id: str | None, codes: frozenset[str] | set[str], *,
          required: bool = True, description: str, kind: str = BEHAVIOR, context: str | None = None,
          overrides: Mapping[str, tuple[str | None, str | None]] = _NO_OVERRIDES,
          technique_hints: tuple[tuple[str, str], ...] = ()) -> StepSpec:
    name = taxonomy.ATTACK_TECHNIQUES.get(technique_id) if technique_id else None
    return StepSpec(order=order, tactic=tactic, technique_id=technique_id, technique_name=name,
                    codes_any=frozenset(codes), required=required, description=description, kind=kind,
                    context=context, overrides=overrides, technique_hints=technique_hints)


# --------------------------------------------------------------------------- shared steps / boosters
def _install_step(order: int, *, required: bool) -> StepSpec:
    return _step(order, EXECUTION, "T1059.006", INSTALL_VECTOR_CODES, required=required,
                 description="Code is triggered automatically by package installation, build or interpreter "
                             "start-up.",
                 overrides=_overrides(_INSTALL_TECHNIQUES))


def _evasion_step(order: int) -> StepSpec:
    return _step(order, DEFENSE_EVASION, "T1027", EVASION_CODES, required=False,
                 description="Behaviour is concealed with encoding, obfuscation or reflective access.",
                 overrides=_overrides(_EVASION_TECHNIQUES))


INSTALL_BOOSTER = BoosterSpec("install_time_vector", INSTALL_VECTOR_CODES,
                              "An install-time or start-up execution vector is present.")
EVASION_BOOSTER = BoosterSpec("evasion", EVASION_CODES, "Obfuscation, encoding or reflection is present.")
EGRESS_BOOSTER = BoosterSpec("egress", EGRESS_CODES | {Code.SUSPICIOUS_DOWNLOAD},
                             "A network egress, download or known-malicious indicator is present.")

# --------------------------------------------------------------------------- templates
TEMPLATES: tuple[ChainTemplate, ...] = (
    ChainTemplate(
        chain_id="credential_exfiltration",
        title="Credential theft and exfiltration",
        severity=Severity.critical,
        summary="Credential access combined with a channel to send data out.",
        steps=(
            _install_step(1, required=False),
            _evasion_step(2),
            _step(3, CREDENTIAL_ACCESS, "T1552", CREDENTIAL_ACCESS_CODES,
                  description="Reads credential material: credential environment variables, key or credential "
                              "files, or browser credential stores.",
                  overrides=_overrides(_CREDENTIAL_TECHNIQUES)),
            _step(4, EXFILTRATION, "T1041", EGRESS_CODES,
                  description="Has a channel to send data out: network egress, a DNS exfiltration pattern or a "
                              "known-malicious indicator.",
                  overrides=_overrides(_EXFIL_TECHNIQUES)),
        ),
        boosters=(INSTALL_BOOSTER, EVASION_BOOSTER),
    ),
    ChainTemplate(
        chain_id="install_time_dropper",
        variant="download_execute",
        title="Install-time payload dropper",
        severity=Severity.critical,
        summary="An install-time execution vector combined with download-and-execute behaviour.",
        steps=(
            _install_step(1, required=True),
            _step(2, COMMAND_AND_CONTROL, "T1105", {Code.SUSPICIOUS_DOWNLOAD},
                  description="Fetches a payload and executes it or marks it executable."),
            _step(3, EXECUTION, "T1059", EXEC_CODES, required=False,
                  description="Starts processes, shells or dynamically evaluated code.",
                  overrides=_overrides(_EXEC_TECHNIQUES)),
        ),
        boosters=(EVASION_BOOSTER,),
    ),
    ChainTemplate(
        chain_id="install_time_dropper",
        variant="fetch_and_exec",
        title="Install-time payload dropper",
        severity=Severity.high,
        summary="An install-time execution vector, network access and process or code execution in one file.",
        require_colocation=True,
        steps=(
            _install_step(1, required=True),
            _step(2, COMMAND_AND_CONTROL, "T1105", {Code.NETWORK_EGRESS},
                  description="Makes network requests in the same file (possible payload retrieval)."),
            _step(3, EXECUTION, "T1059", EXEC_CODES,
                  description="Starts processes, shells or dynamically evaluated code in the same file.",
                  overrides=_overrides(_EXEC_TECHNIQUES)),
        ),
        boosters=(EVASION_BOOSTER,),
    ),
    ChainTemplate(
        chain_id="obfuscated_loader",
        variant="encoded_exec",
        title="Obfuscated code loader",
        severity=Severity.critical,
        summary="An encoded or layered payload that is decoded for execution.",
        steps=(
            _step(1, DEFENSE_EVASION, "T1140", LOADER_CODES,
                  description="Decodes an embedded encoded or multiply-encoded payload.",
                  overrides=_overrides(_EVASION_TECHNIQUES)),
            _step(2, EXECUTION, "T1059.006", {Code.ENCODED_EXEC, Code.DYNAMIC_EXEC, Code.REFLECTION_ABUSE},
                  required=False, description="Executes the decoded code dynamically.",
                  overrides=_overrides(_EXEC_TECHNIQUES)),
        ),
        boosters=(INSTALL_BOOSTER, EGRESS_BOOSTER),
    ),
    ChainTemplate(
        chain_id="obfuscated_loader",
        variant="obfuscated_dynamic_exec",
        title="Obfuscated code loader",
        severity=Severity.high,
        summary="Obfuscated content combined with dynamic or reflective code execution.",
        steps=(
            _step(1, DEFENSE_EVASION, "T1027", {Code.OBFUSCATION, Code.STRING_RECONSTRUCTION},
                  description="Hides content in high-entropy blobs or runtime-reconstructed strings.",
                  overrides=_overrides(_EVASION_TECHNIQUES)),
            _step(2, EXECUTION, "T1059.006", {Code.DYNAMIC_EXEC, Code.REFLECTION_ABUSE},
                  description="Executes code dynamically or through reflective access to builtins.",
                  overrides=_overrides(_EXEC_TECHNIQUES)),
        ),
        boosters=(INSTALL_BOOSTER, EGRESS_BOOSTER),
    ),
    ChainTemplate(
        chain_id="persistence_implant",
        title="Persistence implant",
        severity=Severity.critical,
        summary="A persistence mechanism combined with install-time execution, a download or network access.",
        steps=(
            _step(1, EXECUTION, "T1059.006",
                  INSTALL_VECTOR_CODES | {Code.SUSPICIOUS_DOWNLOAD, Code.NETWORK_EGRESS},
                  description="Delivers or triggers the implant: install-time execution, a payload download or "
                              "network access.",
                  overrides=_overrides(_INSTALL_TECHNIQUES, {
                      Code.SUSPICIOUS_DOWNLOAD: (COMMAND_AND_CONTROL, "T1105"),
                      Code.NETWORK_EGRESS: (COMMAND_AND_CONTROL, "T1071.001"),
                  })),
            _step(2, PERSISTENCE, None, {Code.PERSISTENCE},
                  description="Installs a persistence mechanism (scheduled job, service, autostart entry or shell "
                              "profile).",
                  technique_hints=PERSISTENCE_HINTS),
        ),
        boosters=(EVASION_BOOSTER,),
    ),
    ChainTemplate(
        chain_id="typosquat_payload",
        title="Typosquatting package with payload",
        severity=Severity.critical,
        summary="A package name imitating a popular package that also carries an active payload.",
        steps=(
            _step(1, INITIAL_ACCESS, "T1195.001", {Code.TYPOSQUAT}, kind=IDENTITY,
                  description="The package name imitates a popular package so it is installed by mistake."),
            _step(2, EXECUTION, "T1059.006",
                  INSTALL_VECTOR_CODES | CREDENTIAL_ACCESS_CODES | LOADER_CODES | {Code.IOC_MATCH},
                  description="Carries a payload: install-time execution, credential access, an encoded loader or "
                              "a known-malicious indicator.",
                  overrides=_overrides(_INSTALL_TECHNIQUES, _CREDENTIAL_TECHNIQUES, _EVASION_TECHNIQUES,
                                       _IOC_UNMAPPED)),
        ),
        boosters=(EVASION_BOOSTER, EGRESS_BOOSTER),
    ),
    ChainTemplate(
        chain_id="dependency_confusion_payload",
        title="Dependency-confusion package with payload",
        severity=Severity.critical,
        summary="A package that can shadow a private dependency and also carries an active payload.",
        steps=(
            _step(1, INITIAL_ACCESS, "T1195.001", DEPENDENCY_CONFUSION_CODES, kind=IDENTITY,
                  description="The package name collides with a private or internal package name."),
            _step(2, EXECUTION, "T1059.006", INSTALL_VECTOR_CODES | EGRESS_CODES | CREDENTIAL_ACCESS_CODES,
                  description="Carries a payload: install-time execution, network egress or credential access.",
                  overrides=_overrides(_INSTALL_TECHNIQUES, _EXFIL_TECHNIQUES, _CREDENTIAL_TECHNIQUES)),
        ),
        boosters=(EVASION_BOOSTER,),
    ),
    ChainTemplate(
        chain_id="takeover_behavior_change",
        title="Possible account takeover with behaviour change",
        severity=Severity.high,
        summary="A trust or ownership change combined with new or dangerous behaviour in the release.",
        steps=(
            _step(1, INITIAL_ACCESS, "T1195.001", TAKEOVER_CODES, kind=IDENTITY,
                  description="Ownership, publishing identity or provenance changed or failed verification."),
            _step(2, EXECUTION, "T1059.006",
                  {Code.BEHAVIOR_DRIFT} | INSTALL_VECTOR_CODES | CREDENTIAL_ACCESS_CODES | LOADER_CODES,
                  description="The release behaves differently or dangerously: behaviour drift, install-time "
                              "execution, credential access or an encoded loader.",
                  overrides=_overrides(_INSTALL_TECHNIQUES, _CREDENTIAL_TECHNIQUES, _EVASION_TECHNIQUES,
                                       {Code.BEHAVIOR_DRIFT: (INITIAL_ACCESS, "T1195.001")})),
        ),
        boosters=(EVASION_BOOSTER, EGRESS_BOOSTER),
    ),
    ChainTemplate(
        chain_id="hidden_native_payload",
        variant="native_loading",
        title="Hidden native payload",
        severity=Severity.high,
        summary="A shipped binary or nested archive combined with native code loading.",
        steps=(
            _step(1, DEFENSE_EVASION, "T1027.009", ARTIFACT_CODES, kind=ARTIFACT,
                  description="Ships a prebuilt executable or an archive that is not analysed recursively."),
            _step(2, EXECUTION, "T1129", {Code.NATIVE_CODE_LOADING},
                  description="Loads native code into the Python process."),
        ),
        boosters=(INSTALL_BOOSTER, EVASION_BOOSTER),
    ),
    ChainTemplate(
        chain_id="hidden_native_payload",
        variant="install_time_process",
        title="Hidden native payload",
        severity=Severity.high,
        summary="A shipped binary or nested archive combined with process execution at install time.",
        steps=(
            _step(1, DEFENSE_EVASION, "T1027.009", ARTIFACT_CODES, kind=ARTIFACT,
                  description="Ships a prebuilt executable or an archive that is not analysed recursively."),
            _step(2, EXECUTION, "T1059", {Code.SUBPROCESS_EXEC, Code.SHELL_INVOCATION}, context=INSTALL_CONTEXT,
                  description="Starts processes during installation.",
                  overrides=_overrides(_EXEC_TECHNIQUES)),
        ),
        boosters=(EVASION_BOOSTER,),
    ),
)


# --------------------------------------------------------------------------- validation
def validate_templates(templates: Sequence[ChainTemplate]) -> None:
    """Raise ``ValueError`` if a template is structurally unsound.

    Checks: unique ``(chain_id, variant)``; consistent title per ``chain_id``; at least one
    required step; unique step orders; known tactics, step kinds and severities; every ATT&CK
    id (defaults, overrides, hints) present in ``taxonomy.ATTACK_TECHNIQUES``; and pairwise
    disjoint codes across required steps, so a single finding can never satisfy two required
    steps of the same chain on its own.
    """
    seen: set[tuple[str, str]] = set()
    titles: dict[str, str] = {}
    known = taxonomy.ATTACK_TECHNIQUES
    for t in templates:
        key = (t.chain_id, t.variant)
        if not t.chain_id or key in seen:
            raise ValueError(f"duplicate or empty chain template id: {key}")
        seen.add(key)
        if titles.setdefault(t.chain_id, t.title) != t.title:
            raise ValueError(f"chain {t.chain_id!r} variants must share one title")
        if not isinstance(t.severity, Severity):
            raise ValueError(f"chain {key}: severity must be a Severity")
        required = t.required_steps
        if not required:
            raise ValueError(f"chain {key}: at least one required step is needed")
        orders = [s.order for s in t.steps]
        if len(set(orders)) != len(orders) or any(o < 1 for o in orders):
            raise ValueError(f"chain {key}: step orders must be unique positive integers")
        for s in t.steps:
            if not s.codes_any:
                raise ValueError(f"chain {key} step {s.order}: no codes")
            if s.kind not in STEP_KINDS:
                raise ValueError(f"chain {key} step {s.order}: unknown kind {s.kind!r}")
            if s.context not in (None, INSTALL_CONTEXT):
                raise ValueError(f"chain {key} step {s.order}: unknown context {s.context!r}")
            techniques = [s.technique_id, *(tid for _, tid in s.overrides.values()),
                          *(tid for _, tid in s.technique_hints)]
            tactics = [s.tactic, *(tac for tac, _ in s.overrides.values())]
            for tid in techniques:
                if tid is not None and tid not in known:
                    raise ValueError(f"chain {key} step {s.order}: unknown ATT&CK technique {tid!r}")
            for tactic in tactics:
                if tactic is not None and tactic not in TACTICS:
                    raise ValueError(f"chain {key} step {s.order}: unknown tactic {tactic!r}")
            if s.technique_id is not None and s.technique_name != known[s.technique_id]:
                raise ValueError(f"chain {key} step {s.order}: technique name mismatch")
        for i, a in enumerate(required):
            for b in required[i + 1:]:
                overlap = a.codes_any & b.codes_any
                if overlap:
                    raise ValueError(f"chain {key}: required steps {a.order} and {b.order} share codes "
                                     f"{sorted(overlap)}")


validate_templates(TEMPLATES)

__all__ = [
    "ARTIFACT",
    "ARTIFACT_CODES",
    "BEHAVIOR",
    "CREDENTIAL_ACCESS_CODES",
    "EGRESS_CODES",
    "EVASION_CODES",
    "EXEC_CODES",
    "IDENTITY",
    "INSTALL_CONTEXT",
    "INSTALL_VECTOR_CODES",
    "LOADER_CODES",
    "PERSISTENCE_HINTS",
    "TACTICS",
    "TEMPLATES",
    "BoosterSpec",
    "ChainTemplate",
    "StepSpec",
    "validate_templates",
]
