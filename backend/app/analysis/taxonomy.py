"""Finding-code taxonomy: category, risk dimension, CWE, MITRE ATT&CK and alignment mappings.

Each finding code is registered once with the metadata needed to explain it: a human
title, remediation guidance, the risk dimension it feeds, and — only where the mapping is
defensible — CWE weaknesses, MITRE ATT&CK techniques, OWASP Top 10 (2021) categories,
NIST SSDF (SP 800-218) practices, SLSA and OpenSSF concepts.

These are *alignment mappings* that help a reader place a finding in a familiar framework.
They are not claims of formal compliance. Where no framework entry fits a finding honestly,
the mapping is left empty rather than stretched.

Analyzers that introduce codes outside this catalogue may call :func:`register` at import
time; unknown codes still work (they default to category ``other``).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.findings import Category


class Dimension:
    """Risk dimensions a finding contributes to (see the risk engine)."""

    BEHAVIORAL = "behavioral"
    VULNERABILITY = "vulnerability"
    PROVENANCE = "provenance"
    REPUTATION = "reputation"
    DEPENDENCY = "dependency"
    INTEGRITY = "integrity"
    # bandit B105 false positive: a risk-dimension name, not a credential.
    SECRET = "secret"  # nosec B105
    CONTAINER = "container"
    PIPELINE = "pipeline"


@dataclass(frozen=True)
class CodeInfo:
    code: str
    category: str
    dimension: str
    title: str
    remediation: str
    cwe: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    ssdf: tuple[str, ...] = ()
    slsa: tuple[str, ...] = ()
    openssf: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    # A strong standalone indicator: may drive the rule score to high/critical on its own.
    primary: bool = False


_REGISTRY: dict[str, CodeInfo] = {}


def register(info: CodeInfo, *, replace: bool = False) -> CodeInfo:
    if info.code in _REGISTRY and not replace:
        raise ValueError(f"finding code already registered: {info.code}")
    _REGISTRY[info.code] = info
    return info


def get(code: str) -> CodeInfo | None:
    return _REGISTRY.get(code)


def all_codes() -> dict[str, CodeInfo]:
    return dict(_REGISTRY)


def primary_codes() -> frozenset[str]:
    return frozenset(c for c, i in _REGISTRY.items() if i.primary)


def dimension_for(code: str, default: str = Dimension.BEHAVIORAL) -> str:
    info = _REGISTRY.get(code)
    return info.dimension if info else default


def compliance_for(code: str) -> dict[str, list[str]]:
    info = _REGISTRY.get(code)
    if info is None:
        return {}
    out = {
        "cwe": list(info.cwe),
        "attack": list(info.attack),
        "owasp_top10_2021": list(info.owasp),
        "nist_ssdf": list(info.ssdf),
        "slsa": list(info.slsa),
        "openssf": list(info.openssf),
    }
    return {k: v for k, v in out.items() if v}


# Human-readable names for the identifiers used below (for reports and the dashboard).
ATTACK_TECHNIQUES: dict[str, str] = {
    "T1027": "Obfuscated Files or Information",
    "T1027.002": "Obfuscated Files or Information: Software Packing",
    "T1027.009": "Obfuscated Files or Information: Embedded Payloads",
    "T1036.005": "Masquerading: Match Legitimate Resource Name or Location",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1059": "Command and Scripting Interpreter",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1105": "Ingress Tool Transfer",
    "T1106": "Native API",
    "T1129": "Shared Modules",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1546": "Event Triggered Execution",
    "T1546.004": "Event Triggered Execution: Unix Shell Configuration Modification",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.004": "Unsecured Credentials: Private Keys",
    "T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
    "T1567": "Exfiltration Over Web Service",
    "T1611": "Escape to Host",
    "T1620": "Reflective Code Loading",
}

CWE_NAMES: dict[str, str] = {
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-353": "Missing Support for Integrity Check",
    "CWE-354": "Improper Validation of Integrity Check Value",
    "CWE-409": "Improper Handling of Highly Compressed Data (Data Amplification)",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-506": "Embedded Malicious Code",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-912": "Hidden Functionality",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1357": "Reliance on Insufficiently Trustworthy Component",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
}

OWASP_2021: dict[str, str] = {
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
}

SSDF_PRACTICES: dict[str, str] = {
    "PS.1": "Protect all forms of code from unauthorized access and tampering",
    "PS.2": "Provide a mechanism for verifying software release integrity",
    "PW.4": "Reuse existing, well-secured software when feasible",
    "PW.9": "Configure software to have secure settings by default",
    "RV.1": "Identify and confirm vulnerabilities on an ongoing basis",
}

_REF_PTH = "https://docs.python.org/3/library/site.html"
_REF_PEP517 = "https://peps.python.org/pep-0517/"
_REF_PEP740 = "https://peps.python.org/pep-0740/"
_REF_ATTESTATIONS = "https://docs.pypi.org/attestations/"
_REF_PIP_SECURE = "https://pip.pypa.io/en/stable/topics/secure-installs/"
_REF_KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
_REF_SCORECARD_PINNED = "https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies"
_REF_SLSA = "https://slsa.dev/spec/v1.0/"

C, D = Category, Dimension


def _r(code: str, category: Category, dimension: str, title: str, remediation: str, **kw) -> None:
    register(CodeInfo(code=code, category=category.value, dimension=dimension, title=title,
                      remediation=remediation, **kw))


# --- registry metadata / reputation -----------------------------------------------------
_r("NEW_PACKAGE", C.REPUTATION, D.REPUTATION, "Recently published release",
   "Consider a minimum release-age policy and review very new releases before adoption.",
   cwe=("CWE-1357",), ssdf=("PW.4",))
_r("SINGLE_MAINTAINER", C.REPUTATION, D.REPUTATION, "Single or anonymous maintainer",
   "Weigh the bus-factor and accountability risk; prefer well-maintained alternatives for critical paths.",
   cwe=("CWE-1357",), ssdf=("PW.4",))
_r("NO_SOURCE_REPO", C.REPUTATION, D.REPUTATION, "No source repository declared",
   "Verify the package's origin; packages without a reviewable source repository deserve extra scrutiny.",
   cwe=("CWE-1357",), ssdf=("PW.4",))
_r("RELEASE_FLOOD", C.REPUTATION, D.REPUTATION, "Burst of releases in a short window",
   "Review recent releases individually; release floods are a common spray-and-pray malware pattern.",
   cwe=("CWE-1357",))
_r("VERSION_NOT_FOUND", C.PIPELINE, D.PIPELINE, "Requested version not found on registry",
   "Pin to a version that exists on the registry; never gate on a verdict for a different version.")
_r("YANKED_RELEASE", C.REPUTATION, D.REPUTATION, "Release was yanked by its maintainers",
   "Move to a non-yanked release and read the yank reason before continuing to use this version.",
   cwe=("CWE-1104",), ssdf=("PW.4",))
_r("DORMANT_REVIVAL", C.PROVENANCE, D.PROVENANCE, "Release after long dormancy",
   "A sudden release after a long gap is a known account-takeover pattern; diff it against the previous release.",
   cwe=("CWE-1357",), attack=("T1195.001",), ssdf=("PW.4",))
_r("MAINTAINER_CHANGED", C.PROVENANCE, D.PROVENANCE, "Maintainer / ownership change",
   "Confirm the ownership change is legitimate (project announcement, repository history) before upgrading.",
   cwe=("CWE-1357",), attack=("T1195.001",), ssdf=("PW.4",))

# --- behavioural static analysis ----------------------------------------------------------
_r("INSTALL_HOOK_EXEC", C.INSTALL_TIME, D.BEHAVIORAL, "Active code at install time",
   "Do not install. Review setup.py / build hooks; prefer wheels (pip --only-binary :all:) where feasible.",
   cwe=("CWE-506", "CWE-829"), attack=("T1195.001", "T1059.006"), owasp=("A08:2021",), ssdf=("PW.4",),
   references=(_REF_PEP517,), primary=True)
_r("NETWORK_EGRESS", C.CAPABILITY, D.BEHAVIORAL, "Network egress capability",
   "Confirm network access is expected for this package's stated purpose.",
   attack=("T1071.001",))
_r("SUBPROCESS_EXEC", C.CAPABILITY, D.BEHAVIORAL, "Process execution capability",
   "Confirm process execution is expected; review the commands being run.",
   attack=("T1059",))
_r("SHELL_INVOCATION", C.CAPABILITY, D.BEHAVIORAL, "Shell command invocation",
   "Review shell usage; shell=True or os.system with non-constant input enables command injection.",
   cwe=("CWE-78",), attack=("T1059.004", "T1059.003"))
_r("DYNAMIC_EXEC", C.CAPABILITY, D.BEHAVIORAL, "Dynamic code execution",
   "Review eval/exec/compile call sites and the origin of the code they execute.",
   cwe=("CWE-94", "CWE-95"), attack=("T1059.006",))
_r("DYNAMIC_IMPORT", C.CAPABILITY, D.BEHAVIORAL, "Dynamic import of a computed module name",
   "Review which modules can be imported; computed imports can hide the real dependency surface.",
   cwe=("CWE-829",))
_r("REFLECTION_ABUSE", C.OBFUSCATION, D.BEHAVIORAL, "Reflective access to dangerous builtins",
   "Constructed getattr/globals() access to exec/eval-like builtins is an evasion technique; review manually.",
   cwe=("CWE-506",), attack=("T1027",), primary=True)
_r("NATIVE_CODE_LOADING", C.CAPABILITY, D.BEHAVIORAL, "Native code loading",
   "Verify the loaded native library ships with the package and is built from reviewable source.",
   cwe=("CWE-829",), attack=("T1106", "T1129"))
_r("ENV_HARVEST", C.CREDENTIAL_ACCESS, D.BEHAVIORAL, "Reads credential environment variables",
   "Confirm the package legitimately needs these credentials; run untrusted code without secrets in the environment.",
   cwe=("CWE-200",), attack=("T1552",), primary=True)
_r("FS_SENSITIVE", C.CREDENTIAL_ACCESS, D.BEHAVIORAL, "Accesses credential / key files",
   "Packages rarely need SSH keys, cloud credentials or registry tokens; treat as credential theft until explained.",
   cwe=("CWE-200",), attack=("T1552.001", "T1552.004"), primary=True)
_r("BROWSER_CREDENTIAL_ACCESS", C.CREDENTIAL_ACCESS, D.BEHAVIORAL, "Accesses browser credential stores",
   "Libraries have no legitimate reason to read browser cookie/login databases; do not install.",
   cwe=("CWE-200", "CWE-506"), attack=("T1555.003",), primary=True)
_r("PERSISTENCE", C.MALICIOUS_BEHAVIOR, D.BEHAVIORAL, "Persistence mechanism",
   "Writing cron jobs, services, autostart entries or shell profiles from a package is malicious persistence.",
   cwe=("CWE-506",), attack=("T1053.003", "T1543.002", "T1547.001", "T1546.004"), primary=True)
_r("SUSPICIOUS_DOWNLOAD", C.MALICIOUS_BEHAVIOR, D.BEHAVIORAL, "Download-and-execute behaviour",
   "Code that fetches a payload and executes or marks it executable is a dropper; do not install.",
   cwe=("CWE-494",), attack=("T1105",), primary=True)
_r("DNS_EXFILTRATION", C.MALICIOUS_BEHAVIOR, D.BEHAVIORAL, "DNS-based data exfiltration pattern",
   "DNS lookups of hostnames built from local data are a covert exfiltration channel; do not install.",
   cwe=("CWE-506",), attack=("T1048", "T1071.004"), primary=True)
_r("DANGEROUS_IMPORT", C.CAPABILITY, D.BEHAVIORAL, "Imports high-risk modules",
   "Informational: high-risk modules are common in legitimate code; review in context of other findings.")

# --- install-time execution vectors -----------------------------------------------------
_r("PTH_STARTUP_HOOK", C.INSTALL_TIME, D.BEHAVIORAL, "Executable .pth startup hook",
   ".pth lines starting with 'import' run on every interpreter start; remove the package and inspect site-packages.",
   cwe=("CWE-506",), attack=("T1546", "T1059.006"), owasp=("A08:2021",), references=(_REF_PTH,), primary=True)
_r("BUILD_BACKEND_HOOK", C.INSTALL_TIME, D.BEHAVIORAL, "Custom / in-tree build backend",
   "An in-tree PEP 517 backend runs arbitrary code during build; review the backend before installing from sdist.",
   cwe=("CWE-829",), attack=("T1195.001", "T1059.006"), references=(_REF_PEP517,), primary=True)
_r("ENTRYPOINT_SHADOWING", C.INSTALL_TIME, D.BEHAVIORAL, "Console script shadows a common command",
   "A console script named like a system or developer tool can hijack command execution; verify its purpose.",
   cwe=("CWE-427",), attack=("T1036.005",))

# --- obfuscation --------------------------------------------------------------------------
_r("OBFUSCATION", C.OBFUSCATION, D.BEHAVIORAL, "High-entropy embedded blobs",
   "Decode and review embedded blobs; legitimate packages rarely ship opaque encoded code.",
   cwe=("CWE-506",), attack=("T1027",), primary=True)
_r("ENCODED_EXEC", C.OBFUSCATION, D.BEHAVIORAL, "Decode-then-execute loader",
   "A decode→exec chain over an embedded blob is a packed loader; do not install.",
   cwe=("CWE-506", "CWE-94"), attack=("T1027", "T1140", "T1059.006"), primary=True)
_r("STRING_RECONSTRUCTION", C.OBFUSCATION, D.BEHAVIORAL, "Runtime string reconstruction",
   "Strings assembled from chr()/joins/reversal hide names from reviewers and scanners; decode and review.",
   cwe=("CWE-506",), attack=("T1027",))
_r("LAYERED_ENCODING", C.OBFUSCATION, D.BEHAVIORAL, "Multiple layers of encoding",
   "Nested encoding/compression layers indicate deliberate concealment; decode fully and review.",
   cwe=("CWE-506",), attack=("T1027", "T1140"), primary=True)
_r("HEX_PAYLOAD", C.OBFUSCATION, D.BEHAVIORAL, "Hex-encoded payload",
   "Decode the hex payload and review what it contains.",
   cwe=("CWE-506",), attack=("T1027",))
_r("COMPRESSED_PAYLOAD", C.OBFUSCATION, D.BEHAVIORAL, "Compressed embedded payload",
   "Decompress and review the embedded payload.",
   cwe=("CWE-506",), attack=("T1027.002",))
_r("LARGE_CONSTANT", C.OBFUSCATION, D.BEHAVIORAL, "Unusually large constant",
   "Informational in isolation; very large constants can hide payloads when combined with decoders.",
   attack=("T1027",))
_r("MINIFIED_CODE", C.OBFUSCATION, D.BEHAVIORAL, "Minified / single-line Python code",
   "Minified Python is unusual in source distributions; review whether it hides behaviour.",
   attack=("T1027",))

# --- artifact inventory / integrity ---------------------------------------------------------
_r("BINARY_EXECUTABLE", C.SUSPICIOUS_ARTIFACT, D.INTEGRITY, "Prebuilt executable in source distribution",
   "Source distributions should build from source; inspect prebuilt binaries and their provenance.",
   cwe=("CWE-912",), attack=("T1027.009",))
_r("NESTED_ARCHIVE", C.SUSPICIOUS_ARTIFACT, D.INTEGRITY, "Archive nested inside the package",
   "Nested archives are not analysed recursively and can hide payloads; inspect them manually.",
   cwe=("CWE-912",), attack=("T1027.009",))
_r("SUSPICIOUS_FILE", C.SUSPICIOUS_ARTIFACT, D.INTEGRITY, "Suspicious file in package",
   "Review why this file type is shipped in the package.",
   cwe=("CWE-912",))
_r("HASH_MISMATCH", C.INTEGRITY, D.INTEGRITY, "Artifact hash does not match registry digest",
   "Do not install: the downloaded bytes differ from what the registry published.",
   cwe=("CWE-354", "CWE-345"), owasp=("A08:2021",), ssdf=("PS.2",), slsa=("artifact integrity",),
   references=(_REF_PIP_SECURE,), primary=True)
_r("SDIST_WHEEL_MISMATCH", C.INTEGRITY, D.INTEGRITY, "Wheel contents diverge from source distribution",
   "Code present only in the wheel was not built from the reviewable sdist; inspect the extra files.",
   cwe=("CWE-345",), attack=("T1195.001",), ssdf=("PS.2",))

# --- typosquatting / IOC ------------------------------------------------------------------------
_r("TYPOSQUAT", C.TYPOSQUAT, D.BEHAVIORAL, "Name imitates a popular package",
   "Check the spelling; install the intended popular package instead.",
   cwe=("CWE-1357",), attack=("T1036.005", "T1195.001"), primary=True)
_r("IOC_MATCH", C.IOC, D.BEHAVIORAL, "Known malicious indicator",
   "Do not install; the package contains an indicator associated with known malicious activity.",
   cwe=("CWE-506",), attack=("T1195.001",), owasp=("A08:2021",), primary=True)

# --- secrets / external engines ----------------------------------------------------------------
_r("SECRET_DETECTED", C.SECRET, D.SECRET, "Hard-coded credential",
   "Revoke and rotate the credential, remove it from source and history, and load secrets from a secret store.",
   cwe=("CWE-798",), attack=("T1552.001",), owasp=("A07:2021",), ssdf=("PS.1",))
_r("YARA_MATCH", C.MALICIOUS_BEHAVIOR, D.BEHAVIORAL, "YARA rule match",
   "Review the matched content against the rule description; YARA matches are signature evidence.",
   cwe=("CWE-506",), primary=True)
_r("SEMGREP_FINDING", C.CODE_WEAKNESS, D.BEHAVIORAL, "Semgrep rule match",
   "Review the matched code against the rule's guidance.")

# --- provenance / trust ------------------------------------------------------------------------------
_r("PROVENANCE_ATTESTED", C.PROVENANCE, D.PROVENANCE, "Publish attestation present",
   "Informational: a PEP 740 attestation links this artifact to a publisher identity.",
   slsa=("provenance",), ssdf=("PS.2",), references=(_REF_PEP740, _REF_ATTESTATIONS))
_r("PROVENANCE_UNVERIFIED", C.PROVENANCE, D.PROVENANCE, "No verifiable provenance",
   "Informational: no publish attestation was available; trust rests on registry metadata only.",
   slsa=("provenance",), ssdf=("PS.2",), references=(_REF_ATTESTATIONS,))
_r("PROVENANCE_FAILED", C.PROVENANCE, D.PROVENANCE, "Provenance verification failed",
   "Do not install until the provenance failure is explained.",
   cwe=("CWE-345",), attack=("T1195.001",), ssdf=("PS.2",), slsa=("provenance",), references=(_REF_SLSA,),
   primary=True)
_r("REPO_MISMATCH", C.PROVENANCE, D.PROVENANCE, "Publisher repository differs from declared source",
   "Confirm the publishing repository is the project's real source; mismatches can indicate impersonation.",
   cwe=("CWE-345",), attack=("T1195.001",), ssdf=("PS.2",))

# --- dependency confusion ---------------------------------------------------------------------------
_r("DEPENDENCY_CONFUSION", C.DEPENDENCY_CONFUSION, D.DEPENDENCY, "Dependency confusion risk",
   "Resolve private packages only from the private index (explicit index routing) and pin with hashes.",
   cwe=("CWE-427", "CWE-1357"), attack=("T1195.001",), owasp=("A08:2021",), ssdf=("PW.4",),
   references=(_REF_PIP_SECURE,), primary=True)
_r("NAMESPACE_COLLISION", C.DEPENDENCY_CONFUSION, D.DEPENDENCY, "Private name exists on public index",
   "Reserve or block the public name and route resolution for private namespaces to the private index.",
   cwe=("CWE-427",), attack=("T1195.001",))
_r("INDEX_SOURCE_AMBIGUITY", C.DEPENDENCY_CONFUSION, D.DEPENDENCY, "Ambiguous package index configuration",
   "Avoid --extra-index-url for private packages; pip treats all indexes equally. Use one index and --require-hashes.",
   cwe=("CWE-427",), references=(_REF_PIP_SECURE,))

# --- vulnerability intelligence --------------------------------------------------------------------
_r("KNOWN_VULNERABILITY", C.VULNERABILITY, D.VULNERABILITY, "Known vulnerability",
   "Upgrade to a fixed version, or assess reachability and apply mitigations if no fix exists.",
   cwe=("CWE-1395",), owasp=("A06:2021",), ssdf=("RV.1", "PW.4"))
_r("KNOWN_EXPLOITED_VULNERABILITY", C.VULNERABILITY, D.VULNERABILITY, "Known exploited vulnerability (CISA KEV)",
   "Prioritise immediately: this vulnerability is listed in CISA's Known Exploited Vulnerabilities catalog.",
   cwe=("CWE-1395",), owasp=("A06:2021",), ssdf=("RV.1",), references=(_REF_KEV,))

# --- dependency hygiene --------------------------------------------------------------------------------
_r("UNPINNED_DEPENDENCY", C.DEPENDENCY_HYGIENE, D.DEPENDENCY, "Dependency not pinned to an exact version",
   "Pin exact versions (or use a lock file) so the analysed artifact is the one that gets installed.",
   cwe=("CWE-1357",), ssdf=("PW.4",), openssf=("Scorecard: Pinned-Dependencies",),
   references=(_REF_SCORECARD_PINNED,))
_r("MISSING_HASHES", C.DEPENDENCY_HYGIENE, D.INTEGRITY, "Dependency not hash-pinned",
   "Use hash-checking mode (--require-hashes) or a lock file with hashes.",
   cwe=("CWE-353",), ssdf=("PW.4",), openssf=("Scorecard: Pinned-Dependencies",), references=(_REF_PIP_SECURE,))

# --- derived findings ----------------------------------------------------------------------------------------
_r("BEHAVIOR_DRIFT", C.BEHAVIOR_DRIFT, D.BEHAVIORAL, "Security-relevant behaviour changed between releases",
   "Review the release diff; new install hooks, credential access or network behaviour can signal a takeover.",
   cwe=("CWE-1357",), attack=("T1195.001",), ssdf=("PW.4",), primary=True)
_r("ATTACK_CHAIN", C.ATTACK_CHAIN, D.BEHAVIORAL, "Correlated attack chain",
   "Multiple findings combine into a coherent attack sequence; treat as malicious and investigate.",
   cwe=("CWE-506",), attack=("T1195.001",), primary=True)

# --- containers ----------------------------------------------------------------------------------------------------
_r("DOCKERFILE_ROOT_USER", C.MISCONFIGURATION, D.CONTAINER, "Container runs as root",
   "Add a non-root USER to the final stage.",
   cwe=("CWE-250",), owasp=("A05:2021",), ssdf=("PW.9",))
_r("DOCKERFILE_REMOTE_ADD", C.MISCONFIGURATION, D.CONTAINER, "ADD from remote URL",
   "Download with a checksum-verified RUN step (or COPY vendored files) instead of ADD <url>.",
   cwe=("CWE-494",), attack=("T1105",), owasp=("A08:2021",))
_r("DOCKERFILE_CURL_PIPE_SHELL", C.MISCONFIGURATION, D.CONTAINER, "Remote script piped to shell",
   "Download, verify a pinned checksum, then execute; never pipe remote content into a shell.",
   cwe=("CWE-494",), attack=("T1105", "T1059.004"), owasp=("A08:2021",))
_r("DOCKERFILE_SECRET_IN_ENV", C.SECRET, D.CONTAINER, "Secret baked into image configuration",
   "Use build secrets (RUN --mount=type=secret) or runtime secret injection; rotate the exposed value.",
   cwe=("CWE-798",), attack=("T1552.001",), owasp=("A07:2021",))
_r("DOCKERFILE_UNPINNED_BASE", C.DEPENDENCY_HYGIENE, D.CONTAINER, "Base image not pinned by digest",
   "Pin base images by digest (FROM image@sha256:...) and update deliberately.",
   cwe=("CWE-1357",), openssf=("Scorecard: Pinned-Dependencies",), references=(_REF_SCORECARD_PINNED,))
_r("COMPOSE_PRIVILEGED", C.MISCONFIGURATION, D.CONTAINER, "Privileged container",
   "Remove privileged: true; grant only the specific capabilities required.",
   cwe=("CWE-250",), attack=("T1611",), owasp=("A05:2021",))
_r("COMPOSE_DOCKER_SOCKET", C.MISCONFIGURATION, D.CONTAINER, "Docker socket mounted into container",
   "Never mount /var/run/docker.sock into application containers; it is equivalent to root on the host.",
   cwe=("CWE-668",), attack=("T1611",), owasp=("A05:2021",))
_r("COMPOSE_HOST_NETWORK", C.MISCONFIGURATION, D.CONTAINER, "Host network mode",
   "Use an explicit bridge network instead of network_mode: host.",
   cwe=("CWE-668",), owasp=("A05:2021",))
_r("CONTAINER_VULNERABILITY", C.VULNERABILITY, D.CONTAINER, "Vulnerable package in container image",
   "Rebuild on a patched base image or upgrade the affected package.",
   cwe=("CWE-1395",), owasp=("A06:2021",), ssdf=("RV.1",))
_r("CONTAINER_MISCONFIG", C.MISCONFIGURATION, D.CONTAINER, "Container misconfiguration",
   "Apply the recommended hardening for the reported configuration issue.",
   owasp=("A05:2021",), ssdf=("PW.9",))

# --- pipeline / fail-safe -----------------------------------------------------------------------------
_r("FETCH_FAILED", C.PIPELINE, D.PIPELINE, "Artifact could not be analysed",
   "Analysis was incomplete; do not treat the verdict as clean. Retry or review manually.")
_r("EXTRACTION_ABORTED", C.INTEGRITY, D.INTEGRITY, "Archive failed safe-extraction checks",
   "The archive tripped a hostile-input guard (bomb, traversal, malformed); treat the package as suspicious.",
   cwe=("CWE-409", "CWE-22"))
_r("UNPARSEABLE", C.INTEGRITY, D.INTEGRITY, "Source could not be parsed",
   "Unparseable sources evade static analysis; review manually.")
_r("ANALYZER_ERROR", C.PIPELINE, D.PIPELINE, "Analyzer failed",
   "An analyzer crashed or timed out, so analysis is incomplete; the verdict fails closed.")
_r("TOOL_UNAVAILABLE", C.PIPELINE, D.PIPELINE, "Optional analysis tool unavailable",
   "Install the tool to enable this analysis layer; results from other analyzers are unaffected.")
_r("INTEL_UNAVAILABLE", C.PIPELINE, D.PIPELINE, "Vulnerability intelligence unavailable",
   "Vulnerability status is unknown (not zero); re-run with intelligence sources reachable.")
