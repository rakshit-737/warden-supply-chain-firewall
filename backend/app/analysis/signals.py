"""Signal / finding code catalogue.

v1 called the pipeline's common currency a ``Signal``; Warden X generalises it into the
richer :class:`~app.analysis.findings.Finding`. ``Signal`` remains an alias so existing
analyzers, tests and integrations keep working unchanged.

``Code`` is the canonical catalogue of finding codes. Policies, the correlation engine, the
feature builder and tests reference these constants rather than string literals. Metadata
for each code (category, CWE, MITRE ATT&CK, remediation) lives in
:mod:`app.analysis.taxonomy`.
"""

from __future__ import annotations

from app.analysis.findings import Category, Finding, Location, Provenance, Severity

Signal = Finding


class Code:
    # --- registry metadata / reputation ------------------------------------------
    NEW_PACKAGE = "NEW_PACKAGE"
    SINGLE_MAINTAINER = "SINGLE_MAINTAINER"
    NO_SOURCE_REPO = "NO_SOURCE_REPO"
    RELEASE_FLOOD = "RELEASE_FLOOD"
    VERSION_NOT_FOUND = "VERSION_NOT_FOUND"
    YANKED_RELEASE = "YANKED_RELEASE"
    # --- behavioural static analysis -----------------------------------------------
    INSTALL_HOOK_EXEC = "INSTALL_HOOK_EXEC"
    NETWORK_EGRESS = "NETWORK_EGRESS"
    SUBPROCESS_EXEC = "SUBPROCESS_EXEC"
    SHELL_INVOCATION = "SHELL_INVOCATION"
    DYNAMIC_EXEC = "DYNAMIC_EXEC"
    DYNAMIC_IMPORT = "DYNAMIC_IMPORT"
    REFLECTION_ABUSE = "REFLECTION_ABUSE"
    NATIVE_CODE_LOADING = "NATIVE_CODE_LOADING"
    ENV_HARVEST = "ENV_HARVEST"
    FS_SENSITIVE = "FS_SENSITIVE"
    BROWSER_CREDENTIAL_ACCESS = "BROWSER_CREDENTIAL_ACCESS"
    PERSISTENCE = "PERSISTENCE"
    SUSPICIOUS_DOWNLOAD = "SUSPICIOUS_DOWNLOAD"
    DNS_EXFILTRATION = "DNS_EXFILTRATION"
    DANGEROUS_IMPORT = "DANGEROUS_IMPORT"
    # --- install-time execution vectors ----------------------------------------------
    PTH_STARTUP_HOOK = "PTH_STARTUP_HOOK"
    BUILD_BACKEND_HOOK = "BUILD_BACKEND_HOOK"
    ENTRYPOINT_SHADOWING = "ENTRYPOINT_SHADOWING"
    # --- obfuscation -------------------------------------------------------------------
    OBFUSCATION = "OBFUSCATION"
    ENCODED_EXEC = "ENCODED_EXEC"
    STRING_RECONSTRUCTION = "STRING_RECONSTRUCTION"
    LAYERED_ENCODING = "LAYERED_ENCODING"
    HEX_PAYLOAD = "HEX_PAYLOAD"
    COMPRESSED_PAYLOAD = "COMPRESSED_PAYLOAD"
    LARGE_CONSTANT = "LARGE_CONSTANT"
    MINIFIED_CODE = "MINIFIED_CODE"
    # --- artifact inventory / integrity ----------------------------------------------
    BINARY_EXECUTABLE = "BINARY_EXECUTABLE"
    NESTED_ARCHIVE = "NESTED_ARCHIVE"
    SUSPICIOUS_FILE = "SUSPICIOUS_FILE"
    HASH_MISMATCH = "HASH_MISMATCH"
    SDIST_WHEEL_MISMATCH = "SDIST_WHEEL_MISMATCH"
    # --- typosquatting / IOC -----------------------------------------------------------
    TYPOSQUAT = "TYPOSQUAT"
    IOC_MATCH = "IOC_MATCH"
    # --- secrets / external rule engines -----------------------------------------------
    # bandit B105 false positives (here and DOCKERFILE_SECRET_IN_ENV): finding code names, not credentials.
    SECRET_DETECTED = "SECRET_DETECTED"  # nosec B105
    YARA_MATCH = "YARA_MATCH"
    SEMGREP_FINDING = "SEMGREP_FINDING"
    # --- provenance / trust ------------------------------------------------------------
    PROVENANCE_ATTESTED = "PROVENANCE_ATTESTED"
    PROVENANCE_UNVERIFIED = "PROVENANCE_UNVERIFIED"
    PROVENANCE_FAILED = "PROVENANCE_FAILED"
    REPO_MISMATCH = "REPO_MISMATCH"
    MAINTAINER_CHANGED = "MAINTAINER_CHANGED"
    DORMANT_REVIVAL = "DORMANT_REVIVAL"
    # --- dependency confusion ----------------------------------------------------------
    DEPENDENCY_CONFUSION = "DEPENDENCY_CONFUSION"
    NAMESPACE_COLLISION = "NAMESPACE_COLLISION"
    INDEX_SOURCE_AMBIGUITY = "INDEX_SOURCE_AMBIGUITY"
    # --- vulnerability intelligence ----------------------------------------------------
    KNOWN_VULNERABILITY = "KNOWN_VULNERABILITY"
    KNOWN_EXPLOITED_VULNERABILITY = "KNOWN_EXPLOITED_VULNERABILITY"
    # --- dependency hygiene (project scans) --------------------------------------------
    UNPINNED_DEPENDENCY = "UNPINNED_DEPENDENCY"
    MISSING_HASHES = "MISSING_HASHES"
    # --- derived findings --------------------------------------------------------------
    BEHAVIOR_DRIFT = "BEHAVIOR_DRIFT"
    ATTACK_CHAIN = "ATTACK_CHAIN"
    # --- containers ----------------------------------------------------------------------
    DOCKERFILE_ROOT_USER = "DOCKERFILE_ROOT_USER"
    DOCKERFILE_REMOTE_ADD = "DOCKERFILE_REMOTE_ADD"
    DOCKERFILE_CURL_PIPE_SHELL = "DOCKERFILE_CURL_PIPE_SHELL"
    DOCKERFILE_SECRET_IN_ENV = "DOCKERFILE_SECRET_IN_ENV"  # nosec B105
    DOCKERFILE_UNPINNED_BASE = "DOCKERFILE_UNPINNED_BASE"
    COMPOSE_PRIVILEGED = "COMPOSE_PRIVILEGED"
    COMPOSE_DOCKER_SOCKET = "COMPOSE_DOCKER_SOCKET"
    COMPOSE_HOST_NETWORK = "COMPOSE_HOST_NETWORK"
    CONTAINER_VULNERABILITY = "CONTAINER_VULNERABILITY"
    CONTAINER_MISCONFIG = "CONTAINER_MISCONFIG"
    # --- pipeline / fail-safe ------------------------------------------------------------
    FETCH_FAILED = "FETCH_FAILED"
    EXTRACTION_ABORTED = "EXTRACTION_ABORTED"
    UNPARSEABLE = "UNPARSEABLE"
    ANALYZER_ERROR = "ANALYZER_ERROR"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    INTEL_UNAVAILABLE = "INTEL_UNAVAILABLE"


# Capability tags for policy hard-blocks.
class Capability:
    INSTALL_EXEC = "install_hook_exec"
    NETWORK = "network_egress"
    SUBPROCESS = "subprocess_exec"
    SHELL = "shell_invocation"
    DYNAMIC_EXEC = "dynamic_exec"
    ENV_HARVEST = "env_harvest"
    CREDENTIAL_ACCESS = "credential_access"
    OBFUSCATION = "obfuscation"
    TYPOSQUAT = "typosquat"
    IOC = "ioc"
    PERSISTENCE = "persistence"
    PTH_HOOK = "pth_startup_hook"
    BUILD_HOOK = "build_backend_hook"
    NATIVE_CODE = "native_code"
    # bandit B105 false positive: a capability tag, not a credential.
    SECRET = "secret"  # nosec B105
    DEPENDENCY_CONFUSION = "dependency_confusion"
    KNOWN_EXPLOITED = "known_exploited_vulnerability"


__all__ = ["Capability", "Category", "Code", "Finding", "Location", "Provenance", "Severity", "Signal"]
