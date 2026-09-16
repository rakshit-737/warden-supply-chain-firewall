import { FINDING_CATEGORIES } from "../../api/types";

/**
 * Finding taxonomy an exception can be scoped to.
 *
 * The API exposes no endpoint that lists finding codes or categories, so these are static mirrors:
 * - codes: backend app/analysis/signals.py `Code` constants, grouped as in that file;
 * - categories: backend app/analysis/findings.py `Category` values (FINDING_CATEGORIES in api/types.ts);
 * - non-overridable codes: backend app/schemas/exception.py `NON_OVERRIDABLE_CODES`.
 * Keep them in sync when the backend adds a code. The server validates every request regardless.
 */

export interface FindingCodeGroup {
  label: string;
  codes: readonly string[];
}

export const FINDING_CODE_GROUPS: readonly FindingCodeGroup[] = [
  {
    label: "Registry metadata and reputation",
    codes: ["NEW_PACKAGE", "SINGLE_MAINTAINER", "NO_SOURCE_REPO", "RELEASE_FLOOD", "VERSION_NOT_FOUND", "YANKED_RELEASE"],
  },
  {
    label: "Behavioural static analysis",
    codes: [
      "INSTALL_HOOK_EXEC",
      "NETWORK_EGRESS",
      "SUBPROCESS_EXEC",
      "SHELL_INVOCATION",
      "DYNAMIC_EXEC",
      "DYNAMIC_IMPORT",
      "REFLECTION_ABUSE",
      "NATIVE_CODE_LOADING",
      "ENV_HARVEST",
      "FS_SENSITIVE",
      "BROWSER_CREDENTIAL_ACCESS",
      "PERSISTENCE",
      "SUSPICIOUS_DOWNLOAD",
      "DNS_EXFILTRATION",
      "DANGEROUS_IMPORT",
    ],
  },
  { label: "Install-time execution", codes: ["PTH_STARTUP_HOOK", "BUILD_BACKEND_HOOK", "ENTRYPOINT_SHADOWING"] },
  {
    label: "Obfuscation",
    codes: [
      "OBFUSCATION",
      "ENCODED_EXEC",
      "STRING_RECONSTRUCTION",
      "LAYERED_ENCODING",
      "HEX_PAYLOAD",
      "COMPRESSED_PAYLOAD",
      "LARGE_CONSTANT",
      "MINIFIED_CODE",
    ],
  },
  {
    label: "Artifact inventory and integrity",
    codes: ["BINARY_EXECUTABLE", "NESTED_ARCHIVE", "SUSPICIOUS_FILE", "HASH_MISMATCH", "SDIST_WHEEL_MISMATCH"],
  },
  { label: "Typosquatting and IOC", codes: ["TYPOSQUAT", "IOC_MATCH"] },
  { label: "Secrets and external rule engines", codes: ["SECRET_DETECTED", "YARA_MATCH", "SEMGREP_FINDING"] },
  {
    label: "Provenance and trust",
    codes: [
      "PROVENANCE_ATTESTED",
      "PROVENANCE_UNVERIFIED",
      "PROVENANCE_FAILED",
      "REPO_MISMATCH",
      "MAINTAINER_CHANGED",
      "DORMANT_REVIVAL",
    ],
  },
  { label: "Dependency confusion", codes: ["DEPENDENCY_CONFUSION", "NAMESPACE_COLLISION", "INDEX_SOURCE_AMBIGUITY"] },
  { label: "Vulnerability intelligence", codes: ["KNOWN_VULNERABILITY", "KNOWN_EXPLOITED_VULNERABILITY"] },
  { label: "Dependency hygiene", codes: ["UNPINNED_DEPENDENCY", "MISSING_HASHES"] },
  { label: "Derived findings", codes: ["BEHAVIOR_DRIFT", "ATTACK_CHAIN"] },
  {
    label: "Containers",
    codes: [
      "DOCKERFILE_ROOT_USER",
      "DOCKERFILE_REMOTE_ADD",
      "DOCKERFILE_CURL_PIPE_SHELL",
      "DOCKERFILE_SECRET_IN_ENV",
      "DOCKERFILE_UNPINNED_BASE",
      "COMPOSE_PRIVILEGED",
      "COMPOSE_DOCKER_SOCKET",
      "COMPOSE_HOST_NETWORK",
      "CONTAINER_VULNERABILITY",
      "CONTAINER_MISCONFIG",
    ],
  },
  {
    label: "Pipeline and fail-safe",
    codes: ["FETCH_FAILED", "EXTRACTION_ABORTED", "UNPARSEABLE", "ANALYZER_ERROR", "TOOL_UNAVAILABLE", "INTEL_UNAVAILABLE"],
  },
];

/** Never waivable (SPEC section 11): known-malware IOC matches and tampered artifacts. */
export const NON_OVERRIDABLE_CODES: readonly string[] = ["IOC_MATCH", "HASH_MISMATCH"];

/** Groups with the non-overridable codes removed: what the request form offers. */
export const EXCEPTABLE_CODE_GROUPS: readonly FindingCodeGroup[] = FINDING_CODE_GROUPS.map((group) => ({
  label: group.label,
  codes: group.codes.filter((code) => !NON_OVERRIDABLE_CODES.includes(code)),
})).filter((group) => group.codes.length > 0);

export const EXCEPTION_CATEGORIES = FINDING_CATEGORIES;
