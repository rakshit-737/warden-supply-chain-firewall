import type { SystemInfo, ToolStatus } from "../../api/types";

// Test fixtures: hand-written payloads in the shape of GET /system/info and GET /system/tools
// (backend api/routers/system.py). They are not data from a deployment.

export const PRODUCTION_INFO: SystemInfo = {
  name: "Warden",
  version: "2.1.0",
  env: "production",
  analyzer_version: "2.0.0",
  features: {
    intel: { enabled: true, offline: false, nvd_enabled: false },
    provenance: true,
    monitoring: true,
    sandbox: false,
    metrics: { enabled: true, token_required: true },
    tracing: { enabled: false, active: false },
    analyze_wheels: true,
    sbom_resolve_transitive: false,
    external_tools_enabled: { yara: true, semgrep: true, gitleaks: false },
  },
  limits: {
    max_request_body_bytes: 4 * 1024 * 1024,
    rate_limit_per_minute: 120,
    auth_rate_limit_per_minute: 10,
    max_download_bytes: 25 * 1024 * 1024,
    max_extracted_bytes: 200 * 1024 * 1024,
    max_extracted_files: 5000,
    max_analyzed_file_bytes: 1024 * 1024,
    max_metadata_bytes: 512 * 1024,
    max_manifest_bytes: 2 * 1024 * 1024,
    max_project_components: 2000,
    max_graph_nodes: 5000,
    scan_timeout_seconds: 180,
    analyzer_timeout_seconds: 60,
    analyzer_workers: 4,
    tool_timeout_seconds: 90,
  },
  runtime: { cache_backend: "redis", trusted_proxies_configured: true },
};

/** Development defaults: no metrics token, in-process cache, no trusted proxies. */
export const DEVELOPMENT_INFO: SystemInfo = {
  ...PRODUCTION_INFO,
  env: "development",
  features: { ...PRODUCTION_INFO.features, metrics: { enabled: true, token_required: false } },
  runtime: { cache_backend: "in_process", trusted_proxies_configured: false },
};

export const TOOLS: ToolStatus[] = [
  { name: "yara", available: true, version: null, detail: "python module yara-python" },
  { name: "semgrep", available: false, version: null, detail: "not found" },
  { name: "gitleaks", available: false, version: null, detail: "not found; disabled by configuration" },
  { name: "syft", available: true, version: "1.18.1", detail: null },
];

export const ALL_TOOLS_AVAILABLE: ToolStatus[] = TOOLS.map((tool) => ({ ...tool, available: true }));
