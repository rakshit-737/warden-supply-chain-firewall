"""System information routes (``system:read``: admin and auditor).

``GET /system/info`` describes how *this deployment* is configured — version, environment,
feature switches and enforced limits — so operators and auditors can verify its security
posture without shell access.

``GET /system/tools`` reports whether the optional external analysis tools are installed
(``available``/``version``/``detail`` per tool). Binaries are located on ``PATH`` and asked for
their version through the hardened runner in :mod:`app.analysis.tools` (no shell, bounded
time and output); results are cached per process. The YARA engine is a Python module and is
only *located*, not imported. Each probe also updates the ``tool_available{tool}`` gauge.

Both endpoints deliberately return only versions, booleans, short status text and numeric
limits. Secrets, connection strings and filesystem paths (``SECRET_KEY``, ``DATABASE_URL``,
``REDIS_URL``, ``METRICS_TOKEN``, ``NVD_API_KEY``, private index URLs, tool binary paths ...)
are never included, not even redacted.
"""

from __future__ import annotations

import importlib.util
from typing import Any

from fastapi import APIRouter, Depends

from app import __version__
from app.api.deps import require_permission
from app.core import metrics, tracing
from app.core.cache import cache
from app.core.config import settings
from app.core.logging import get_logger
from app.core.permissions import Permission

# RBAC (SPEC §6): system:read is granted to admin and auditor.
_require_system_read = require_permission(Permission.SYSTEM_READ)

router = APIRouter(prefix="/system", tags=["system"])
log = get_logger("warden.system")

# (reported name, settings attribute holding the binary, settings attribute enabling it or None)
_BINARY_TOOLS: tuple[tuple[str, str, str | None], ...] = (
    ("semgrep", "SEMGREP_BINARY", "SEMGREP_ENABLED"),
    ("gitleaks", "GITLEAKS_BINARY", "GITLEAKS_ENABLED"),
    ("syft", "SYFT_BINARY", None),
    ("grype", "GRYPE_BINARY", None),
    ("trivy", "TRIVY_BINARY", None),
)


def system_info() -> dict[str, Any]:
    s = settings
    return {
        "name": s.PROJECT_NAME,
        "version": __version__,
        "env": s.ENV,
        "analyzer_version": s.ANALYZER_VERSION,
        "features": {
            "intel": {"enabled": s.INTEL_ENABLED, "offline": s.INTEL_OFFLINE, "nvd_enabled": s.NVD_ENABLED},
            "provenance": s.PROVENANCE_ENABLED,
            "monitoring": s.MONITOR_ENABLED,
            "sandbox": s.SANDBOX_ENABLED,
            "metrics": {"enabled": s.METRICS_ENABLED, "token_required": bool(s.METRICS_TOKEN)},
            "tracing": {"enabled": s.OTEL_ENABLED, "active": tracing.is_enabled()},
            "analyze_wheels": s.ANALYZE_WHEELS,
            "sbom_resolve_transitive": s.SBOM_RESOLVE_TRANSITIVE,
            # Configuration switches only; whether a tool binary is installed is reported by the tools endpoint.
            "external_tools_enabled": {"yara": s.YARA_ENABLED, "semgrep": s.SEMGREP_ENABLED,
                                       "gitleaks": s.GITLEAKS_ENABLED},
        },
        "limits": {
            "max_request_body_bytes": s.MAX_REQUEST_BODY_BYTES,
            "rate_limit_per_minute": s.RATE_LIMIT_PER_MINUTE,
            "auth_rate_limit_per_minute": s.AUTH_RATE_LIMIT_PER_MINUTE,
            "max_download_bytes": s.MAX_DOWNLOAD_BYTES,
            "max_extracted_bytes": s.MAX_EXTRACTED_BYTES,
            "max_extracted_files": s.MAX_EXTRACTED_FILES,
            "max_analyzed_file_bytes": s.MAX_ANALYZED_FILE_BYTES,
            "max_metadata_bytes": s.MAX_METADATA_BYTES,
            "max_manifest_bytes": s.MAX_MANIFEST_BYTES,
            "max_project_components": s.MAX_PROJECT_COMPONENTS,
            "max_graph_nodes": s.MAX_GRAPH_NODES,
            "scan_timeout_seconds": s.SCAN_TIMEOUT_SECONDS,
            "analyzer_timeout_seconds": s.ANALYZER_TIMEOUT_SECONDS,
            "analyzer_workers": s.ANALYZER_WORKERS,
            "tool_timeout_seconds": s.TOOL_TIMEOUT_SECONDS,
        },
        "runtime": {
            "cache_backend": cache.backend,
            "trusted_proxies_configured": bool(s.TRUSTED_PROXY_IPS),
        },
    }


def _tool_entry(name: str, available: bool, version: str | None, detail: str | None) -> dict[str, Any]:
    metrics.set_tool_available(name, available)
    return {"name": name, "available": bool(available), "version": version, "detail": detail}


def _yara_status() -> dict[str, Any]:
    try:
        found = importlib.util.find_spec("yara") is not None
    except (ImportError, ValueError):
        found = False
    detail = "python module yara-python" if found else "python module yara-python not installed"
    return _tool_entry("yara", found, None, detail if settings.YARA_ENABLED else f"{detail}; disabled by configuration")


def tool_statuses() -> list[dict[str, Any]]:
    """Availability of each optional external tool; never raises (a failed probe = unavailable)."""
    from app.analysis.tools import find_tool  # imported lazily: /system/info must not need the analysis stack

    statuses = [_yara_status()]
    for name, binary_setting, enabled_setting in _BINARY_TOOLS:
        try:
            status = find_tool(str(getattr(settings, binary_setting)))
            available, version, detail = bool(status.available), status.version, status.detail
        except Exception as exc:  # defensive: report the tool as unavailable rather than failing the endpoint
            log.warning("tool_probe_failed", tool=name, error_type=type(exc).__name__)
            available, version, detail = False, None, f"probe failed ({type(exc).__name__})"
        if enabled_setting is not None and not getattr(settings, enabled_setting):
            detail = f"{detail}; disabled by configuration" if detail else "disabled by configuration"
        statuses.append(_tool_entry(name, available, version, detail))
    return statuses


@router.get("/info", dependencies=[Depends(_require_system_read)])
def info() -> dict[str, Any]:
    return system_info()


@router.get("/tools", dependencies=[Depends(_require_system_read)])
def tools() -> list[dict[str, Any]]:
    return tool_statuses()
