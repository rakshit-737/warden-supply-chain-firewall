"""Application configuration.

All configuration comes from the environment (12-factor). The settings object is
validated at import time and fails closed: a production deployment that is missing a
strong secret or is left with an insecure default will refuse to start rather than run
insecurely.

List-valued settings accept either a JSON array or a comma-separated string
(``CORS_ORIGINS=http://a,http://b``).
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

StrList = Annotated[list[str], NoDecode]

_KNOWN_PLACEHOLDER_SECRETS = {
    "please-override-with-a-long-random-secret-value-1234",
    "change-me-to-a-long-random-value",
    "changeme",
    "secret",
}
_DEFAULT_ADMIN_PASSWORD = "ChangeMe_Warden!2026"  # nosec B105 - dev default; rejected in production


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Environment -------------------------------------------------------
    ENV: str = Field(default="development", description="development|staging|production")
    DEBUG: bool = False

    # --- Server ------------------------------------------------------------
    PROJECT_NAME: str = "Warden — Software Supply-Chain Security Platform"
    API_V1_PREFIX: str = "/api/v1"
    HOST: str = "0.0.0.0"  # nosec B104 - binding all interfaces is intended inside a container
    PORT: int = 8000

    # --- Security ----------------------------------------------------------
    # A random secret is generated if none is supplied so local dev works out of the box;
    # production is *required* to supply one (enforced below).
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 15
    REFRESH_TOKEN_TTL_DAYS: int = 7
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 2
    # Key for keyed fingerprints of discovered secrets (defaults to SECRET_KEY).
    SECRET_FINGERPRINT_KEY: str | None = None

    CORS_ORIGINS: StrList = Field(default_factory=lambda: ["http://localhost:5173"])

    # --- First-run bootstrap admin ----------------------------------------
    FIRST_ADMIN_EMAIL: str = "admin@warden.io"
    FIRST_ADMIN_PASSWORD: str = _DEFAULT_ADMIN_PASSWORD

    # --- Datastores --------------------------------------------------------
    DATABASE_URL: str = "sqlite+pysqlite:///./warden.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    # If Redis is unavailable, fall back to an in-process limiter/cache (dev only).
    REDIS_OPTIONAL: bool = True

    # --- API hardening -----------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 120
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10
    MAX_REQUEST_BODY_BYTES: int = 4 * 1024 * 1024
    # Proxies whose X-Forwarded-For header is trusted for client-IP rate limiting.
    TRUSTED_PROXY_IPS: StrList = Field(default_factory=list)

    # --- Analysis pipeline -------------------------------------------------
    ANALYZER_VERSION: str = "2.0.0"
    FETCH_TIMEOUT_SECONDS: int = 20
    MAX_DOWNLOAD_BYTES: int = 25 * 1024 * 1024  # compressed artifact cap
    MAX_EXTRACTED_BYTES: int = 120 * 1024 * 1024  # decompressed cap for retained members
    # Cap on the *declared* size of every member, including skipped ones: skipping a member
    # still decompresses it, so an unbounded skipped member is a decompression bomb.
    MAX_DECLARED_ARCHIVE_BYTES: int = 512 * 1024 * 1024
    MAX_EXTRACTED_FILES: int = 25000  # generous: real packages (numpy, etc.) are large
    MAX_ANALYZED_FILE_BYTES: int = 2 * 1024 * 1024  # per-file parse cap
    MAX_RETAINED_BINARY_BYTES: int = 32 * 1024 * 1024  # raw non-text bytes kept for YARA/secrets
    MAX_RETAINED_BINARY_FILE_BYTES: int = 4 * 1024 * 1024
    MAX_PATH_LENGTH: int = 512
    MAX_PATH_DEPTH: int = 32
    MAX_METADATA_BYTES: int = 32 * 1024 * 1024  # registry JSON responses (numpy's is large)
    EXTRACTION_TIMEOUT_SECONDS: int = 60  # wall-clock budget for reading one archive
    # Whole-scan budget. Measured on a large real sdist (numpy: 8k members, ~20 MB), fetching and
    # extracting alone took 20-120s depending on link speed, and analyzers add ~30s. Too small a
    # budget turns an ordinary big package into an "incomplete analysis" verdict, which fails
    # closed and therefore reads as risk.
    SCAN_TIMEOUT_SECONDS: int = 300
    ANALYZER_TIMEOUT_SECONDS: int = 60
    ANALYZER_WORKERS: int = 4
    PYPI_JSON_BASE: str = "https://pypi.org/pypi"
    PYPI_SIMPLE_BASE: str = "https://pypi.org/simple"
    PYPI_INTEGRITY_API_BASE: str = "https://pypi.org/integrity"
    REGISTRY_HOST_ALLOWLIST: StrList = Field(default_factory=lambda: ["pypi.org"])
    ARTIFACT_HOST_ALLOWLIST: StrList = Field(default_factory=lambda: ["files.pythonhosted.org"])
    ANALYZE_WHEELS: bool = True
    # Fail closed: a requested version that does not exist is an error, never "scan latest".
    FAIL_ON_VERSION_NOT_FOUND: bool = True
    VERDICT_CACHE_TTL_SECONDS: int = 3600
    # Fusion mode for combining rule and ml scores: "max" (conservative) or "mean".
    SCORE_FUSION: str = "max"
    ENABLED_ANALYZERS: StrList = Field(default_factory=list)  # empty = all registered
    DISABLED_ANALYZERS: StrList = Field(default_factory=list)

    # --- External analysis tools (all optional; degrade gracefully) -------
    TOOL_TIMEOUT_SECONDS: int = 120
    YARA_ENABLED: bool = True
    YARA_RULES_DIR: str | None = None  # default: packaged rules
    SEMGREP_ENABLED: bool = True
    SEMGREP_BINARY: str = "semgrep"
    SEMGREP_EXTRA_CONFIGS: StrList = Field(default_factory=list)
    GITLEAKS_ENABLED: bool = True
    GITLEAKS_BINARY: str = "gitleaks"
    SYFT_BINARY: str = "syft"
    GRYPE_BINARY: str = "grype"
    TRIVY_BINARY: str = "trivy"
    CONTAINER_SCAN_TIMEOUT_SECONDS: int = 900
    # Upload limit for POST /containers/scans only (every other route keeps MAX_REQUEST_BODY_BYTES).
    # Images are analysed in memory, so this also bounds per-scan memory; scans run one at a time.
    MAX_IMAGE_UPLOAD_BYTES: int = 256 * 1024 * 1024

    # --- Vulnerability intelligence ---------------------------------------
    INTEL_ENABLED: bool = True
    INTEL_OFFLINE: bool = False
    OSV_API_BASE: str = "https://api.osv.dev"
    KEV_FEED_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_BASE: str = "https://api.first.org/data/v1/epss"
    NVD_ENABLED: bool = False  # opt-in: strict public rate limits
    NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str | None = None
    INTEL_TIMEOUT_SECONDS: int = 15
    INTEL_RATE_LIMIT_PER_SECOND: float = 5.0
    INTEL_CACHE_TTL_SECONDS: int = 6 * 3600
    KEV_CACHE_TTL_SECONDS: int = 12 * 3600
    EPSS_CACHE_TTL_SECONDS: int = 24 * 3600

    # --- Provenance / dependency confusion ---------------------------------
    PROVENANCE_ENABLED: bool = True
    DORMANCY_THRESHOLD_DAYS: int = 365
    PRIVATE_PACKAGE_PATTERNS: StrList = Field(default_factory=list)  # e.g. "acme-*,acme_internal*"
    PRIVATE_INDEX_URLS: StrList = Field(default_factory=list)
    # Local snapshot of public index project names; avoids per-name lookups that would
    # disclose private package names to the public registry.
    PUBLIC_INDEX_SNAPSHOT_PATH: str | None = None
    DEPCONF_ALLOW_PUBLIC_LOOKUP: bool = False

    # --- SBOM / dependency graph -----------------------------------------
    MAX_MANIFEST_BYTES: int = 2 * 1024 * 1024
    MAX_PROJECT_COMPONENTS: int = 2000
    MAX_GRAPH_NODES: int = 5000
    SBOM_RESOLVE_TRANSITIVE: bool = False

    # --- Monitoring / events ------------------------------------------------
    MONITOR_ENABLED: bool = False
    MONITOR_POLL_INTERVAL_SECONDS: int = 3600
    MONITOR_BATCH_SIZE: int = 25
    MONITOR_JITTER_SECONDS: int = 120
    EVENT_STREAM_KEY: str = "warden:events"
    EVENT_STREAM_MAXLEN: int = 10000
    SCAN_QUEUE_STREAM: str = "warden:scan-jobs"

    # --- Observability -----------------------------------------------------
    METRICS_ENABLED: bool = True
    METRICS_TOKEN: str | None = None  # when set, /metrics requires "Authorization: Bearer <token>"
    OTEL_ENABLED: bool = False

    # --- Machine learning ---------------------------------------------------
    # Optional sha256 pin of the model artifact; a mismatch disables the model (rules-only).
    MODEL_ARTIFACT_SHA256: str | None = None

    # --- Optional dynamic sandbox (opt-in, off by default) ------------------
    SANDBOX_ENABLED: bool = False
    SANDBOX_RUNTIME: str = "runsc"
    SANDBOX_IMAGE: str | None = None
    SANDBOX_TIMEOUT_SECONDS: int = 120
    SANDBOX_MEMORY_MB: int = 512
    SANDBOX_CPUS: float = 1.0
    SANDBOX_PIDS_LIMIT: int = 128

    @field_validator(
        "CORS_ORIGINS", "TRUSTED_PROXY_IPS", "REGISTRY_HOST_ALLOWLIST", "ARTIFACT_HOST_ALLOWLIST",
        "ENABLED_ANALYZERS", "DISABLED_ANALYZERS", "SEMGREP_EXTRA_CONFIGS", "PRIVATE_PACKAGE_PATTERNS",
        "PRIVATE_INDEX_URLS",
        mode="before",
    )
    @classmethod
    def _split_list(cls, v: object) -> object:
        if isinstance(v, str):
            stripped = v.strip()
            if stripped.startswith("["):
                import json

                return json.loads(stripped)
            return [o.strip() for o in stripped.split(",") if o.strip()]
        return v

    @field_validator("ENV")
    @classmethod
    def _env(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in {"development", "staging", "production", "test"}:
            raise ValueError("ENV must be one of development|staging|production|test")
        return v

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> Settings:
        if self.SANDBOX_ENABLED:
            # Only the settings exist (docs/SANDBOX.md); refusing the switch keeps /system/info and
            # the console from reporting a dynamic-analysis layer that does not run.
            raise ValueError("SANDBOX_ENABLED is not supported: the dynamic sandbox is not implemented "
                             "in this version.")
        if self.ENV == "production":
            # Length is measured after stripping, so a whitespace-only value cannot pass.
            secret = self.SECRET_KEY.strip()
            if len(secret) < 32 or secret.lower() in _KNOWN_PLACEHOLDER_SECRETS:
                raise ValueError("SECRET_KEY must be a strong, non-placeholder value (>=32 chars) in production.")
            # 12 matches the registration password minimum (RegisterRequest).
            if self.FIRST_ADMIN_PASSWORD == _DEFAULT_ADMIN_PASSWORD or len(self.FIRST_ADMIN_PASSWORD.strip()) < 12:
                raise ValueError("FIRST_ADMIN_PASSWORD must be changed from its default (>=12 chars) in production.")
            if self.DEBUG:
                raise ValueError("DEBUG must be False in production.")
        return self

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
