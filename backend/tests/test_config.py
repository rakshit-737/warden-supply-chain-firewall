"""Settings parsing and production fail-closed validation.

``Settings`` is instantiated directly with ``_env_file=None`` so a developer's local ``.env``
cannot influence the result; init kwargs take precedence over the test environment.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import _DEFAULT_ADMIN_PASSWORD, _KNOWN_PLACEHOLDER_SECRETS, Settings

STRONG_SECRET = "Q7v" + "x9K2mP4nR8sT1wY6zB3cD5fG" + "h0JkLq"  # 33 chars, not a known placeholder
STRONG_ADMIN_PASSWORD = "A-unique-admin-passphrase-2026!"
LIST_FIELDS = (
    "CORS_ORIGINS", "TRUSTED_PROXY_IPS", "REGISTRY_HOST_ALLOWLIST", "ARTIFACT_HOST_ALLOWLIST", "ENABLED_ANALYZERS",
    "DISABLED_ANALYZERS", "SEMGREP_EXTRA_CONFIGS", "PRIVATE_PACKAGE_PATTERNS", "PRIVATE_INDEX_URLS",
)


def make(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def production(**overrides) -> Settings:
    values = {"ENV": "production", "SECRET_KEY": STRONG_SECRET, "FIRST_ADMIN_PASSWORD": STRONG_ADMIN_PASSWORD,
              "DEBUG": False}
    values.update(overrides)
    return make(**values)


# --------------------------------------------------------------------------- list parsing
@pytest.mark.parametrize("field", LIST_FIELDS)
def test_comma_separated_lists_from_environment(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(field, " alpha, beta ,,gamma ")
    assert getattr(make(), field) == ["alpha", "beta", "gamma"]


@pytest.mark.parametrize("field", LIST_FIELDS)
def test_json_array_lists_from_environment(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(field, '["one", "two,with,commas"]')
    assert getattr(make(), field) == ["one", "two,with,commas"]


def test_empty_list_and_init_kwargs() -> None:
    assert make(TRUSTED_PROXY_IPS="").TRUSTED_PROXY_IPS == []
    assert make(TRUSTED_PROXY_IPS="10.0.0.1, 10.0.0.0/8").TRUSTED_PROXY_IPS == ["10.0.0.1", "10.0.0.0/8"]
    assert make(CORS_ORIGINS=["http://a"]).CORS_ORIGINS == ["http://a"]


def test_malformed_json_list_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", '["http://a", ')
    with pytest.raises(ValidationError):
        make()


def test_numeric_and_boolean_settings_parse_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "1024")
    monkeypatch.setenv("METRICS_ENABLED", "false")
    monkeypatch.setenv("INTEL_RATE_LIMIT_PER_SECOND", "2.5")
    s = make()
    assert s.MAX_REQUEST_BODY_BYTES == 1024 and s.METRICS_ENABLED is False and s.INTEL_RATE_LIMIT_PER_SECOND == 2.5


# --------------------------------------------------------------------------- ENV
def test_env_is_normalised_and_validated() -> None:
    assert make(ENV=" Staging ").ENV == "staging"
    with pytest.raises(ValidationError):
        make(ENV="prod")


def test_development_generates_a_random_secret_when_none_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECRET_KEY", raising=False)
    a, b = make(ENV="development"), make(ENV="development")
    assert len(a.SECRET_KEY) >= 32 and a.SECRET_KEY != b.SECRET_KEY


# --------------------------------------------------------------------------- production hardening
def test_hardened_production_configuration_is_accepted() -> None:
    s = production()
    assert s.ENV == "production" and not s.DEBUG


def test_env_normalisation_cannot_bypass_production_checks() -> None:
    with pytest.raises(ValidationError):
        production(ENV=" PRODUCTION ", SECRET_KEY="changeme")


@pytest.mark.parametrize("secret", sorted(_KNOWN_PLACEHOLDER_SECRETS))
def test_production_rejects_placeholder_secret_keys(secret: str) -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        production(SECRET_KEY=secret)
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        production(SECRET_KEY=f"  {secret.upper()}  ")


@pytest.mark.parametrize("unfilled", ["", " "])
def test_production_rejects_unfilled_secret_key(unfilled: str) -> None:
    # What an unfilled ``SECRET_KEY=`` line from an example .env file produces.
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        production(SECRET_KEY=unfilled)


def test_production_rejects_short_secret_key() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        production(SECRET_KEY="x" * 31)
    assert production(SECRET_KEY="x" * 32).SECRET_KEY == "x" * 32


def test_production_rejects_default_admin_password() -> None:
    with pytest.raises(ValidationError, match="FIRST_ADMIN_PASSWORD"):
        production(FIRST_ADMIN_PASSWORD=_DEFAULT_ADMIN_PASSWORD)


@pytest.mark.parametrize("secret", ["\t" * 40, " " * 64, "\n \t" * 20], ids=["tabs", "spaces", "mixed"])
def test_production_rejects_whitespace_only_secret_key_of_any_length(secret: str) -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        production(SECRET_KEY=secret)


@pytest.mark.parametrize("password", ["", "short", "x" * 11, " " * 20], ids=["empty", "short", "eleven", "blank"])
def test_production_rejects_empty_or_short_admin_password(password: str) -> None:
    with pytest.raises(ValidationError, match="FIRST_ADMIN_PASSWORD"):
        production(FIRST_ADMIN_PASSWORD=password)
    assert production(FIRST_ADMIN_PASSWORD="x" * 12).FIRST_ADMIN_PASSWORD == "x" * 12


def test_production_rejects_debug() -> None:
    with pytest.raises(ValidationError, match="DEBUG"):
        production(DEBUG=True)


def test_production_sandbox_requires_gvisor() -> None:
    with pytest.raises(ValidationError, match="runsc"):
        production(SANDBOX_ENABLED=True, SANDBOX_RUNTIME="runc")
    assert production(SANDBOX_ENABLED=True, SANDBOX_RUNTIME="runsc").SANDBOX_ENABLED


def test_non_production_environments_do_not_fail_closed() -> None:
    s = make(ENV="development", SECRET_KEY="changeme", FIRST_ADMIN_PASSWORD=_DEFAULT_ADMIN_PASSWORD, DEBUG=True)
    assert s.DEBUG and s.SECRET_KEY == "changeme"
