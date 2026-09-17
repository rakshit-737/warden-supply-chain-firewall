"""Tests for ``app.core.redaction``: detector coverage, idempotency, escaping and evidence bounding.

Secret-shaped fixtures are assembled at runtime from fragments so repository secret scanners
do not flag this file. None of them is a real credential.
"""

from __future__ import annotations

import json
from collections import namedtuple

import pytest
from hypothesis import HealthCheck, given
from hypothesis import settings as hsettings
from hypothesis import strategies as st

from app.analysis.findings import Finding, Severity
from app.core import redaction
from app.core.redaction import (
    PRIVATE_KEY_MARKER,
    SECRET_PATTERNS,
    find_secrets,
    fingerprint,
    html_escape,
    is_redaction_marker,
    markdown_escape,
    redact_structure,
    redact_text,
    redact_value,
    sanitize_evidence,
    sanitize_text,
    structlog_redactor,
    terminal_safe,
)


def _j(*parts: str) -> str:
    return "".join(parts)


_PEM_BODY = _j("MIIEow", "IBAAKCAQEA", "q7BFUuQ8XrZsmN2y", "x4d0PvQ3J9Kw")
_PASSWORD_WITH_AT = _j("S3cr3t", "@", "Passw0rd")
_BEARER = _j("abcdefghij", "klmnopqrst", "uvwxyz012345")
_STRIPE = _j("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc")
_JWT = _j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".",
          "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")

# detector -> (text containing the secret, the secret value that must not survive redaction)
SAMPLES: dict[str, tuple[str, str]] = {
    "private_key": (
        _j("-----BEGIN RSA ", "PRIVATE KEY-----\n", _PEM_BODY, "\n-----END RSA ", "PRIVATE KEY-----"),
        _PEM_BODY,
    ),
    "aws_access_key_id": (_j("AKIA", "IOSFODNN7EXAMPLE"), _j("AKIA", "IOSFODNN7EXAMPLE")),
    "github_token": (_j("ghp_", "a1B2" * 9), _j("ghp_", "a1B2" * 9)),
    "github_fine_grained_pat": (_j("github_pat_", "11ABCDEFG0", "123456789_abcdefghijklmn"),
                                _j("github_pat_", "11ABCDEFG0", "123456789_abcdefghijklmn")),
    "gitlab_token": (_j("glpat-", "abcdefghij", "0123456789"), _j("glpat-", "abcdefghij", "0123456789")),
    "slack_token": (_j("xoxb-", "1234567890-", "abcdefghij"), _j("xoxb-", "1234567890-", "abcdefghij")),
    "slack_webhook": (_j("https://hooks.slack.com/services/", "T0000000/B0000000/", "X" * 24),
                      _j("https://hooks.slack.com/services/", "T0000000/B0000000/", "X" * 24)),
    "stripe_secret_key": (_STRIPE, _STRIPE),
    "google_api_key": (_j("AIza", "Sy", "A" * 33), _j("AIza", "Sy", "A" * 33)),
    "pypi_token": (_j("pypi-", "AgEIcHlwaS5vcmc", "x" * 60), _j("pypi-", "AgEIcHlwaS5vcmc", "x" * 60)),
    "npm_token": (_j("npm_", "b" * 36), _j("npm_", "b" * 36)),
    "anthropic_api_key": (_j("sk-ant-", "api03-", "c" * 40), _j("sk-ant-", "api03-", "c" * 40)),
    "openai_api_key": (_j("sk-", "proj-", "d" * 40), _j("sk-", "proj-", "d" * 40)),
    "jwt": (_JWT, _JWT),
    "url_credentials": (_j("postgres://warden:", _PASSWORD_WITH_AT, "@db.example.com:5432/warden"), _PASSWORD_WITH_AT),
    "bearer_token": (_j("Authorization: Bearer ", _BEARER), _BEARER),
    "authorization_header": (_j("Authorization: Basic ", "dXNlcjpwYXNz", "d29yZA=="), _j("dXNlcjpwYXNz", "d29yZA==")),
    "auth_scheme_credentials": (_j("Bearer ", _BEARER), _BEARER),
}
_GROUP_DETECTORS = {"url_credentials", "bearer_token", "authorization_header", "auth_scheme_credentials"}


# --------------------------------------------------------------------------- detector coverage
def test_every_secret_detector_has_a_sample() -> None:
    assert set(SAMPLES) == {detector for detector, _ in SECRET_PATTERNS}


@pytest.mark.parametrize("detector", sorted(SAMPLES))
def test_detector_finds_and_redacts_its_secret(detector: str) -> None:
    sample, secret = SAMPLES[detector]
    text = f'config = {{"value": "{sample}"}} # trailing context'

    hits = [h for h in find_secrets(text) if h[0] == detector]
    assert hits, f"{detector} did not match its sample"
    # Pattern-with-group detectors report the secret group; others the whole match (e.g. a PEM block).
    assert any(secret in value and text[start:end] == value for _, start, end, value in hits)

    out = redact_text(text)
    assert secret not in out
    assert secret[4:] not in out  # nothing beyond the kept type prefix
    assert out.endswith("# trailing context")
    assert redact_text(out) == out
    assert secret not in sanitize_text(text, max_len=0)

    if detector == "private_key":
        assert PRIVATE_KEY_MARKER in out
    elif detector in _GROUP_DETECTORS:
        assert "[REDACTED]" in out
    else:
        assert f"[REDACTED:{detector}]" in out


def test_url_credentials_redacts_password_only_urls_and_passwords_containing_at() -> None:
    assert redact_text("redis://:hunter2hunter2@cache:6379/0") == "redis://:[REDACTED]@cache:6379/0"
    out = redact_text("https://user:p@ss@host.example/x")
    assert out == "https://user:[REDACTED]@host.example/x"
    assert "ss@" not in out


@pytest.mark.parametrize("username_detector", ["aws_access_key_id", "github_token", "jwt", "npm_token"])
def test_url_password_is_redacted_even_when_the_username_looks_like_a_token(username_detector: str) -> None:
    """Regression: a token pattern rewrote the username first, and the '[' in its marker stopped
    url_credentials from matching, leaving the password in clear text."""
    user = SAMPLES[username_detector][1]
    password = _j("wJalrXUtnFEMI", "K7MDENGbPxRfiCY", "EXAMPLEKEY")
    text = f"s3://{user}:{password}@bucket/object"
    out = redact_text(text)
    assert password not in out and user[4:] not in out
    assert out.endswith(":[REDACTED]@bucket/object")
    assert redact_text(out) == out
    assert password not in sanitize_text(text, max_len=0)
    assert password not in json.dumps(sanitize_evidence({"snippet": text}))


@pytest.mark.parametrize(("text", "secret"), [
    (_j("Authorization: Basic ", "dXNlcjpwYXNzd29yZA=="), "dXNlcjpwYXNzd29yZA=="),
    (_j("[(b'authorization', b'Bearer ", _BEARER, "')]"), _BEARER),
    (_j("Bearer ", _BEARER), _BEARER),
    (_j("curl -H 'Proxy-Authorization: Basic ", "YWRtaW46czNjcjN0", "'"), "YWRtaW46czNjcjN0"),
    (_j('headers = {"Authorization": "Token ', "9f8e7d6c5b4a39281706", '"}'), "9f8e7d6c5b4a39281706"),
])
def test_http_authorization_credentials_are_redacted(text: str, secret: str) -> None:
    """Regression: only 'Authorization: Bearer <16+ chars>' used to be redacted."""
    out = redact_text(text)
    assert secret not in out and "[REDACTED]" in out
    assert redact_text(out) == out


def test_auth_scheme_words_in_prose_are_not_redacted() -> None:
    for prose in ("Use basic authentication-and-authorization here", "A Bearer token is required",
                  "basic usage example"):
        assert redact_text(prose) == prose


def test_secret_named_keys_redact_values_of_every_type() -> None:
    """Regression: only non-empty strings were redacted under secret-named keys."""
    event = {
        "password": ["hunter2"], "token": b"hunter2", "api_key": 123456, "cookies": {"session": "abc123sessionid"},
        "credentials": {"user": "a", "pass": "hunter2"}, "secret": ("hunter2",), "authorization": None,
        "token_valid": True, "password_hint": "",
    }
    expected = {k: "[REDACTED]" for k in ("password", "token", "api_key", "cookies", "credentials", "secret")}
    expected.update(authorization=None, token_valid=True, password_hint="")
    logged = redact_structure(event)
    assert logged == expected and redact_structure(logged) == logged
    stored = sanitize_evidence(event)
    assert stored == expected and sanitize_evidence(stored) == stored
    assert "hunter2" not in repr(logged) + json.dumps(stored) and "abc123sessionid" not in repr(logged)
    # Explicitly safe counters survive.
    assert redact_structure({"revoked_tokens": 2}) == {"revoked_tokens": 2}
    assert sanitize_evidence({"revoked_refresh_tokens": 1}) == {"revoked_refresh_tokens": 1}


def test_private_key_redaction_keeps_trailing_text_and_is_idempotent() -> None:
    text = SAMPLES["private_key"][0] + " found in settings.py line 12"
    once = redact_text(text)
    assert once == PRIVATE_KEY_MARKER + " found in settings.py line 12"
    assert redact_text(once) == once


def test_truncated_private_key_header_is_still_redacted() -> None:
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + _PEM_BODY  # no END line
    assert _PEM_BODY not in redact_text(text)


def test_redact_value_never_contains_the_secret() -> None:
    secret = SAMPLES["github_token"][1]
    shown = redact_value(secret, "github_token")
    assert secret[4:] not in shown
    assert shown == f"ghp_…[REDACTED:github_token:len={len(secret)}]"
    assert redact_value("short", "password") == "…[REDACTED:password:len=5]"
    assert redact_value(_PEM_BODY, "private_key") == PRIVATE_KEY_MARKER
    assert is_redaction_marker(shown)


def test_fingerprint_is_keyed_deterministic_and_non_reversible() -> None:
    secret = SAMPLES["aws_access_key_id"][1]
    a = fingerprint(secret, key=b"k1")
    assert a == fingerprint(secret, key=b"k1")
    assert a != fingerprint(secret, key=b"k2")
    assert a.startswith("hmac-sha256:") and len(a) == len("hmac-sha256:") + 32
    assert secret not in a
    assert fingerprint(secret).startswith("hmac-sha256:")  # default key from settings


# --------------------------------------------------------------------------- escaping
@pytest.mark.parametrize(
    "char",
    ["\x00", "\x07", "\x1b", "\r", "\x7f", "\x85", "\x9b", "\xad", "؜", "᠎", "​", "‎",
     "‏", " ", " ", "‪", "‮", "⁠", "⁦", "⁩", "﻿", "￹",
     "\U000e0041", "\U000e007f"],
)
def test_control_bidi_and_invisible_characters_are_escaped(char: str) -> None:
    out = sanitize_text(f"safe{char}text")
    assert char not in out
    assert out.startswith("safe\\") and out.endswith("text")
    assert sanitize_text(out) == out


def test_trojan_source_sequence_is_neutralised() -> None:
    hostile = "access_level = \"user‮ ⁦// Check if admin⁩ ⁦\""
    out = terminal_safe(hostile)
    assert not any(c in out for c in "‮⁦⁩")
    assert "\\u202e" in out


def test_tabs_and_newlines() -> None:
    assert sanitize_text("a\tb") == "a\tb"
    assert sanitize_text("a\nb") == "a\\nb"
    assert sanitize_text("a\nb", keep_newlines=True) == "a\nb"
    assert "\x1b" not in terminal_safe("\x1b]0;pwned\x07title")


def test_lone_surrogates_do_not_break_utf8_encoding() -> None:
    out = sanitize_text(b"caf\xe9".decode("utf-8", "surrogateescape"))
    out.encode("utf-8")
    assert "\\udce9" in out


def test_html_and_markdown_escaping() -> None:
    assert html_escape('<img src=x onerror="alert(1)">') == "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"
    md = markdown_escape("[click](javascript:alert(1)) | *bold* <b>\nnext row")
    assert "[click](" not in md and "\\[click\\]\\(" in md
    assert "\\|" in md and "\\*bold\\*" in md and "&lt;b&gt;" in md
    assert "\n" not in md  # cannot break out of a table row
    assert SAMPLES["github_token"][1] not in markdown_escape(SAMPLES["github_token"][0])


# --------------------------------------------------------------------------- bounding
def test_sanitize_text_bounds_length() -> None:
    out = sanitize_text("x" * 1000, max_len=50)
    assert len(out) == 50 and out.endswith("…")
    assert sanitize_text(out, max_len=50) == out
    assert sanitize_text("x" * 1000, max_len=0) == "x" * 1000


def test_truncation_that_creates_a_match_is_redacted() -> None:
    # 300 token characters are too long for the github pattern until the cut adds a boundary.
    text = "ghp_" + "A" * 300
    out = sanitize_text(text, max_len=200)
    assert "A" * 30 not in out
    assert sanitize_text(out, max_len=200) == out


def test_truncation_through_a_marker_stays_bounded_and_idempotent() -> None:
    text = "k" * 50 + " " + SAMPLES["private_key"][0] + " tail"
    for max_len in (30, 60, 80, 113, 120):
        out = sanitize_text(text, max_len=max_len)
        assert len(out) <= max_len
        assert _PEM_BODY not in out
        assert sanitize_text(out, max_len=max_len) == out


def test_sanitize_evidence_bounds_every_dimension() -> None:
    value = {
        "long": "y" * 1000,
        "items": list(range(100)),
        "nested": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}},
        "blob": b"\x00" * 64,
        "nan": float("nan"),
        "inf": float("-inf"),
        "tags": {"zeta", "alpha"},
        "tuple": (1, 2),
        "obj": object(),
    }
    out = sanitize_evidence(value, max_str=40, max_items=10, max_keys=50, max_depth=4)
    assert len(out["long"]) == 40
    assert len(out["items"]) == 10 and out["items"][-1] == "<91 more>"
    assert out["nested"]["a"]["b"]["c"] == "<max-depth>"
    assert out["blob"] == "<64 bytes>"
    assert out["nan"] is None and out["inf"] is None
    assert out["tags"] == ["alpha", "zeta"]
    assert out["tuple"] == [1, 2]
    assert isinstance(out["obj"], str)
    json.dumps(out)

    many = sanitize_evidence({f"k{i}": i for i in range(80)}, max_keys=10)
    assert len(many) == 10 and many["_truncated_keys"] == 71


def test_sanitize_evidence_redacts_secret_named_keys_but_keeps_safe_metadata() -> None:
    out = sanitize_evidence({
        "password": "hunter2",
        "api_key": "plain-value",
        "Authorization": "Basic dXNlcjpwYXNz",
        "secret_type": "aws_access_key_id",
        "fingerprint": "hmac-sha256:abc",
        "note": "found " + SAMPLES["slack_token"][0],
    })
    assert out["password"] == "[REDACTED]"
    assert out["api_key"] == "[REDACTED]"
    assert out["Authorization"] == "[REDACTED]"
    assert out["secret_type"] == "aws_access_key_id"
    assert out["fingerprint"] == "hmac-sha256:abc"
    assert SAMPLES["slack_token"][1] not in out["note"]


def test_marker_prefix_cannot_smuggle_a_secret_or_control_characters() -> None:
    hostile = "[REDACTED] hunter2-the-real-password \x1b[31m" + "A" * 5000
    out = sanitize_evidence({"password": hostile, "token": "xyzw…[REDACTED] but actually the secret"})
    assert out == {"password": "[REDACTED]", "token": "[REDACTED]"}


def test_genuine_markers_under_secret_keys_are_preserved() -> None:
    shown = redact_value(SAMPLES["aws_access_key_id"][1], "aws_access_key_id")
    out = sanitize_evidence({"secret": shown, "private_key": SAMPLES["private_key"][0], "token": "[REDACTED]"})
    assert out == {"secret": shown, "private_key": PRIVATE_KEY_MARKER, "token": "[REDACTED]"}


def test_finding_id_is_stable_across_round_trips_with_secret_evidence() -> None:
    evidence = {"snippet": SAMPLES["private_key"][0] + " in config.py", "url": SAMPLES["url_credentials"][0]}
    finding = Finding("TEST_SECRET", Severity.high, 1.0, "secret found", evidence)
    again = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert again.evidence == finding.evidence
    assert again.finding_id == finding.finding_id
    assert _PEM_BODY not in json.dumps(finding.to_dict())


# --------------------------------------------------------------------------- log redaction
def test_redact_structure_handles_named_tuples_sets_and_depth() -> None:
    Pair = namedtuple("Pair", "left right")
    event = {
        "event": "login " + SAMPLES["jwt"][0],
        "pair": Pair(SAMPLES["npm_token"][0], 2),
        "set": {SAMPLES["gitlab_token"][0]},
        "password": "hunter2",
        "deep": [[[[[[[[[[["x"]]]]]]]]]]],
    }
    out = structlog_redactor(None, "info", event)
    dumped = repr(out)
    for detector in ("jwt", "npm_token", "gitlab_token"):
        assert SAMPLES[detector][1] not in dumped
    assert out["password"] == "[REDACTED]"
    assert out["pair"][1] == 2
    assert "<max-depth>" in dumped
    assert redact_structure(out) == out


# --------------------------------------------------------------------------- properties
_FRAGMENTS = st.sampled_from(
    [s for s, _ in SAMPLES.values()]
    + ["\x1b[31m", "‮", "…", "[REDACTED]", "://u:", ":", "@", "/", "-----BEGIN PRIVATE KEY-----",
       "-----END PRIVATE KEY-----", PRIVATE_KEY_MARKER, "\n", "ghp_", "A" * 40, "Authorization: Bearer ", " "]
)
_TEXT = st.lists(st.one_of(st.text(max_size=30), _FRAGMENTS), max_size=8).map("".join)


@hsettings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_TEXT)
def test_redact_text_is_idempotent(text: str) -> None:
    once = redact_text(text)
    assert redact_text(once) == once


@hsettings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_TEXT, max_len=st.sampled_from([0, 1, 8, 16, 40, 64, 120, 300]))
def test_sanitize_text_is_idempotent_and_bounded(text: str, max_len: int) -> None:
    once = sanitize_text(text, max_len=max_len)
    assert sanitize_text(once, max_len=max_len) == once
    assert max_len == 0 or len(once) <= max_len
    assert redact_text(once) == once


_KEYS = st.one_of(st.sampled_from(["password", "token", "secret_type", "api_key", "note", "_truncated_keys"]), _TEXT)
_LEAVES = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(), _TEXT, st.binary(max_size=4))
_EVIDENCE = st.recursive(
    _LEAVES,
    lambda children: st.one_of(
        st.lists(children, max_size=6), st.dictionaries(_KEYS, children, max_size=6), st.frozensets(st.integers())
    ),
    max_leaves=25,
)


@hsettings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(value=_EVIDENCE)
def test_sanitize_evidence_is_idempotent_and_json_safe(value: object) -> None:
    kw = dict(max_str=40, max_items=4, max_keys=4, max_depth=3)
    once = sanitize_evidence(value, **kw)
    assert sanitize_evidence(once, **kw) == once
    json.dumps(once, allow_nan=False)


def test_module_exports_are_stable() -> None:
    for name in ("redact_text", "find_secrets", "redact_value", "fingerprint", "sanitize_text", "sanitize_evidence",
                 "terminal_safe", "html_escape", "markdown_escape", "structlog_redactor"):
        assert callable(getattr(redaction, name))


def test_escaped_bidi_prefix_does_not_hide_a_following_token() -> None:
    token = "gh" + "p_" + "A" * 36
    out = redaction.sanitize_text("pkg\u202e" + token)
    assert token not in out and "\u202e" not in out
