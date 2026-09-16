"""Tests for the secrets analyzer (``app.analysis.analyzers.secrets``), its optional gitleaks adapter
and the redaction patterns added for it (``app.core.redaction``).

Every credential-shaped value is generated at runtime (seeded RNG + string concatenation) so
repository secret scanners never see a literal token; none of them is a real credential. The
gitleaks report used below is a labelled TEST FIXTURE shaped like gitleaks v8 JSON output — not
output of a real gitleaks run (gitleaks is not installed on the test host and is faked).

Analyzer inputs are source *text*; nothing in them is imported or executed.
"""

from __future__ import annotations

import json
import os
import random
import string
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given
from hypothesis import settings as hsettings
from hypothesis import strategies as st

from app.analysis import tools
from app.analysis.analyzers import secrets as sec
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, SourceFile, ToolStatus
from app.analysis.analyzers.secrets import SecretsAnalyzer
from app.analysis.findings import Finding, Severity
from app.analysis.signals import Capability, Code
from app.analysis.tools import ToolError, ToolResult
from app.core import redaction
from app.core.config import settings
from app.core.redaction import (
    ALL_SECRET_PATTERNS,
    EXTENDED_SECRET_PATTERNS,
    SECRET_PATTERNS,
    find_secrets,
    is_redaction_marker,
    redact_text,
    redact_value,
    sanitize_text,
)

# --------------------------------------------------------------------------- runtime-built fakes
_RNG = random.Random(20260915)
ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
HEX = "0123456789abcdef"
B64 = ALNUM + "+/"


def rand(alphabet: str, n: int) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def gh_token() -> str:
    return "gh" + "p_" + rand(ALNUM, 36)


def aws_key_id() -> str:
    return "AK" + "IA" + rand(UPPER_DIGITS, 16)


def aws_secret() -> str:
    while True:
        value = rand(B64, 40)
        if any(c.isupper() for c in value) and any(c.islower() for c in value) and any(c.isdigit() for c in value):
            return value


def pem_block(kind: str = "RSA ", lines: int = 6) -> tuple[str, str]:
    body = "\n".join(rand(B64, 64) for _ in range(lines))
    armour = "PRIV" + "ATE KEY-----"
    return f"-----BEGIN {kind}{armour}\n{body}\n-----END {kind}{armour}", body


def slack_app_token() -> str:
    return "xa" + "pp-1-" + rand(UPPER_DIGITS, 11) + "-" + rand(string.digits, 13) + "-" + rand(HEX, 64)


def sendgrid_key() -> str:
    return "S" + "G." + rand(ALNUM + "_-", 22) + "." + rand(ALNUM + "_-", 43)


def twilio_key() -> str:
    return "S" + "K" + rand(HEX, 32)


def mailgun_key() -> str:
    return "ke" + "y-" + rand(HEX, 32)


def uuid_like() -> str:
    return "-".join(rand(HEX, n) for n in (8, 4, 4, 4, 12))


def azure_key(length: int = 86) -> str:
    return rand(B64, length) + "=="


def stripe_live() -> str:
    return "sk" + "_live_" + rand(ALNUM, 24)


def jwt_token(payload: str) -> str:
    import base64

    def seg(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    return seg('{"alg":"HS256","typ":"JWT"}') + "." + seg(payload) + "." + rand(ALNUM + "-_", 43)


def ctx(files: dict[str, str] | None = None, *, binaries: dict[str, bytes] | None = None,
        wheel_files: dict[str, str] | None = None) -> PackageContext:
    return PackageContext(
        ecosystem="pypi", name="demo", version="1.0.0",
        files=[SourceFile(relpath=k, text=v, size=len(v)) for k, v in (files or {}).items()],
        binaries=dict(binaries or {}),
        wheel_files=[SourceFile(relpath=k, text=v, size=len(v)) for k, v in (wheel_files or {}).items()],
    )


def run(files: dict[str, str] | None = None, **kw) -> list[Finding]:
    return SecretsAnalyzer().analyze(ctx(files, **kw))


def secret_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.code == Code.SECRET_DETECTED]


def by_detector(findings: list[Finding], detector: str) -> list[Finding]:
    return [f for f in secret_findings(findings) if f.evidence["detector"] == detector]


def one(findings: list[Finding], detector: str) -> Finding:
    matches = by_detector(findings, detector)
    assert len(matches) == 1, [(f.evidence["detector"], f.location.line) for f in secret_findings(findings)]
    return matches[0]


def line_of(text: str, needle: str) -> int:
    return next(i for i, line in enumerate(text.splitlines(), start=1) if needle in line)


def assert_not_leaked(findings: list[Finding], *values: str) -> None:
    dumped = json.dumps([f.to_dict() for f in findings])
    for value in values:
        assert value not in dumped
        for i in range(4, max(5, len(value) - 12), 6):  # partial leaks beyond a four-character type prefix
            assert value[i:i + 12] not in dumped


@pytest.fixture(autouse=True)
def _gitleaks_absent(monkeypatch):
    """Default: gitleaks is not installed (deterministic even on hosts that have it)."""
    monkeypatch.setattr(settings, "GITLEAKS_ENABLED", True)
    monkeypatch.setattr(tools, "find_tool",
                        lambda binary, **kw: ToolStatus(name="gitleaks", available=False, detail="not found on PATH"))

    def no_run(*args, **kwargs):
        raise AssertionError("gitleaks must not run when it is unavailable")

    monkeypatch.setattr(tools, "run_tool", no_run)


# =========================================================================== redaction patterns
def test_extended_patterns_are_part_of_the_applied_order():
    names = [d for d, _ in ALL_SECRET_PATTERNS]
    assert len(names) == len(set(names))
    assert set(names) == {d for d, _ in SECRET_PATTERNS} | {d for d, _ in EXTENDED_SECRET_PATTERNS}
    assert names[:2] == ["private_key", "url_credentials"]
    assert names[-1] == "aws_secret_access_key"
    # Key-anchored patterns run before the v1 token patterns so a token cannot shield their value.
    assert names.index("azure_storage_key") < names.index("aws_access_key_id")


_AZ = azure_key()
_SAS = rand(B64, 43) + "="
_GCP_FIELD = rand(B64, 120)
_HEROKU = uuid_like()
_XAPP = slack_app_token()
_TWILIO = twilio_key()
_SENDGRID = sendgrid_key()
_MAILGUN = mailgun_key()
_AWS_SECRET = aws_secret()

NEW_SAMPLES: dict[str, list[tuple[str, str]]] = {
    "azure_storage_key": [
        ("DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=" + _AZ + ";EndpointSuffix=core.windows.net", _AZ),
        ("Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=" + _SAS, _SAS),
    ],
    "gcp_private_key_field": [('{"type": "service_account", "private_key": "' + _GCP_FIELD + '"}', _GCP_FIELD)],
    "heroku_api_key": [("HEROKU_API_KEY=" + _HEROKU, _HEROKU), ('heroku:\n  api_key: "' + _HEROKU + '"', _HEROKU)],
    "slack_app_token": [("SLACK_APP_TOKEN=" + _XAPP, _XAPP)],
    "twilio_api_key": [("TWILIO_API_KEY = '" + _TWILIO + "'", _TWILIO)],
    "sendgrid_api_key": [("sg = SendGridAPIClient('" + _SENDGRID + "')", _SENDGRID)],
    "mailgun_api_key": [("auth=('api', '" + _MAILGUN + "')", _MAILGUN)],
    "aws_secret_access_key": [
        ("aws_secret_access_key = " + _AWS_SECRET, _AWS_SECRET),
        ('{"SecretAccessKey": "' + _AWS_SECRET + '"}', _AWS_SECRET),
        ("export AWS_SECRET_ACCESS_KEY='" + _AWS_SECRET + "'", _AWS_SECRET),
    ],
}


@pytest.mark.parametrize(("detector", "index"), [(d, i) for d, samples in NEW_SAMPLES.items()
                                                 for i in range(len(samples))])
def test_new_redaction_patterns_find_and_redact(detector, index):
    text, secret = NEW_SAMPLES[detector][index]
    hits = [h for h in find_secrets(text) if h[0] == detector]
    assert hits and any(value == secret and text[start:end] == value for _, start, end, value in hits)
    out = redact_text(text)
    assert secret not in out and secret[4:16] not in out
    assert redact_text(out) == out
    assert secret not in sanitize_text(text, max_len=0)


@pytest.mark.parametrize("builder", [
    lambda: ("MY_TOKEN_" + (v := gh_token()), v),
    lambda: ("AWS_KEY_" + (v := aws_key_id()), v),
    lambda: ("token_" + (v := jwt_token('{"sub":"42"}')), v),
    lambda: ((v := gh_token()) + "_suffix", v),
    lambda: ("key=" + (v := stripe_live()) + "_x", v),
], ids=["github-after-identifier", "aws-after-identifier", "jwt-after-identifier", "github-before-underscore",
        "stripe-before-underscore"])
def test_tokens_glued_to_identifiers_are_redacted(builder):
    """Regression: ``\\b`` does not match between ``_`` and a letter, so MY_TOKEN_ghp_… stayed in clear text."""
    text, secret = builder()
    out = redact_text(text)
    assert secret not in out and secret[4:] not in out
    assert redact_text(out) == out


def test_url_password_after_an_identifier_scheme_is_redacted():
    password = rand(ALNUM, 20)
    out = redact_text(f"DB_URL_postgres://svc:{password}@db.internal:5432/app")
    assert password not in out and out.endswith(":[REDACTED]@db.internal:5432/app")


@pytest.mark.parametrize("benign", [
    "SharedAccessKeyName=RootManageSharedAccessKey",
    "AccountKey=<your-account-key>",
    "AccountKey=${AZURE_STORAGE_KEY}",
    '"private_key": "path/to/key.pem"',
    '"private_key_id": "' + rand(HEX, 40) + '"',
    "heroku_app_id = " + uuid_like(),
    "app_uuid: " + uuid_like(),
    "monkey-" + rand(HEX, 32),
    "api-key-" + rand(HEX, 32),
    "sk" + rand(HEX, 32),
    "SKU-1234567890",
    "SG.example.com",
    "xapp-1-example",
    "aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']",
    "commit = " + rand(HEX, 40),
    "tokenizer_name = bert-base-uncased",
    "Use basic authentication for the heroku key rotation guide",
])
def test_lookalike_benign_strings_are_not_redacted(benign):
    assert redact_text(benign) == benign
    assert find_secrets(benign) == []


def test_redact_value_can_hide_the_prefix():
    secret = aws_secret()
    assert redact_value(secret, "aws_secret_access_key", keep_prefix=False) == \
        f"…[REDACTED:aws_secret_access_key:len={len(secret)}]"
    token = gh_token()
    assert redact_value(token, "github_token") == f"{token[:4]}…[REDACTED:github_token:len={len(token)}]"
    assert is_redaction_marker(redact_value(secret, "generic_secret", keep_prefix=False))


def test_marker_shortening_a_forty_character_run_stays_idempotent():
    """A token marker can shorten a longer key run to exactly 40 characters; the AWS secret pattern runs
    last so a second pass cannot find a new match."""
    text = "aws_secret_access_key=" + rand(ALNUM, 35) + "/" + aws_key_id() + " tail"
    once = redact_text(text)
    assert redact_text(once) == once


_NEW_FRAGMENTS = st.sampled_from(
    [s for samples in NEW_SAMPLES.values() for s, _ in samples]
    + ["AccountKey=", "SharedAccessKey=", "aws_secret_access_key=", '"SecretAccessKey": "', "HEROKU_API_KEY=",
       '"private_key": "', "\\n", "xapp-1-", "SK", "SG.", "key-", "/", "+", "=", "-", "_", "[REDACTED]", "…",
       rand(B64, 40), rand(HEX, 32), rand(B64, 20), uuid_like(), "/" + aws_key_id(), gh_token(), "MY_TOKEN_",
       "postgres://u:", "@", "-----BEGIN PRIVATE KEY-----", "Authorization: Bearer "]
)
_NEW_TEXT = st.lists(st.one_of(st.text(max_size=12), _NEW_FRAGMENTS), max_size=10).map("".join)


@hsettings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_NEW_TEXT)
def test_redaction_with_new_patterns_is_idempotent(text):
    once = redact_text(text)
    assert redact_text(once) == once


@hsettings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_NEW_TEXT, max_len=st.sampled_from([0, 16, 40, 120, 300]))
def test_sanitize_text_with_new_patterns_is_idempotent_and_bounded(text, max_len):
    once = sanitize_text(text, max_len=max_len)
    assert sanitize_text(once, max_len=max_len) == once
    assert max_len == 0 or len(once) <= max_len


# =========================================================================== analyzer contract
def test_analyzer_contract_and_optional_gitleaks_availability():
    analyzer = SecretsAnalyzer()
    assert isinstance(analyzer, BaseAnalyzer)
    assert (analyzer.name, analyzer.version, analyzer.requires_network) == ("secrets", sec.ANALYZER_VERSION, False)
    status = analyzer.availability()
    assert status.available is True and status.name == "secrets"
    assert "gitleaks unavailable" in status.detail and "built-in" in status.detail
    assert analyzer.analyze(ctx({"pkg/a.py": "x = 1\n"})) == []


# --------------------------------------------------------------------------- detectors
def test_realistic_settings_module_every_detector_line_and_evidence():
    token, key_id, key_secret, stripe = gh_token(), aws_key_id(), aws_secret(), stripe_live()
    db_password, generic = rand(ALNUM, 18), rand(ALNUM + "!#%", 28)
    xapp, sendgrid = slack_app_token(), sendgrid_key()
    src = (
        '"""Service configuration."""\n'
        "import os\n"
        "\n"
        f"GITHUB_TOKEN = '{token}'\n"
        f"AWS_ACCESS_KEY_ID = '{key_id}'\n"
        f"AWS_SECRET_ACCESS_KEY = '{key_secret}'\n"
        f"DATABASE_URL = 'postgresql://svc_app:{db_password}@db.prod.internal:5432/app'\n"
        f"STRIPE_KEY = '{stripe}'\n"
        f"SLACK_APP_TOKEN = '{xapp}'\n"
        f"SENDGRID_API_KEY = '{sendgrid}'\n"
        f"API_SECRET = '{generic}'\n"
        "DEBUG = os.environ.get('DEBUG') == '1'\n"
    )
    findings = run({"svc/settings.py": src})
    expected = {
        # detector: (severity, confidence, needle)
        "github_token": (Severity.high, 0.9, "GITHUB_TOKEN"),
        "aws_access_key_id": (Severity.high, 0.85, "AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": (Severity.high, 0.9, "AWS_SECRET_ACCESS_KEY"),
        "database_url": (Severity.medium, 0.7, "DATABASE_URL"),
        "stripe_secret_key": (Severity.high, 0.9, "STRIPE_KEY"),
        "slack_app_token": (Severity.high, 0.9, "SLACK_APP_TOKEN"),
        "sendgrid_api_key": (Severity.high, 0.9, "SENDGRID_API_KEY"),
        "generic_secret": (Severity.medium, 0.5, "API_SECRET"),
    }
    assert sorted(f.evidence["detector"] for f in secret_findings(findings)) == sorted(expected)
    assert len(findings) == len(expected)
    for detector, (severity, confidence, needle) in expected.items():
        finding = one(findings, detector)
        assert (finding.severity, finding.confidence) == (severity, confidence), detector
        assert finding.capability == Capability.SECRET and finding.code == Code.SECRET_DETECTED
        assert finding.location.file == "svc/settings.py" and finding.location.line == line_of(src, needle)
        assert finding.location.column is None and finding.location.snippet is None
        ev = finding.evidence
        assert ev["context"] == "runtime"
        assert ev["fingerprint"].startswith("hmac-sha256:") and len(ev["fingerprint"]) == 44
        assert is_redaction_marker(ev["redacted"]) and isinstance(ev["length"], int) and ev["entropy"] > 3.0
        assert finding.weight == {Severity.high: 5.0, Severity.medium: 2.5}[severity]
    assert one(findings, "aws_secret_access_key").evidence["paired_access_key_id"] is True
    assert one(findings, "database_url").evidence["scheme"] == "postgresql"
    assert one(findings, "generic_secret").evidence["name"] == "API_SECRET"
    assert one(findings, "github_token").evidence["redacted"].startswith(token[:4] + "…")
    assert one(findings, "aws_secret_access_key").evidence["redacted"].startswith("…")  # no prefix for a secret key
    assert one(findings, "database_url").evidence["length"] == len(db_password)
    assert_not_leaked(findings, token, key_id, key_secret, stripe, db_password, generic, xapp, sendgrid)


def test_private_key_in_triple_quoted_string_and_json_escapes():
    block, body = pem_block()
    src = f"import ssl\n\nSERVER_KEY = '''\n{block}\n'''\n"
    finding = one(run({"pkg/tls.py": src}), "private_key")
    assert finding.location.line == line_of(src, "-----BEGIN")
    assert (finding.severity, finding.confidence) == (Severity.high, 0.9)
    assert finding.evidence["redacted"] == redaction.PRIVATE_KEY_MARKER

    escaped = json.dumps({"tls": {"key": block}})  # newlines become \n escapes on one line
    json_finding = one(run({"conf/tls.json": escaped}), "private_key")
    assert json_finding.location.line == 1
    for line in body.splitlines():
        assert_not_leaked([finding, json_finding], line)


def test_code_that_only_mentions_pem_armour_is_not_a_private_key():
    armour = "PRIV" + "ATE KEY-----"
    parser = (
        "PEM_HEADER = b'-----BEGIN RSA " + armour + "'\n"
        "PEM_FOOTER = b'-----END RSA " + armour + "'\n"
        "\n"
        "def load(data: bytes):\n"
        "    if not data.startswith(PEM_HEADER):\n"
        "        raise ValueError('not a PEM private key')\n"
        "    return data[len(PEM_HEADER):data.index(PEM_FOOTER)]\n"
    )
    assert run({"crypto/pem.py": parser}) == []


def test_real_key_after_a_header_only_mention_is_still_found():
    armour = "PRIV" + "ATE KEY-----"
    block, _ = pem_block()
    src = (
        "HEADER = '-----BEGIN RSA " + armour + "'\n"
        "def is_key(text):\n"
        "    return text.startswith(HEADER)\n"
        f"TEST_KEY = '''{block}'''\n"
    )
    finding = one(run({"pkg/keys.py": src}), "private_key")
    assert finding.location.line == 4


def test_gcp_service_account_file_is_one_finding():
    block, body = pem_block(kind="", lines=20)
    account = {
        "type": "service_account", "project_id": "acme-prod", "private_key_id": rand(HEX, 40),
        "private_key": block + "\n", "client_email": "deploy@acme-prod.iam.gserviceaccount.com",
        "client_id": rand(string.digits, 21), "token_uri": "https://oauth2.googleapis.com/token",
    }
    text = json.dumps(account, indent=2)
    findings = run({"deploy/service-account.json": text})
    finding = one(findings, "gcp_service_account")
    assert len(secret_findings(findings)) == 1
    assert finding.location.line == line_of(text, '"private_key":')
    assert (finding.severity, finding.confidence) == (Severity.high, 0.9)
    assert_not_leaked(findings, body.splitlines()[3])


def test_azure_connection_strings_and_documented_emulator_key():
    key = azure_key()
    conn = ("STORAGE = 'DefaultEndpointsProtocol=https;AccountName=acmeprod;"
            f"AccountKey={key};EndpointSuffix=core.windows.net'\n")
    finding = one(run({"pkg/storage.py": conn}), "azure_storage_key")
    assert (finding.severity, finding.confidence, finding.evidence["key_name"]) == (Severity.high, 0.9, "AccountKey")

    emulator = "UseDevelopmentStorage: DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=" \
               + azure_key() + ";BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1\n"
    documented = one(run({"docs/azurite.cfg": emulator}), "azure_storage_key")
    assert documented.severity == Severity.info and documented.weight == 0.0
    assert documented.confidence <= 0.3 and documented.evidence["documented_example"] is True

    benign = "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;" \
             "SharedAccessKey=<key>\n"
    assert run({"pkg/bus.cfg": benign}) == []


def test_aws_secret_confidence_depends_on_context():
    key_id, key_secret = aws_key_id(), aws_secret()
    keyword_only = run({"a.py": f"aws_secret_access_key = '{key_secret}'\n"})
    assert one(keyword_only, "aws_secret_access_key").confidence == 0.85

    proximity = f"CREDS = (\n    '{key_id}',\n    '{key_secret}',\n)\n"
    pair = one(run({"b.py": proximity}), "aws_secret_access_key")
    assert pair.confidence == 0.75 and pair.location.line == 3 and pair.evidence["paired_access_key_id"] is True

    sha = rand(HEX, 40)
    assert by_detector(run({"c.py": f"KEY = '{key_id}'\nCOMMIT = '{sha}'\n"}), "aws_secret_access_key") == []


def test_documented_aws_example_keys_are_info_at_most():
    example_id = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    example_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
    src = f"# from the AWS documentation\naws_access_key_id = {example_id}\naws_secret_access_key = {example_secret}\n"
    findings = run({"docs/credentials.ini": src})
    assert findings, "documented examples are still reported, as info"
    for finding in findings:
        assert finding.severity == Severity.info and finding.weight == 0.0 and finding.confidence <= 0.3
        assert finding.evidence["documented_example"] is True


def test_jwt_documentation_sample_is_info_and_real_looking_token_is_medium():
    sample = jwt_token('{"sub":"1234567890","name":"John Doe","iat":1516239022}')
    doc = one(run({"pkg/auth.py": f"EXAMPLE_JWT = '{sample}'\n"}), "jwt")
    assert doc.severity == Severity.info
    session = jwt_token('{"sub":"svc-deploy","scope":"admin"}')
    real = one(run({"pkg/auth.py": f"SESSION = '{session}'\n"}), "jwt")
    assert (real.severity, real.confidence) == (Severity.medium, 0.6)


def test_overlapping_matches_report_the_most_specific_detector_once():
    token = gh_token()
    findings = run({"a.py": f"REMOTE = 'https://ci-bot:{token}@github.com/acme/app.git'\n"})
    assert [f.evidence["detector"] for f in secret_findings(findings)] == ["github_token"]
    bearer = jwt_token('{"sub":"svc"}')
    findings = run({"b.py": f"HEADERS = {{'Authorization': 'Bearer {bearer}'}}\n"})
    assert [f.evidence["detector"] for f in secret_findings(findings)] == ["jwt"]


@pytest.mark.parametrize(("url", "expected"), [
    ("postgresql://app:{pw}@db.prod.acme.io:5432/app", ("database_url", Severity.medium, 0.7)),
    ("amqps://worker:{pw}@mq.acme.io/vhost", ("database_url", Severity.medium, 0.7)),
    ("mongodb+srv://ops:{pw}@cluster0.acme.mongodb.net/admin", ("database_url", Severity.medium, 0.7)),
    ("redis://:{pw}@localhost:6379/0", ("database_url", Severity.low, 0.35)),
    ("https://deploy:{pw}@artifacts.acme.io/simple/", ("url_credentials", Severity.medium, 0.6)),
])
def test_database_and_credential_urls(url, expected):
    password = rand(ALNUM, 14) + "@" + rand(ALNUM, 4)  # passwords may contain "@"
    text = "BROKER = '" + url.format(pw=password) + "'\n"
    detector, severity, confidence = expected
    finding = one(run({"pkg/conf.py": text}), detector)
    assert (finding.severity, finding.confidence) == (severity, confidence)
    assert finding.evidence["length"] == len(password)
    assert_not_leaked([finding], password)


@pytest.mark.parametrize("url", [
    "postgresql://user:password@localhost:5432/mydb",
    "postgresql+psycopg2://scott:tiger@localhost/test",
    "driver://user:pass@localhost/dbname",
    "postgresql://{user}:{password}@{host}:{port}/{db}",
    "postgresql://%(user)s:%(password)s@%(host)s/app",
    "mysql://root:${MYSQL_ROOT_PASSWORD}@db:3306/app",
    "redis://:<password>@redis:6379/0",
    "amqp://guest:guest@localhost:5672//",
    "sqlite:///var/lib/app/app.db",
])
def test_placeholder_and_template_urls_are_not_reported(url):
    findings = run({"pkg/conf.py": f"URL = \"{url}\"\n", "alembic.ini": f"sqlalchemy.url = {url}\n"})
    assert [f for f in findings if f.severity not in (Severity.info, Severity.low)] == []
    assert all(f.evidence["detector"] != "url_credentials" for f in findings)


# --------------------------------------------------------------------------- generic keyword assignments
def test_generic_python_ast_forms_with_real_lines():
    values = [rand(ALNUM + "#$%", 26) for _ in range(8)]
    src = (
        "import os\n"                                                   # 1
        "from os import getenv as ge\n"                                 # 2
        f"DB_PASSWORD = '{values[0]}'\n"                                # 3
        f"client_secret: str = '{values[1]}'\n"                         # 4
        "client = Client(\n"                                            # 5
        f"    api_key='{values[2]}',\n"                                 # 6
        ")\n"                                                           # 7
        f"CONFIG = {{'auth_token': '{values[3]}'}}\n"                   # 8
        f"def connect(host, passwd='{values[4]}'):\n"                   # 9
        "    return host\n"                                             # 10
        f"if request.password == '{values[5]}':\n"                      # 11
        "    grant()\n"                                                 # 12
        f"token = ge('SERVICE_TOKEN', '{values[6]}')\n"                 # 13
        f"os.environ['UPLOAD_API_KEY'] = '{values[7]}'\n"               # 14
    )
    findings = by_detector(run({"pkg/client.py": src}), "generic_secret")
    assert sorted((f.location.line, f.evidence["name"]) for f in findings) == [
        (3, "DB_PASSWORD"), (4, "client_secret"), (6, "api_key"), (8, "auth_token"), (9, "passwd"),
        (11, "password"), (13, "SERVICE_TOKEN"), (14, "UPLOAD_API_KEY"),
    ]
    for finding in findings:
        assert finding.severity in (Severity.low, Severity.medium) and 0.3 <= finding.confidence <= 0.5
        assert finding.evidence["redacted"].startswith("…")
    assert_not_leaked(findings, *values)


def test_generic_config_files_and_unparseable_python_use_line_detection():
    a, b, c, d = (rand(ALNUM + "-_", 24) for _ in range(4))
    files = {
        "deploy/.env": f"# production\nexport SERVICE_PASSWORD={a}\n",
        "deploy/values.yaml": f"app:\n  apiKey: \"{b}\"\n",
        "deploy/app.ini": f"[auth]\nclient_secret = {c}\n",
        "pkg/broken.py": f"def (:\nSECRET_TOKEN = '{d}'\n",
    }
    findings = by_detector(run(files), "generic_secret")
    assert sorted((f.location.file, f.location.line) for f in findings) == [
        ("deploy/.env", 2), ("deploy/app.ini", 2), ("deploy/values.yaml", 2), ("pkg/broken.py", 2)]


# --------------------------------------------------------------------------- false positives (realistic benign code)
BENIGN_FILES: dict[str, str] = {
    "mysite/settings.py": (
        "import os\n"
        "from pathlib import Path\n"
        "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']\n"
        "DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql', 'PASSWORD': os.getenv('DB_PASSWORD'),\n"
        "             'HOST': os.getenv('DB_HOST', 'localhost')}}\n"
        "PASSWORD_HASHERS = ['django.contrib.auth.hashers.PBKDF2PasswordHasher']\n"
        "AUTH_PASSWORD_VALIDATORS = [{'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'}]\n"
        "SESSION_COOKIE_NAME = 'sessionid'\n"
        "CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'\n"
    ),
    "oauthlib_client/client.py": (
        "import getpass\n"
        "import requests\n"
        "TOKEN_URL = 'https://oauth2.googleapis.com/token'\n"
        "token_type = 'Bearer'\n"
        "GRANT_TYPE = 'client_credentials'\n"
        "def fetch_token(client_id, client_secret, scope='openid email'):\n"
        "    password = getpass.getpass('Password: ')\n"
        "    resp = requests.post(TOKEN_URL, data={'grant_type': 'password', 'password': password,\n"
        "                                          'client_secret': client_secret})\n"
        "    access_token = resp.json()['access_token']\n"
        "    return {'Authorization': f'Bearer {access_token}'}\n"
        "PASSWORD_FIELD = 'password'\n"
        "api_key_header = 'X-API-Key'\n"
        "SECRET_KEY_ENV_VAR = 'APP_SECRET_KEY'\n"
    ),
    "nlp/model.py": (
        "from transformers import AutoTokenizer\n"
        "tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')\n"
        "max_tokens = 4096\n"
        "special_tokens = {'pad_token': '[PAD]', 'eos_token': '</s>'}\n"
        "token_pattern = r'(?u)\\\\b\\\\w\\\\w+\\\\b'\n"
    ),
    "app/models.py": (
        "from pydantic import BaseModel, SecretStr\n"
        "class Login(BaseModel):\n"
        "    username: str\n"
        "    password: SecretStr\n"
        "password_hash = 'pbkdf2_sha256$600000$' + 'salt$hash'\n"
        "reset_token_ttl = 3600\n"
        "ERROR_INVALID_TOKEN = 'invalid_or_expired_token'\n"
        "def check(user, password):\n"
        "    return hmac.compare_digest(user.password_hash, hash_password(password))\n"
    ),
    "app/assets.py": (
        "import uuid\n"
        f"LOGO_PNG = '{'iVBORw0KGgo' + rand(B64, 200)}'\n"
        f"COMMIT_SHA = '{rand(HEX, 40)}'\n"
        f"NAMESPACE = uuid.UUID('{uuid_like()}')\n"
        f"CACHE_KEY = 'key-{rand(HEX, 30)}'\n"
    ),
    "cli/main.py": (
        "import argparse\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.add_argument('--password', help='database password (or set DB_PASSWORD)', default=None)\n"
        "parser.add_argument('--token', metavar='TOKEN', default='${GITHUB_TOKEN}')\n"
        "parser.add_argument('--api-key', default=os.environ.get('API_KEY', ''))\n"
    ),
    "tests/test_login.py": (
        "def test_login(client):\n"
        "    resp = client.post('/login', json={'username': 'alice', 'password': 'correct horse battery staple'})\n"
        "    assert resp.status_code == 200\n"
        "    fake_token = 'dummy-token-for-tests-only-0000'\n"
        "    password = 'testpassword123456'\n"
    ),
    ".env.example": (
        "DATABASE_URL=postgresql://user:password@localhost:5432/app\n"
        "SECRET_KEY=changeme-to-a-long-random-string\n"
        "API_TOKEN=<your-api-token>\n"
        "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}\n"
        "STRIPE_API_KEY=" + "sk" + "_test_" + "x" * 24 + "\n"
    ),
    "docker-compose.yml": (
        "services:\n"
        "  db:\n"
        "    environment:\n"
        "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n"
        "      REDIS_URL: redis://redis:6379/0\n"
    ),
    "docs/configuration.md": (
        "Set `password: <your password>` in `config.yaml` and export "
        "`GITHUB_TOKEN=" + "gh" + "p_" + "x" * 36 + "`.\n"
        "The API key looks like `" + "AK" + "IA" + "X" * 16 + "`.\n"
    ),
    "pkg-1.0.dist-info/RECORD": (
        f"pkg/__init__.py,sha256={rand(ALNUM + '-_', 43)},120\n"
        f"pkg/secrets_manager.py,sha256={rand(ALNUM + '-_', 43)},2048\n"
    ),
    "logging.ini": (
        "[formatter_json]\n"
        "format = %(asctime)s %(levelname)s %(message)s\n"
        "[handler_file]\n"
        "args = ('/var/log/app/token-refresh.log',)\n"
    ),
    "pkg/crypto.py": (
        "from cryptography.hazmat.primitives import serialization\n"
        "def load_key(path, passphrase=None):\n"
        "    with open(path, 'rb') as fh:\n"
        "        return serialization.load_pem_private_key(fh.read(), password=passphrase)\n"
        "PRIVATE_KEY_PATH = 'certs/server-private-key.pem'\n"
    ),
}


def test_benign_real_world_code_produces_no_findings():
    findings = run(BENIGN_FILES)
    assert [(f.location.file, f.location.line, f.evidence.get("detector")) for f in findings] == []


def test_benign_files_one_by_one_produce_no_findings():
    for relpath, text in BENIGN_FILES.items():
        assert run({relpath: text}) == [], relpath


@pytest.mark.parametrize(("name", "expected"), [
    ("DB_PASSWORD", True), ("apiKey", True), ("APIKey", True), ("client_secret", True), ("SECRET_KEY", True),
    ("auth_token", True), ("db_pwd", True), ("signing_key", True),
    ("tokenizer", False), ("max_tokens", False), ("token_type", False), ("password_hash", False),
    ("api_key_header", False), ("AWS_ACCESS_KEY_ID", False), ("pwd", False), ("test_password", False),
    ("EXAMPLE_TOKEN", False), ("PASSWORD_FIELD", False), ("token_url", False), ("secrets", False),
])
def test_secret_name_classification(name, expected):
    assert sec.is_secret_name(name) is expected


@pytest.mark.parametrize(("value", "reason"), [
    ("short", "length"),
    ("correct horse battery staple", "whitespace"),
    ("${DATABASE_PASSWORD_VALUE}", "template"),
    ("<insert-your-token-here>", "template"),
    ("os.environ['APP_SECRET_KEY']", "environment_lookup"),
    ("changeme-to-a-long-random-value", "placeholder"),
    ("xxxxxxxxxxxxxxxxxxxxxxxx", "placeholder"),
    ("https://vault.internal/v1/secret", "url_or_path"),
    ("certs/server-private.pem", "url_or_path"),
    ("invalid_or_expired_token", "identifier"),
    ("django.contrib.auth.hashers.Argon2", "identifier"),
    ("ab12" * 5, "entropy"),
    ("aaaabbbbccccdddd1111", "identifier"),  # letters then trailing digits read as a name, not a key
])
def test_generic_value_rejections(value, reason):
    assert sec.generic_value_rejection(value) == reason


# --------------------------------------------------------------------------- context, lines, binaries
@pytest.mark.parametrize(("relpath", "context", "confidence"), [
    ("pkg/settings.py", "runtime", 0.9),
    ("setup.py", "install_time", 0.9),
    ("pkg/__init__.py", "import_time", 0.9),
    ("setup.cfg", "build_config", 0.9),
    ("tests/test_api.py", "test", 0.7),
    ("pkg/conftest.py", "test", 0.7),
    ("docs/usage.md", "documentation", 0.7),
    ("examples/quickstart.py", "documentation", 0.7),
])
def test_context_is_recorded_and_test_files_lower_confidence(relpath, context, confidence):
    finding = one(run({relpath: f"x = '{gh_token()}'\n"}), "github_token")
    assert finding.evidence["context"] == context and finding.confidence == confidence


def test_line_numbers_follow_crlf_and_cr_terminators():
    token = gh_token()
    crlf = "a = 1\r\nb = 2\r\n\r\nTOKEN = '" + token + "'\r\n"
    old_mac = "a = 1\rb = 2\r\r\rTOKEN = '" + token + "'\r"
    assert one(run({"pkg/crlf.py": crlf}), "github_token").location.line == 4
    assert one(run({"pkg/mac.cfg": old_mac}), "github_token").location.line == 5
    big = "x = 1\n" * 4999 + f"TOKEN = '{token}'\n"
    assert one(run({"pkg/big.py": big}), "github_token").location.line == 5000


def test_binaries_printable_runs_have_offsets_but_no_lines():
    token = stripe_live()
    prefix = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
    data = prefix + b"api_key=" + token.encode() + b"\x00" * 16
    finding = one(run(binaries={"pkg/_speedups.so": data}), "stripe_secret_key")
    assert finding.location.file == "pkg/_speedups.so" and finding.location.line is None
    assert finding.evidence["context"] == "binary"
    assert finding.evidence["byte_offset"] == len(prefix) + len(b"api_key=")
    # A token split into short runs by NUL bytes is not stitched together.
    split = token[:12].encode() + b"\x00" + token[12:].encode()
    assert run(binaries={"pkg/other.so": b"\x00" * 8 + split + b"\x00" * 8}) == []


def test_binary_budget_is_enforced_and_reported(monkeypatch):
    monkeypatch.setattr(sec, "MAX_BINARY_SCAN_BYTES", 64)
    data = b"\x00" * 128 + gh_token().encode()
    findings = run(binaries={"a.so": data, "b.so": data})
    assert secret_findings(findings) == []
    [incomplete] = [f for f in findings if f.code == sec.CODE_SCAN_INCOMPLETE]
    assert incomplete.severity == Severity.info and incomplete.weight == 0.0
    assert incomplete.evidence["reason"] == "binary_budget"


def test_wheel_only_content_is_scanned_and_identical_files_are_not_duplicated():
    same = f"TOKEN = '{gh_token()}'\n"
    injected = f"TOKEN = '{gh_token()}'\n"
    findings = run({"pkg/a.py": same}, wheel_files={"pkg/a.py": same, "pkg/b.py": injected})
    secrets = secret_findings(findings)
    assert [(f.location.file, f.evidence.get("origin")) for f in secrets] == [("pkg/a.py", None), ("pkg/b.py", "wheel")]


# --------------------------------------------------------------------------- bounds / adversarial
def test_finding_caps_are_enforced_and_reported(monkeypatch):
    monkeypatch.setattr(sec, "MAX_FINDINGS", 30)
    files = {f"pkg/m{i}.py": "\n".join(f"T{j} = '{gh_token()}'" for j in range(40)) for i in range(2)}
    findings = run(files)
    secrets = secret_findings(findings)
    assert len(secrets) == 30
    assert max(sum(1 for f in secrets if f.location.file == name) for name in files) <= sec.MAX_FINDINGS_PER_FILE
    [incomplete] = [f for f in findings if f.code == sec.CODE_SCAN_INCOMPLETE]
    assert incomplete.evidence["reason"] == "finding_cap" and incomplete.evidence["findings_omitted"] == 50


def test_time_budget_stops_the_scan_and_says_so(monkeypatch):
    monkeypatch.setattr(sec, "BUILTIN_BUDGET_FRACTION", 0.0)
    findings = run({"pkg/a.py": f"T = '{gh_token()}'\n"})
    assert secret_findings(findings) == []
    [incomplete] = [f for f in findings if f.code == sec.CODE_SCAN_INCOMPLETE]
    assert incomplete.evidence["reason"] == "time_budget" and incomplete.evidence["files_skipped"] == 1


@pytest.mark.parametrize("hostile", [
    "a://" * 200_000,
    "postgres://u:" + "@" * 300_000,
    "password = " + "A" * 900_000,
    ("secret_token=" + "x1" * 40 + " ") * 20_000,
    "-----BEGIN RSA " + "PRIV" + "ATE KEY-----\n" + "Z" * 1_500_000,
    "eyJ" + "a" * 100_000 + ".eyJ" * 1000,
], ids=["schemes", "at-signs", "long-value", "many-assignments", "unterminated-pem", "jwt-fragments"])
def test_hostile_inputs_complete_quickly(hostile):
    start = time.monotonic()
    findings = run({"pkg/hostile.cfg": hostile, "pkg/hostile.py": hostile[:200_000]})
    assert time.monotonic() - start < 20
    assert len(findings) <= sec.MAX_FINDINGS + 1


def test_hostile_relpath_is_escaped_everywhere():
    hostile = "pkg/\x1b[2Jevil\u202etxt.py"
    finding = one(run({hostile: f"T = '{gh_token()}'\n"}), "github_token")
    rendered = json.dumps(finding.to_dict())
    for raw in ("\x1b", "\u202e"):
        assert raw not in finding.location.file and raw not in finding.message and raw not in rendered


def test_output_is_deterministic():
    block, _ = pem_block()
    files = {
        "pkg/a.py": f"A = '{gh_token()}'\nB = '{aws_key_id()}'\nPASSWORD = '{rand(ALNUM + '#', 30)}'\n",
        "pkg/b.json": json.dumps({"private_key": block}),
    }
    context = ctx(files, binaries={"x.so": b"\x00" + sendgrid_key().encode()})
    first = [f.to_dict() for f in SecretsAnalyzer().analyze(context)]
    second = [f.to_dict() for f in SecretsAnalyzer().analyze(context)]
    assert first == second and len(first) == 5
    assert [f["finding_id"] for f in first] == [f["finding_id"] for f in second]


def test_secret_findings_do_not_raise_the_malicious_rule_score():
    from app.analysis import risk

    findings = run({"pkg/a.py": f"T = '{gh_token()}'\nK = '''{pem_block()[0]}'''\n"})
    assert secret_findings(findings)
    breakdown = risk.assess(findings)
    assert breakdown.rule_score == 0 and breakdown.final_score == 0


# =========================================================================== gitleaks adapter
def test_gitleaks_argv_by_version():
    old = sec.gitleaks_argv("gitleaks", "/ws", "/ws/report.json", version="8.18.4")
    assert old[:5] == ["gitleaks", "detect", "--no-git", "--source", "/ws"]
    new = sec.gitleaks_argv("gitleaks", Path("/ws"), Path("/ws/report.json"), version="8.21.2")
    assert new[:2] == ["gitleaks", "dir"] and new[-1] == os.fspath(Path("/ws"))
    unknown = sec.gitleaks_argv("gitleaks", "/ws", "/ws/r.json", version=None)
    assert unknown[1] == "detect"
    for argv in (old, new, unknown):
        assert all(isinstance(a, str) for a in argv)
        assert "--redact" in argv and "--no-banner" in argv
        assert argv[argv.index("--report-format") + 1] == "json"
        assert argv[argv.index("--exit-code") + 1] == "0"
        assert argv[argv.index("--report-path") + 1].endswith(".json")


@pytest.mark.parametrize(("rule", "detector"), [
    ("github-pat", "github_token"), ("GITHUB-OAUTH", "github_token"), ("aws-access-token", "aws_access_key_id"),
    ("private-key", "private_key"), ("generic-api-key", "generic_secret"), ("slack-something-new", "slack_token"),
    ("adafruit-api-key", "gitleaks_adafruit_api_key"),
])
def test_gitleaks_rule_mapping(rule, detector):
    assert sec.canonical_gitleaks_detector(rule) == detector


def gitleaks_fixture(root: Path, raw_secret: str) -> list[dict]:
    """TEST FIXTURE shaped like a gitleaks v8 JSON report (not real tool output).

    ``Secret``/``Match`` deliberately hold a raw value, as a gitleaks without ``--redact`` would
    produce, to prove the parser never reads them.
    """
    base = {"EndLine": 0, "StartColumn": 1, "EndColumn": 40, "SymlinkFile": "", "Commit": "", "Author": "",
            "Email": "", "Date": "", "Message": "", "Tags": [], "Entropy": 4.73}
    return [
        {**base, "RuleID": "github-pat", "Description": "GitHub Personal Access Token", "StartLine": 2,
         "Match": "TOKEN = '" + raw_secret + "'", "Secret": raw_secret, "File": str(root / "pkg" / "settings.py"),
         "Fingerprint": str(root / "pkg" / "settings.py") + ":github-pat:2"},
        {**base, "RuleID": "adafruit-api-key", "Description": "Adafruit API Key", "StartLine": 1,
         "Match": raw_secret, "Secret": raw_secret, "File": "./conf/io.cfg", "Fingerprint": "conf/io.cfg:adafruit:1"},
        {**base, "RuleID": "generic-api-key", "Description": "Generic API Key", "StartLine": 2, "Match": "REDACTED",
         "Secret": "REDACTED", "File": str(root / "pkg" / "settings.py").replace("/", "\\")},
        {**base, "RuleID": "generic-api-key", "Description": "Generic API Key", "StartLine": 99, "Match": "REDACTED",
         "Secret": "REDACTED", "File": "conf/io.cfg"},
        {**base, "RuleID": "private-key", "Description": "Private Key", "StartLine": 1, "Secret": "REDACTED",
         "File": "/somewhere/else/not-in-package.pem"},
        {"RuleID": 42, "File": "conf/io.cfg"},
        "not-an-object",
    ]


def test_gitleaks_report_parser_reads_only_safe_fields(tmp_path):
    raw_secret = gh_token()
    report = json.dumps(gitleaks_fixture(tmp_path, raw_secret))
    results, stats = sec.parse_gitleaks_report(
        report, root=str(tmp_path), known_files=["pkg/settings.py", "conf/io.cfg"],
        line_counts={"pkg/settings.py": 3, "conf/io.cfg": 2},
    )
    assert [(r.relpath, r.line, r.rule_id, r.detector) for r in results] == [
        ("pkg/settings.py", 2, "github-pat", "github_token"),
        ("conf/io.cfg", 1, "adafruit-api-key", "gitleaks_adafruit_api_key"),
        ("pkg/settings.py", 2, "generic-api-key", "generic_secret"),
        ("conf/io.cfg", None, "generic-api-key", "generic_secret"),  # line 99 is outside the file: not guessed
    ]
    assert stats == {"results": 4, "dropped_unknown_file": 1, "dropped_invalid": 2, "truncated": 0}
    assert raw_secret not in repr(results)
    assert results[0].entropy == 4.73


@pytest.mark.parametrize(("raw", "reason"), [
    ("{not json", "report_not_json"),
    ('{"RuleID": "x"}', "report_not_a_list"),
    (b"[" + b" " * (8 * 1024 * 1024) + b"]", "report_too_large"),
], ids=["not-json", "not-a-list", "too-large"])
def test_gitleaks_report_parser_rejects_bad_reports(raw, reason):
    with pytest.raises(sec.GitleaksReportError) as excinfo:
        sec.parse_gitleaks_report(raw, root=None, known_files=[])
    assert excinfo.value.reason == reason


def test_gitleaks_report_parser_bounds_result_count(monkeypatch):
    monkeypatch.setattr(sec, "MAX_GITLEAKS_RESULTS", 3)
    report = json.dumps([{"RuleID": "jwt", "File": "a.py", "StartLine": 1}] * 10)
    results, stats = sec.parse_gitleaks_report(report, root=None, known_files=["a.py"])
    assert len(results) == 3 and stats["truncated"] == 7
    assert sec.parse_gitleaks_report("", root=None, known_files=[]) == ([], {
        "results": 0, "dropped_unknown_file": 0, "dropped_invalid": 0, "truncated": 0})


class FakeGitleaks:
    """Stands in for ``tools.run_tool``: writes a fixture report where gitleaks would."""

    def __init__(self, raw_secret: str, *, result: ToolResult | None = None, exc: Exception | None = None,
                 report: str | None = None) -> None:
        self.raw_secret = raw_secret
        self.result = result or ToolResult(0, "", "", False, 12, False)
        self.exc = exc
        self.report = report
        self.calls: list[dict] = []

    def __call__(self, argv, *, timeout, cwd=None, extra_env=None, max_output_bytes=None):
        root = Path(cwd)
        present = sorted(str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*") if p.is_file())
        self.calls.append({"argv": list(argv), "timeout": timeout, "cwd": root, "files": present})
        if self.exc is not None:
            raise self.exc
        report_path = Path(argv[argv.index("--report-path") + 1])
        assert report_path.parent == root
        body = self.report if self.report is not None else json.dumps(gitleaks_fixture(root, self.raw_secret))
        report_path.write_text(body, encoding="utf-8")
        return self.result


@pytest.fixture()
def gitleaks_available(monkeypatch):
    monkeypatch.setattr(tools, "find_tool",
                        lambda binary, **kw: ToolStatus(name="gitleaks", available=True, version="8.21.2"))

    def install(fake: FakeGitleaks) -> FakeGitleaks:
        monkeypatch.setattr(tools, "run_tool", fake)
        return fake

    return install


def _gitleaks_package() -> tuple[dict[str, str], str]:
    token = gh_token()
    files = {
        "pkg/settings.py": f"import os\nTOKEN = '{token}'\nDEBUG = False\n",
        "conf/io.cfg": "[io]\nendpoint = https://io.adafruit.com\n",
        ".gitleaks.toml": "[allowlist]\npaths = ['''.*''']\n",  # hostile: would disable every rule
        "pkg/.gitleaksignore": "*\n",
    }
    return files, token


def test_gitleaks_results_are_merged_and_deduplicated(gitleaks_available):
    files, token = _gitleaks_package()
    raw_secret = gh_token()
    fake = gitleaks_available(FakeGitleaks(raw_secret))
    findings = run(files)

    [call] = fake.calls
    assert call["argv"][:2] == ["gitleaks", "dir"] and "--redact" in call["argv"]
    assert ".gitleaks.toml" not in call["files"] and "pkg/.gitleaksignore" not in call["files"]
    assert "pkg/settings.py" in call["files"]
    assert 0 < call["timeout"] <= settings.TOOL_TIMEOUT_SECONDS
    assert not call["cwd"].exists()  # the workspace is removed afterwards

    builtin = one(findings, "github_token")
    assert builtin.evidence["corroborated_by"] == ["gitleaks"]
    assert builtin.provenance == "static-analysis"
    [only_gitleaks] = by_detector(findings, "gitleaks_adafruit_api_key")
    assert only_gitleaks.provenance == "external-tool:gitleaks"
    assert (only_gitleaks.location.file, only_gitleaks.location.line) == ("conf/io.cfg", 1)
    assert (only_gitleaks.severity, only_gitleaks.confidence) == (Severity.medium, 0.6)
    assert only_gitleaks.evidence["redacted"] == "[REDACTED]" and only_gitleaks.evidence["tool"] == "gitleaks"
    generic = by_detector(findings, "generic_secret")
    assert [(f.location.file, f.location.line) for f in generic] == [("conf/io.cfg", None)]
    assert Code.TOOL_UNAVAILABLE not in {f.code for f in findings}
    assert_not_leaked(findings, token, raw_secret)


def test_gitleaks_unavailable_keeps_builtin_detection_without_status_finding():
    files, token = _gitleaks_package()
    findings = run(files)
    assert one(findings, "github_token").evidence.get("corroborated_by") is None
    assert Code.TOOL_UNAVAILABLE not in {f.code for f in findings}


def test_gitleaks_disabled_is_never_probed(monkeypatch):
    monkeypatch.setattr(settings, "GITLEAKS_ENABLED", False)

    def boom(*a, **k):
        raise AssertionError("find_tool must not be called when gitleaks is disabled")

    monkeypatch.setattr(tools, "find_tool", boom)
    analyzer = SecretsAnalyzer()
    assert analyzer.availability().available is True
    assert "disabled by configuration" in analyzer.availability().detail
    assert one(analyzer.analyze(ctx({"a.py": f"T = '{gh_token()}'\n"})), "github_token")


@pytest.mark.parametrize(("fake_kwargs", "status"), [
    ({"result": ToolResult(None, "", "", True, 120_000, False)}, "timeout"),
    ({"result": ToolResult(2, "", "config error", False, 30, False)}, "exit_2"),
    ({"exc": ToolError("could not launch gitleaks")}, "launch_failed:ToolError"),
    ({"report": "{definitely not json"}, "report_not_json"),
])
def test_gitleaks_failures_degrade_to_an_info_status(gitleaks_available, fake_kwargs, status):
    files, token = _gitleaks_package()
    gitleaks_available(FakeGitleaks(gh_token(), **fake_kwargs))
    findings = run(files)
    assert one(findings, "github_token")  # built-in detection is unaffected
    [degraded] = [f for f in findings if f.code == Code.TOOL_UNAVAILABLE]
    assert degraded.severity == Severity.info and degraded.weight == 0.0
    assert degraded.evidence == {"analyzer": "secrets", "tool": "gitleaks", "version": "8.21.2", "status": status}


def test_gitleaks_is_skipped_without_time_budget(gitleaks_available, monkeypatch):
    monkeypatch.setattr(sec, "GITLEAKS_BUDGET_FRACTION", 0.0)
    fake = gitleaks_available(FakeGitleaks(gh_token()))
    findings = run({"a.py": f"T = '{gh_token()}'\n"})
    assert fake.calls == []
    [degraded] = [f for f in findings if f.code == Code.TOOL_UNAVAILABLE]
    assert degraded.evidence["status"] == "no_time_budget"


def test_secrets_analyzer_in_the_orchestrator_is_ok_without_gitleaks(monkeypatch):
    from app.analysis import scoring
    from app.analysis.orchestrator import Orchestrator

    class _NoModel:
        available = False
        metadata: dict = {}

        def predict(self, features):
            return 0, 0.0

    class _Fetcher:
        def build_context(self, name, version, options=None):
            return ctx({"pkg/a.py": f"TOKEN = '{gh_token()}'\n"})

    class _Cache:
        def get_json(self, key):
            return None

        def set_json(self, key, value, ttl):
            pass

    monkeypatch.setattr(scoring, "get_model_store", lambda: _NoModel())
    result = Orchestrator(_Fetcher(), analyzers=[SecretsAnalyzer()], cache_backend=_Cache()).analyze(
        "pypi", "demo", "1.0.0")
    [record] = [r for r in result.analyzer_runs if r["name"] == "secrets"]
    assert record["status"] == "ok" and record["finding_count"] == 1
    assert [s["code"] for s in result.signals] == [Code.SECRET_DETECTED]
    assert result.signals[0]["category"] == "secret" and result.capabilities == [Capability.SECRET]
    assert result.rule_score == 0
