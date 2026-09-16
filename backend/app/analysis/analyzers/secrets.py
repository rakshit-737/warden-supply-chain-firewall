"""Secrets analyzer: hard-coded credentials in package contents.

Designed to detect credentials that a package author shipped by mistake (or on purpose) in the
files Warden extracted: source code, configuration, data files, the text-like parts of retained
binaries and — when a wheel was inventoried — wheel files whose content differs from the sdist.
It provides signals for exposure risk; a hard-coded credential is not in itself evidence of
malice, so every finding is ``SECRET_DETECTED`` with capability ``secret``, whose taxonomy
dimension is excluded from the malicious rule score.

Built-in detectors (always active)
==================================

* **Format detectors** reuse :func:`app.core.redaction.find_secrets` (private keys, AWS access key
  ids, GitHub/GitLab/Slack/Stripe/Google/PyPI/npm/Anthropic/OpenAI/Twilio/SendGrid/Mailgun/Heroku
  tokens, JWTs, HTTP authorization credentials) with extra validation that the regexes cannot
  express: a PEM block must contain real base64 key material (so code that merely mentions
  ``-----BEGIN … PRIVATE KEY-----`` is ignored); obvious placeholders (runs such as ``xxxxxxxx``,
  ``abcdefgh``/``12345678`` sequences, very low entropy) are dropped; documented example values
  (``…EXAMPLE…`` AWS keys, the jwt.io sample token, the Azurite ``devstoreaccount1`` key) are
  reported at severity ``info`` only; Mailgun keys need the word "mailgun" in the same file and
  Twilio key SIDs without "twilio" nearby are low confidence.
* **Contextual detectors**: AWS secret access keys (a 40-character key next to an AWS secret-key
  name, or near an AWS access key id), GCP service-account JSON (``"type": "service_account"`` plus
  a ``private_key`` field), Azure ``AccountKey=`` / ``SharedAccessKey=`` connection-string values,
  and database / message-broker URLs with an embedded password (passwords that are placeholders or
  templates are ignored; local or placeholder hosts lower severity and confidence).
* **Generic keyword assignments** (``password``/``secret``/``token``/``api_key`` … names): Python
  files are read with ``ast`` (assignments, annotated assignments, keyword arguments, dict literals,
  parameter defaults, equality comparisons and ``os.getenv``/``os.environ.get`` defaults, with import
  aliases resolved); other text files and unparseable Python fall back to a line regex. A value is
  reported only when it is at least 16 characters long, has Shannon entropy ≥ 3.5 bits/char, mixes
  character classes, contains no whitespace and is not a placeholder (``xxx``, ``changeme``,
  ``example``, ``dummy``, ``test``, angle-bracket placeholders, ``${…}`` templates, environment
  lookups, URLs, paths, identifiers). These findings are ``low`` (confidence 0.35) or ``medium``
  (0.5) and are not run on documentation files or binaries.

Every finding records ``evidence["context"]``: ``install_time`` (``setup.py``, ``.pth``),
``import_time`` (``__init__.py``), ``build_config`` (``setup.cfg``, ``pyproject.toml``), ``test``,
``documentation``, ``binary`` or ``runtime``. Test and documentation files lower confidence by 0.2.
Locations carry the real 1-based line computed from the match offset (``\\r\\n``, ``\\r`` and ``\\n``
terminators, as the Python parser counts them) or from the AST node; binary matches have no line
(``evidence["byte_offset"]`` instead). Columns are never reported.

Secret hygiene: the raw value is used only to compute a keyed fingerprint
(:func:`app.core.redaction.fingerprint`), length and entropy. Messages, evidence and locations
contain the redacted stand-in (:func:`app.core.redaction.redact_value`, with the four-character
prefix shown only for formats whose prefix is a public type marker) and never a snippet. Nothing
is logged except counts and statuses.

Bounds: per-file and total character budgets, a binary byte budget, a raw-candidate cap per file,
a finding cap (per file and per scan) and a wall-clock budget derived from
``ANALYZER_TIMEOUT_SECONDS``. When a budget cuts the scan short an info
``SECRET_SCAN_INCOMPLETE`` finding says what was skipped, so "no findings" is never silently
reported for a partially searched package. Output order is deterministic (package file order,
then line).

Optional gitleaks adapter
=========================

When ``GITLEAKS_ENABLED`` and ``tools.find_tool(GITLEAKS_BINARY)`` reports the binary available,
the package is materialised with :func:`app.analysis.tools.package_workspace` (without any
package-supplied ``.gitleaks.toml`` / ``.gitleaksignore``, which could otherwise disable rules) and
gitleaks runs through :func:`app.analysis.tools.run_tool` in no-git directory mode with
``--redact`` and a JSON report written inside the workspace. Only rule id, description, file, line
and entropy are read from the report — never ``Secret`` or ``Match``. Results are merged with the
built-in ones, de-duplicated by file + line + detector family; a built-in finding confirmed by
gitleaks gets ``evidence["corroborated_by"] = ["gitleaks"]``. If gitleaks is unavailable the
built-in detectors still run and :meth:`SecretsAnalyzer.availability` reports gitleaks as an
optional sub-tool (the analyzer itself stays available). If gitleaks is available but fails
(timeout, crash, unreadable report) an info ``TOOL_UNAVAILABLE`` finding with the failure status is
added. Package files can still suppress gitleaks with inline ``gitleaks:allow`` comments; the
built-in detectors ignore such comments.

Known limitations: secrets split across string concatenations, encoded (base64/hex) secrets,
free-form passwords that do not follow a secret-named key, and formats not listed above are not
detected; nested archives are not opened.
"""

from __future__ import annotations

import ast
import base64
import binascii
import bisect
import hashlib
import json
import math
import os
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from app.analysis import taxonomy
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, ToolStatus
from app.analysis.findings import Category, Finding, Location, Provenance, Severity
from app.analysis.signals import Capability, Code
from app.core import redaction
from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("warden.analyzers.secrets")

ANALYZER_NAME = "secrets"
ANALYZER_VERSION = "1.0.0"
GITLEAKS_TOOL = "gitleaks"

# Pipeline status code: part of the package was not searched (budget) or findings were omitted (cap).
CODE_SCAN_INCOMPLETE = "SECRET_SCAN_INCOMPLETE"
taxonomy.register(
    taxonomy.CodeInfo(
        code=CODE_SCAN_INCOMPLETE,
        category=Category.PIPELINE.value,
        dimension=taxonomy.Dimension.PIPELINE,
        title="Secret scan incomplete",
        remediation="Part of the package was not searched for secrets or findings were omitted (size, time or "
                    "finding budget); review the remaining files manually or raise the limits.",
    ),
    replace=True,
)

# --------------------------------------------------------------------------- bounds
MAX_TEXT_FILE_CHARS = 2 * 1024 * 1024
MAX_TOTAL_TEXT_CHARS = 64 * 1024 * 1024
MAX_BINARY_SCAN_BYTES = 16 * 1024 * 1024
MIN_BINARY_RUN = 20
MAX_AST_CHARS = 1024 * 1024
MAX_GENERIC_LINE_CHARS = 4096
MAX_RAW_HITS_PER_FILE = 2000
MAX_GENERIC_CANDIDATES_PER_FILE = 2000
MAX_FINDINGS_PER_FILE = 25
MAX_FINDINGS = 200
BUILTIN_BUDGET_FRACTION = 0.6  # of ANALYZER_TIMEOUT_SECONDS
GITLEAKS_BUDGET_FRACTION = 0.9  # gitleaks must finish before the orchestrator's analyzer timeout
MIN_GITLEAKS_TIMEOUT_SECONDS = 1.0
MAX_GITLEAKS_REPORT_BYTES = 8 * 1024 * 1024
MAX_GITLEAKS_RESULTS = 1000
GITLEAKS_REPORT_NAME = "~warden-gitleaks-report.json"  # "~" names can never be package members
_GITLEAKS_CONFIG_NAMES = frozenset({".gitleaks.toml", ".gitleaksignore", "gitleaks.toml"})
_GITLEAKS_DIR_COMMAND_VERSION = (8, 19, 0)

TEST_CONFIDENCE_PENALTY = 0.2
DOCUMENTED_EXAMPLE_CONFIDENCE = 0.3
MIN_CONFIDENCE = 0.1
GENERIC_MIN_LENGTH = 16
GENERIC_MAX_LENGTH = 512
GENERIC_MIN_ENTROPY = 3.5

_WEIGHTS = {Severity.critical: 8.0, Severity.high: 5.0, Severity.medium: 2.5, Severity.low: 1.0, Severity.info: 0.0}


# --------------------------------------------------------------------------- detector catalogue
@dataclass(frozen=True)
class DetectorSpec:
    label: str
    severity: Severity
    confidence: float
    keep_prefix: bool = False  # the first four characters are a public type marker
    rank: int = 5  # lower rank wins when two matches overlap


_H, _M, _L = Severity.high, Severity.medium, Severity.low
DETECTORS: dict[str, DetectorSpec] = {
    "private_key": DetectorSpec("private key", _H, 0.9, rank=0),
    "gcp_service_account": DetectorSpec("GCP service-account private key", _H, 0.9, rank=0),
    "gcp_private_key_field": DetectorSpec("private key field", _H, 0.8, rank=1),
    "aws_access_key_id": DetectorSpec("AWS access key ID", _H, 0.85, keep_prefix=True, rank=1),
    "aws_secret_access_key": DetectorSpec("AWS secret access key", _H, 0.9, rank=1),
    "azure_storage_key": DetectorSpec("Azure storage / service account key", _H, 0.9, rank=1),
    "github_token": DetectorSpec("GitHub token", _H, 0.9, keep_prefix=True, rank=1),
    "github_fine_grained_pat": DetectorSpec("GitHub fine-grained personal access token", _H, 0.9, True, rank=1),
    "gitlab_token": DetectorSpec("GitLab token", _H, 0.9, keep_prefix=True, rank=1),
    "slack_token": DetectorSpec("Slack token", _H, 0.9, keep_prefix=True, rank=1),
    "slack_app_token": DetectorSpec("Slack app-level token", _H, 0.9, keep_prefix=True, rank=1),
    "slack_webhook": DetectorSpec("Slack incoming-webhook URL", _M, 0.8, keep_prefix=True, rank=1),
    "stripe_secret_key": DetectorSpec("Stripe secret key", _H, 0.9, keep_prefix=True, rank=1),
    "google_api_key": DetectorSpec("Google API key", _M, 0.6, keep_prefix=True, rank=1),
    "pypi_token": DetectorSpec("PyPI upload token", _H, 0.9, keep_prefix=True, rank=1),
    "npm_token": DetectorSpec("npm access token", _H, 0.9, keep_prefix=True, rank=1),
    "anthropic_api_key": DetectorSpec("Anthropic API key", _H, 0.9, keep_prefix=True, rank=1),
    "openai_api_key": DetectorSpec("OpenAI API key", _H, 0.9, keep_prefix=True, rank=1),
    "twilio_api_key": DetectorSpec("Twilio API key SID", _M, 0.7, rank=1),
    "sendgrid_api_key": DetectorSpec("SendGrid API key", _H, 0.9, rank=1),
    "mailgun_api_key": DetectorSpec("Mailgun API key", _H, 0.85, keep_prefix=True, rank=1),
    "heroku_api_key": DetectorSpec("Heroku API key", _H, 0.85, rank=1),
    "jwt": DetectorSpec("JSON Web Token", _M, 0.6, keep_prefix=True, rank=2),
    "database_url": DetectorSpec("database / message-broker URL with an embedded password", _M, 0.7, rank=3),
    "url_credentials": DetectorSpec("URL with embedded credentials", _M, 0.6, rank=3),
    "bearer_token": DetectorSpec("HTTP authorization credential", _M, 0.55, rank=4),
    "authorization_header": DetectorSpec("HTTP authorization credential", _M, 0.55, rank=4),
    "auth_scheme_credentials": DetectorSpec("HTTP authorization credential", _M, 0.55, rank=4),
    "generic_secret": DetectorSpec("possible hard-coded secret", _L, 0.35, rank=9),
}
# Detectors whose matches are the same underlying credential kind (for de-duplication).
_FAMILY = {
    "gcp_service_account": "private_key",
    "gcp_private_key_field": "private_key",
    "github_fine_grained_pat": "github_token",
    "database_url": "url_credentials",
    "bearer_token": "http_authorization",
    "authorization_header": "http_authorization",
    "auth_scheme_credentials": "http_authorization",
}
# Pattern detectors of app.core.redaction that this analyzer handles itself or not at all.
_SELF_HANDLED = frozenset({"url_credentials"})
_HEADER_DETECTORS = frozenset({"bearer_token", "authorization_header", "auth_scheme_credentials"})

# gitleaks default-config rule ids -> built-in detector names.
GITLEAKS_RULE_MAP: dict[str, str] = {
    "private-key": "private_key",
    "gcp-service-account": "gcp_service_account",
    "aws-access-token": "aws_access_key_id",
    "github-pat": "github_token",
    "github-oauth": "github_token",
    "github-app-token": "github_token",
    "github-refresh-token": "github_token",
    "github-fine-grained-pat": "github_fine_grained_pat",
    "gitlab-pat": "gitlab_token",
    "gitlab-ptt": "gitlab_token",
    "gitlab-rrt": "gitlab_token",
    "slack-bot-token": "slack_token",
    "slack-user-token": "slack_token",
    "slack-legacy-token": "slack_token",
    "slack-legacy-bot-token": "slack_token",
    "slack-legacy-workspace-token": "slack_token",
    "slack-config-access-token": "slack_token",
    "slack-config-refresh-token": "slack_token",
    "slack-app-token": "slack_app_token",
    "slack-webhook-url": "slack_webhook",
    "stripe-access-token": "stripe_secret_key",
    "gcp-api-key": "google_api_key",
    "pypi-upload-token": "pypi_token",
    "npm-access-token": "npm_token",
    "anthropic-api-key": "anthropic_api_key",
    "anthropic-admin-api-key": "anthropic_api_key",
    "openai-api-key": "openai_api_key",
    "jwt": "jwt",
    "twilio-api-key": "twilio_api_key",
    "sendgrid-api-token": "sendgrid_api_key",
    "mailgun-private-api-token": "mailgun_api_key",
    "heroku-api-key": "heroku_api_key",
    "generic-api-key": "generic_secret",
}
_GITLEAKS_RULE_PREFIXES = (("github-", "github_token"), ("gitlab-", "gitlab_token"), ("slack-", "slack_token"),
                           ("aws-", "aws_access_key_id"))

# --------------------------------------------------------------------------- shared regexes
_NEWLINE_RE = re.compile(r"\r\n|\r|\n")
_REPEATED_CHAR_RE = re.compile(r"(.)\1{7,}")
_SEQUENCES = ("abcdefgh", "01234567", "12345678", "qwertyui")
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_PEM_HEADER_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_PEM_MATERIAL_LINE_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
_PEM_HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z\-]{1,30}:\s?.*$")  # RFC 1421 headers (Proc-Type, DEK-Info)
_SERVICE_ACCOUNT_RE = re.compile(r"[\"']type[\"']\s*:\s*[\"']service_account[\"']")
_PRIVATE_KEY_FIELD_BEFORE_RE = re.compile(r"[\"']private_key[\"']\s*:\s*[\"']\s*$")
_AZURE_ACCOUNT_KEY_RE = re.compile(r"(?i)AccountKey\s*=\s*$")
_AWS_SECRET_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9/+=])(?P<value>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])")
# URL credentials are located from each "://" (a scheme regex over every letter would be quadratic-ish).
_URL_SCHEME_BEFORE_RE = re.compile(r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{1,20}$")
_URL_AUTHORITY_RE = re.compile(
    r"(?P<user>[^\s:/@\[\]\"'`<>]{0,128}):(?P<password>[^\s/\[\]\"'`<>]{1,256})@"
    r"(?P<host>\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9_\-]{1,63}(?:\.[A-Za-z0-9_\-]{1,63}){0,20})"
)
_URL_WINDOW = 1024
_DB_SCHEMES = frozenset({
    "postgres", "postgresql", "pgsql", "mysql", "mariadb", "mongodb", "redis", "rediss", "amqp", "amqps",
    "mssql", "sqlserver", "oracle", "cockroachdb", "clickhouse", "kafka", "nats", "memcached", "couchdb",
    "cassandra", "neo4j", "bolt", "db2", "snowflake", "influxdb", "elasticsearch", "rabbitmq", "mqtt", "mqtts",
    "stomp", "ldap", "ldaps", "sftp", "ftp", "ftps",
})
_LOCAL_HOSTS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "[::1]", "host.docker.internal", "db", "database", "postgres", "mysql",
    "redis", "rabbitmq", "mongo", "mongodb", "host", "hostname", "server", "your-host", "yourhost",
})
_LOCAL_HOST_SUFFIXES = (".local", ".localhost", ".example", ".test", ".invalid", "example.com", "example.org",
                        "example.net")
_URL_PASSWORD_PLACEHOLDERS = frozenset({
    "password", "passwd", "pass", "pwd", "secret", "changeme", "example", "user", "username", "test", "testing",
    "xxx", "xxxx", "***", "****", "...", "mypassword", "yourpassword", "pa55word", "p@ssw0rd", "passw0rd",
})
_TEMPLATE_RE = re.compile(r"\$\{|\{\{|%\(|%s|<[^>]*>|^\$[A-Za-z_]|\{[A-Za-z_][A-Za-z0-9_]*\}|^\*+$")
_PLACEHOLDER_WORDS = (
    "xxx", "changeme", "change_me", "change-me", "changeit", "example", "dummy", "sample", "placeholder",
    "your_", "your-", "yourkey", "yourtoken", "yoursecret", "yourpassword", "insert", "replaceme", "replace_me",
    "redacted", "todo", "fixme", "fake", "notreal", "not_real", "not-a-real", "test", "mock",
)
_ENV_LOOKUP_MARKERS = ("os.environ", "getenv", "environ[", "environ.get", "process.env", "env(", "env[", "secret(",
                       "vault:", "arn:aws:", "secretsmanager", "ssm:", "keyring")
_URL_OR_PATH_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://|/|\./|\.\./|~/|[A-Za-z]:[\\/]|file:)")
# Relative paths with a file extension (``certs/server.pem``); base64 with "/" but no extension is not a path.
_PATH_LIKE_RE = re.compile(r"^[\w.\-]+(?:[/\\][\w.\-]+)+\.[A-Za-z][A-Za-z0-9]{0,7}$")
_IDENTIFIER_LIKE_RE = re.compile(
    r"^(?:[a-z]+(?:[_.\-][a-z]+)*\d*"
    r"|[A-Z]+(?:[_.\-][A-Z]+)*\d*"
    r"|(?:[A-Z][a-z]+)+\d*"
    r"|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

# Secret-ish name parts. A name matches when one of its parts (split on separators and camelCase) is
# a keyword, or two adjacent parts form one of the compound keywords.
_NAME_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
_NAME_KEYWORDS = frozenset({"password", "passwd", "passphrase", "secret", "token", "apikey", "credential",
                            "credentials", "pwd"})
_NAME_COMPOUNDS = frozenset({("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"),
                             ("auth", "key"), ("signing", "key"), ("encryption", "key"), ("client", "secret")})
_NAME_METADATA_SUFFIXES = frozenset({
    "url", "uri", "endpoint", "path", "file", "filename", "dir", "directory", "name", "names", "type", "types",
    "header", "headers", "field", "fields", "param", "params", "parameter", "prefix", "suffix", "env", "var",
    "variable", "len", "length", "min", "max", "regex", "re", "pattern", "format", "fmt", "template", "id", "ids",
    "count", "size", "ttl", "timeout", "expiry", "expires", "expiration", "label", "hint", "prompt", "message",
    "msg", "error", "help", "description", "desc", "placeholder", "policy", "scope", "scopes", "cache", "class",
    "cls", "model", "enabled", "required", "mode", "style", "hash", "hashed", "digest", "validator", "reset",
    "confirm", "confirmation", "strength", "rule", "rules", "widget", "input", "form", "attr", "attribute",
    "column", "col", "table", "location", "source", "provider", "backend", "command", "cmd", "arg", "args",
    "option", "options", "setting", "settings", "lifetime", "age", "algorithm", "alg",
})
_NAME_EXCLUDED_PARTS = frozenset({"example", "dummy", "fake", "sample", "placeholder", "mock", "test"})
_GENERIC_LINE_HINT_RE = re.compile(
    r"(?i)pass(?:word|wd|phrase)|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|credential|pwd"
)
_GENERIC_ASSIGN_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[\"']?\s*(?:=|:=|=>|:)\s*"
    r"(?:(?P<q>[\"'`])(?P<qv>[^\"'`\s]{16,512})(?P=q)"
    r"|(?P<uv>[^\s\"'`,;#{}()\[\]<>]{16,512})(?![^\s\"'`,;#{}()\[\]<>]))"
)
_ENV_CALLS = frozenset({"os.getenv", "os.environ.get", "os.environ.setdefault", "os.putenv"})
_DOC_SUFFIXES = (".md", ".rst", ".adoc", ".html", ".htm")
_DOC_BASENAMES = frozenset({"readme", "changelog", "changes", "history", "news", "authors", "contributing",
                            "license", "licence", "notice"})
_TEST_DIRS = frozenset({"test", "tests", "testing", "__tests__", "spec", "specs", "fixtures", "fixture", "testdata",
                        "test_data", "unittests", "unit_tests"})
_DOC_DIRS = frozenset({"doc", "docs", "documentation", "example", "examples", "sample", "samples", "demo", "demos",
                       "tutorial", "tutorials"})
_PYTHON_SUFFIXES = (".py", ".pyw", ".pyi")
_PRINTABLE_RUN_RE = re.compile(rb"[\t\n\r\x20-\x7e]{%d,}" % MIN_BINARY_RUN)


# --------------------------------------------------------------------------- small helpers
def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _char_classes(value: str) -> int:
    lower = any(c.islower() for c in value)
    upper = any(c.isupper() for c in value)
    digit = any(c.isdigit() for c in value)
    symbol = any(not c.isalnum() for c in value)
    return lower + upper + digit + symbol


def classify_context(relpath: str) -> str:
    """Execution context of a package file: install_time, import_time, build_config, test, documentation, runtime."""
    parts = [p for p in str(relpath).replace("\\", "/").split("/") if p]
    if not parts:
        return "runtime"
    base = parts[-1].lower()
    dirs = {p.lower() for p in parts[:-1]}
    if base == "setup.py" or base.endswith(".pth"):
        return "install_time"
    if (dirs & _TEST_DIRS or base.startswith("test_") or base.endswith(("_test.py", "_tests.py"))
            or base == "conftest.py"):
        return "test"
    if dirs & _DOC_DIRS or base.endswith(_DOC_SUFFIXES) or base.split(".", 1)[0] in _DOC_BASENAMES:
        return "documentation"
    if base in {"setup.cfg", "pyproject.toml"}:
        return "build_config"
    if base == "__init__.py":
        return "import_time"
    return "runtime"


def _context_adjusted(confidence: float, context: str) -> float:
    if context in {"test", "documentation"}:
        confidence -= TEST_CONFIDENCE_PENALTY
    return round(max(MIN_CONFIDENCE, min(1.0, confidence)), 2)


class _Lines:
    """Offset -> 1-based line mapping (``\\r\\n``, ``\\r``, ``\\n``), built lazily."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._starts: list[int] | None = None

    @property
    def starts(self) -> list[int]:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in _NEWLINE_RE.finditer(self._text)]
        return self._starts

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)

    def count(self) -> int:
        return len(self.starts)

    def span(self, first_line: int, last_line: int) -> tuple[int, int]:
        starts = self.starts
        first = max(1, first_line)
        last = min(len(starts), last_line)
        begin = starts[first - 1]
        end = starts[last] if last < len(starts) else len(self._text)
        return begin, end


def _looks_like_placeholder_token(value: str) -> bool:
    """Obvious documentation placeholders for format detectors (``ghp_xxxxxxxx…``, ``sk_live_1234…``)."""
    lowered = value.lower()
    if _REPEATED_CHAR_RE.search(value) or any(seq in lowered for seq in _SEQUENCES):
        return True
    return len(value) >= 20 and shannon_entropy(value) < 3.0


def _is_sample_jwt(value: str) -> bool:
    """The jwt.io documentation token (``sub`` 1234567890, ``name`` John Doe)."""
    parts = value.split(".")
    if len(parts) < 2 or len(parts[1]) > 4096:
        return False
    segment = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(segment.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeError):
        return False
    return isinstance(payload, dict) and payload.get("sub") == "1234567890" and payload.get("name") == "John Doe"


def pem_contains_key_material(block: str) -> bool:
    """True when a ``-----BEGIN … PRIVATE KEY-----`` match wraps real base64 key material.

    Code that only mentions the armour lines (parsers, docstrings, ``startswith`` checks) is
    rejected: every non-empty line between the armour lines must be base64 (after removing string
    quotes, ``\\n`` escapes and concatenation punctuation) or an RFC 1421 header, and there must be at
    least 64 base64 characters with key-like entropy.
    """
    header = _PEM_HEADER_RE.match(block)
    body = block[header.end():] if header else block
    end = body.find("-----END")
    body = body[:end] if end >= 0 else body[:8192]
    body = body.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    material: list[str] = []
    for raw_line in body.splitlines():
        line = raw_line.strip().strip("\"'+,;\\()").strip()
        if line.startswith(("b\"", "b'")):
            line = line[2:].strip("\"'")
        if not line:
            continue
        if _PEM_MATERIAL_LINE_RE.match(line):
            material.append(line)
        elif not _PEM_HEADER_LINE_RE.match(line):
            return False
    joined = "".join(material)
    return 64 <= len(joined) <= 32768 and shannon_entropy(joined) >= 4.0


def _name_parts(name: str) -> list[str]:
    return [p.lower() for p in _NAME_SPLIT_RE.split(name) if p]


def is_secret_name(name: str) -> bool:
    """True for identifiers/keys that conventionally hold a credential (``DB_PASSWORD``, ``apiKey``)."""
    if not name or len(name) > 128:
        return False
    parts = _name_parts(name)
    if not parts or parts[-1] in _NAME_METADATA_SUFFIXES or _NAME_EXCLUDED_PARTS & set(parts):
        return False
    if any(p in _NAME_KEYWORDS for p in parts):
        return "pwd" not in parts or len(parts) > 1
    return any(pair in _NAME_COMPOUNDS for pair in zip(parts, parts[1:]))


def generic_value_rejection(value: str) -> str | None:
    """Why a value under a secret-named key is not reported (``None`` = report it)."""
    if not (GENERIC_MIN_LENGTH <= len(value) <= GENERIC_MAX_LENGTH):
        return "length"
    if any(ch.isspace() for ch in value):
        return "whitespace"
    lowered = value.lower()
    if _TEMPLATE_RE.search(value):
        return "template"
    if any(marker in lowered for marker in _ENV_LOOKUP_MARKERS):
        return "environment_lookup"
    if any(word in lowered for word in _PLACEHOLDER_WORDS):
        return "placeholder"
    if _REPEATED_CHAR_RE.search(value) or any(seq in lowered for seq in _SEQUENCES):
        return "placeholder"
    if _URL_OR_PATH_RE.match(value) or "://" in value or _PATH_LIKE_RE.match(value) or _EMAIL_RE.match(value):
        return "url_or_path"
    if _IDENTIFIER_LIKE_RE.match(value):
        return "identifier"
    if _char_classes(value) < 2:
        return "character_classes"
    if shannon_entropy(value) < GENERIC_MIN_ENTROPY:
        return "entropy"
    return None


# --------------------------------------------------------------------------- hits / records
@dataclass
class _Hit:
    detector: str
    start: int | None  # character offset in the scanned text (None for AST-only candidates)
    end: int | None
    value: str
    line: int | None
    severity: Severity
    confidence: float
    rank: int
    extra: dict[str, Any] = field(default_factory=dict)
    example: bool = False
    name: str | None = None


@dataclass
class _Record:
    order: int  # position of the file in scan order (for deterministic output)
    relpath: str
    line: int | None
    detector: str
    severity: Severity
    confidence: float
    message: str
    evidence: dict[str, Any]
    provenance: str

    def to_finding(self) -> Finding:
        return Finding(
            Code.SECRET_DETECTED, self.severity, _WEIGHTS[self.severity], self.message, self.evidence,
            Capability.SECRET, confidence=self.confidence, location=Location(file=self.relpath, line=self.line),
            provenance=self.provenance,
        )


def _family(detector: str) -> str:
    return _FAMILY.get(detector, detector)


class _IntervalSet:
    """Accepted, non-overlapping [start, end) spans with O(log n) overlap checks."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []

    def overlaps(self, start: int, end: int) -> bool:
        i = bisect.bisect_left(self._starts, start)
        if i < len(self._starts) and self._starts[i] < end:
            return True
        return i > 0 and self._ends[i - 1] > start

    def add(self, start: int, end: int) -> None:
        i = bisect.bisect_left(self._starts, start)
        self._starts.insert(i, start)
        self._ends.insert(i, end)


# --------------------------------------------------------------------------- python AST candidates
def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os" or alias.name.startswith("os."):
                    aliases[alias.asname or "os"] = alias.name if alias.asname else "os"
        elif isinstance(node, ast.ImportFrom) and node.module == "os" and not node.level:
            for alias in node.names:
                if alias.name in {"environ", "getenv", "putenv"}:
                    aliases[alias.asname or alias.name] = f"os.{alias.name}"
    return aliases


def _qualname(expr: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(expr, ast.Name):
        return aliases.get(expr.id)
    if isinstance(expr, ast.Attribute):
        base = _qualname(expr.value, aliases)
        return f"{base}.{expr.attr}" if base else None
    return None


def _str_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _target_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        return _str_constant(target.slice)
    return None


def python_generic_candidates(text: str) -> list[tuple[int, str, str]] | None:
    """``(line, name, value)`` string constants bound to secret-named targets; ``None`` if unparseable.

    Only syntax is inspected: nothing is imported, evaluated or executed.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return None
    aliases = _import_aliases(tree)
    out: list[tuple[int, str, str]] = []

    def add(name: str | None, value_node: ast.AST | None) -> None:
        value = _str_constant(value_node)
        if name and value is not None and is_secret_name(name):
            line = getattr(value_node, "lineno", None)
            if isinstance(line, int) and line >= 1:
                out.append((line, name, value))

    for node in ast.walk(tree):
        if len(out) >= MAX_GENERIC_CANDIDATES_PER_FILE:
            break
        if isinstance(node, ast.Assign):
            for target in node.targets:
                add(_target_name(target), node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            add(_target_name(node.target), node.value)
        elif isinstance(node, ast.keyword) and node.arg:
            add(node.arg, node.value)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                add(_str_constant(key), value)
        elif isinstance(node, ast.arguments):
            positional = [*node.posonlyargs, *node.args]
            for arg, default in zip(positional[len(positional) - len(node.defaults):], node.defaults):
                add(arg.arg, default)
            for arg, default in zip(node.kwonlyargs, node.kw_defaults):
                add(arg.arg, default)
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            add(_target_name(node.left), node.comparators[0])
        elif isinstance(node, ast.Call) and _qualname(node.func, aliases) in _ENV_CALLS and node.args:
            env_name = _str_constant(node.args[0])
            default = node.args[1] if len(node.args) > 1 else next(
                (kw.value for kw in node.keywords if kw.arg in {"default", "value"}), None)
            add(env_name, default)
    return out


def line_generic_candidates(text: str, lines: _Lines) -> list[tuple[int, str, str, int]]:
    """``(line, key, value, offset)`` from ``key = value`` / ``key: value`` lines (non-Python or unparseable)."""
    out: list[tuple[int, str, str, int]] = []
    starts = lines.starts
    for index, begin in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        line = text[begin:min(end, begin + MAX_GENERIC_LINE_CHARS)]
        if not _GENERIC_LINE_HINT_RE.search(line):
            continue
        for m in _GENERIC_ASSIGN_RE.finditer(line):
            key = m.group("key")
            value = m.group("qv") if m.group("qv") is not None else m.group("uv")
            if value is None or not is_secret_name(key):
                continue
            group = "qv" if m.group("qv") is not None else "uv"
            out.append((index + 1, key, value, begin + m.start(group)))
            if len(out) >= MAX_GENERIC_CANDIDATES_PER_FILE:
                return out
    return out


# --------------------------------------------------------------------------- text scanning
@dataclass
class _Budget:
    deadline: float
    text_chars: int = MAX_TOTAL_TEXT_CHARS
    binary_bytes: int = MAX_BINARY_SCAN_BYTES
    incomplete: dict[str, Any] = field(default_factory=dict)

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline


def _spec_hit(detector: str, start: int, end: int, value: str, lines: _Lines | None, **kw: Any) -> _Hit:
    spec = DETECTORS[detector]
    return _Hit(
        detector=detector, start=start, end=end, value=value,
        line=lines.line_of(start) if lines is not None else None,
        severity=kw.pop("severity", spec.severity), confidence=kw.pop("confidence", spec.confidence),
        rank=spec.rank, **kw,
    )


def _format_hits(text: str, lines: _Lines | None, lowered: str) -> list[_Hit]:
    """Validated hits from the redaction format patterns (URL credentials are handled separately)."""
    hits: list[_Hit] = []
    service_account = bool(_SERVICE_ACCOUNT_RE.search(text))
    for detector, start, end, value in redaction.find_secrets(text):
        if len(hits) >= MAX_RAW_HITS_PER_FILE:
            break
        if detector in _SELF_HANDLED or detector not in DETECTORS:
            continue
        kw: dict[str, Any] = {}
        if detector == "private_key":
            # A header-only mention (``startswith("-----BEGIN RSA PRIVATE KEY-----")``) makes the lazy
            # redaction match run on to a later real key's END line: try each header inside the match.
            block = next((value[h.start():] for h in _PEM_HEADER_RE.finditer(value)
                          if pem_contains_key_material(value[h.start():])), None)
            if block is None:
                continue
            start, value = end - len(block), block
            if service_account and _PRIVATE_KEY_FIELD_BEFORE_RE.search(text[max(0, start - 64):start]):
                detector = "gcp_service_account"
        elif detector == "gcp_private_key_field":
            material = value.replace("\\n", "").replace("\\", "")
            if len(material) < 64 or shannon_entropy(material) < 4.0 or _looks_like_placeholder_token(material):
                continue
            if service_account:
                detector = "gcp_service_account"
        elif detector == "aws_secret_access_key":
            if not _aws_secret_shape(value):
                continue
            kw["extra"] = {"key_name_context": True}
        elif detector == "azure_storage_key":
            if _looks_like_placeholder_token(value) or shannon_entropy(value) < 3.5:
                continue
            is_account_key = bool(_AZURE_ACCOUNT_KEY_RE.search(text[max(0, start - 40):start]))
            exact = (is_account_key and len(value) == 88) or (not is_account_key and len(value) == 44)
            kw["extra"] = {"key_name": "AccountKey" if is_account_key else "SharedAccessKey"}
            if not exact:
                kw.update(severity=Severity.medium, confidence=0.6)
            if "devstoreaccount1" in lowered[max(0, start - 400):start]:
                kw["example"] = True
        elif detector == "mailgun_api_key":
            if "mailgun" not in lowered:
                continue
        elif detector == "twilio_api_key":
            if "twilio" not in lowered:
                kw.update(severity=Severity.low, confidence=0.4)
        elif detector == "heroku_api_key":
            if _looks_like_placeholder_token(value.replace("-", "")):
                continue
        elif detector == "stripe_secret_key":
            if "_test_" in value:
                kw.update(severity=Severity.medium, confidence=0.7, extra={"mode": "test"})
        elif detector in _HEADER_DETECTORS:
            if (shannon_entropy(value) < 3.0 or generic_value_rejection(value) in {"placeholder", "template",
                                                                                   "environment_lookup"}):
                continue
        if detector not in {"private_key", "gcp_service_account"} and _looks_like_placeholder_token(value):
            if "EXAMPLE" not in value.upper():
                continue
        if "EXAMPLE" in value.upper() or (detector == "jwt" and _is_sample_jwt(value)):
            kw["example"] = True
        hits.append(_spec_hit(detector, start, end, value, lines, **kw))
    return hits


def _aws_secret_shape(value: str) -> bool:
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    has_digit_or_symbol = any(c.isdigit() or c in "/+" for c in value)
    return has_upper and has_lower and has_digit_or_symbol and shannon_entropy(value) >= 3.5


def _aws_pair_hits(text: str, lines: _Lines | None, hits: list[_Hit]) -> list[_Hit]:
    """40-character secret keys within five lines of an AWS access key id (without a key name)."""
    keyed = {h.start: h for h in hits if h.detector == "aws_secret_access_key"}
    out: list[_Hit] = []
    if lines is not None:
        occupied = _IntervalSet()
        for h in sorted(hits, key=lambda item: item.start or 0):
            if h.start is not None and h.end is not None and h.detector != "aws_secret_access_key" \
                    and not occupied.overlaps(h.start, h.end):
                occupied.add(h.start, h.end)
        ids = [h for h in hits if h.detector == "aws_access_key_id" and not h.example and h.line is not None]
        for id_hit in ids[:50]:
            begin, end = lines.span(id_hit.line - 5, id_hit.line + 5)
            window = text[begin:min(end, begin + 8192)]
            for m in _AWS_SECRET_CANDIDATE_RE.finditer(window):
                value, start = m.group("value"), begin + m.start("value")
                if start in keyed:  # already found next to a key name: the pairing strengthens it
                    keyed[start].extra["paired_access_key_id"] = True
                    continue
                if (occupied.overlaps(start, start + len(value)) or not _aws_secret_shape(value)
                        or _looks_like_placeholder_token(value)):
                    continue
                hit = _spec_hit("aws_secret_access_key", start, start + len(value), value, lines, confidence=0.75,
                                extra={"paired_access_key_id": True}, example="EXAMPLE" in value.upper())
                keyed[start] = hit
                out.append(hit)
    for h in hits:
        if h.detector == "aws_secret_access_key":
            # Key name + nearby access key id: 0.9; key name only: 0.85.
            h.confidence = 0.9 if h.extra.get("paired_access_key_id") else min(h.confidence, 0.85)
    return out


def _url_hits(text: str, lines: _Lines | None) -> list[_Hit]:
    hits: list[_Hit] = []
    pos = text.find("://")
    while pos != -1 and len(hits) < MAX_RAW_HITS_PER_FILE:
        scheme_match = _URL_SCHEME_BEFORE_RE.search(text[max(0, pos - 22):pos])
        m = _URL_AUTHORITY_RE.match(text, pos + 3, min(len(text), pos + 3 + _URL_WINDOW)) if scheme_match else None
        pos = text.find("://", pos + 3)
        if m is None:
            continue
        password = m.group("password")
        user = m.group("user")
        host = m.group("host").lower()
        scheme = scheme_match.group(0).lower()
        base_scheme = scheme.split("+", 1)[0]
        lowered = password.lower()
        if (lowered in _URL_PASSWORD_PLACEHOLDERS or _TEMPLATE_RE.search(password) or password.startswith("$")
                or any(word in lowered for word in ("xxx", "changeme", "example", "your", "placeholder"))
                or _REPEATED_CHAR_RE.search(password) or len(password) < 3):
            continue
        detector = "database_url" if base_scheme in _DB_SCHEMES else "url_credentials"
        local = host in _LOCAL_HOSTS or host.endswith(_LOCAL_HOST_SUFFIXES) or host.startswith("127.")
        kw: dict[str, Any] = {"extra": {"scheme": scheme[:24], "host_class": "local_or_placeholder" if local
                                        else "remote"}}
        if local or password == user:
            kw.update(severity=Severity.low, confidence=0.35)
        start = m.start("password")
        hits.append(_spec_hit(detector, start, start + len(password), password, lines, **kw))
    return hits


def scan_text(text: str, *, python: bool, generic: bool) -> list[_Hit]:
    """All accepted (non-overlapping, validated) hits in one text; deterministic order."""
    lines = _Lines(text)
    lowered = text.lower()
    hits = _format_hits(text, lines, lowered)
    hits.extend(_aws_pair_hits(text, lines, hits))
    hits.extend(_url_hits(text, lines))
    accepted = _resolve_overlaps(hits)
    if generic:
        accepted.extend(_generic_hits(text, lines, python=python, stronger=accepted))
    accepted.sort(key=lambda h: (h.line or 0, h.start if h.start is not None else -1, h.rank, h.detector))
    return accepted


def scan_binary_text(text: str) -> list[_Hit]:
    """Hits in the printable runs of a binary (no line numbers, no generic keyword detection)."""
    lowered = text.lower()
    hits = _format_hits(text, None, lowered)
    hits.extend(_url_hits(text, None))
    accepted = _resolve_overlaps(hits)
    accepted.sort(key=lambda h: (h.start or 0, h.rank, h.detector))
    return accepted


def _resolve_overlaps(hits: list[_Hit]) -> list[_Hit]:
    spans = _IntervalSet()
    accepted: list[_Hit] = []
    for hit in sorted(hits, key=lambda h: (h.rank, h.start or 0, -((h.end or 0) - (h.start or 0)), h.detector)):
        if hit.start is None or hit.end is None or spans.overlaps(hit.start, hit.end):
            continue
        spans.add(hit.start, hit.end)
        accepted.append(hit)
    return accepted


def _generic_hits(text: str, lines: _Lines, *, python: bool, stronger: list[_Hit]) -> list[_Hit]:
    candidates: list[tuple[int, str, str, int | None]] = []
    parsed = python_generic_candidates(text) if python and len(text) <= MAX_AST_CHARS else None
    if parsed is not None:
        candidates = [(line, name, value, None) for line, name, value in parsed]
    else:
        candidates = list(line_generic_candidates(text, lines))
    by_line: dict[int, list[_Hit]] = {}
    for h in stronger:
        if h.line is not None:
            by_line.setdefault(h.line, []).append(h)
    out: list[_Hit] = []
    seen: set[tuple[int, str]] = set()
    spec = DETECTORS["generic_secret"]
    for line, name, value, offset in candidates:
        if (line, value) in seen:
            continue
        seen.add((line, value))
        if any(h.value in value or value in h.value for h in by_line.get(line, ())):
            continue
        if generic_value_rejection(value) is not None:
            continue
        strong = len(value) >= 24 and shannon_entropy(value) >= 4.0 and _char_classes(value) >= 3
        out.append(_Hit(
            detector="generic_secret", start=offset, end=offset + len(value) if offset is not None else None,
            value=value, line=line, severity=Severity.medium if strong else spec.severity,
            confidence=0.5 if strong else spec.confidence, rank=spec.rank, name=name,
        ))
    return out


# --------------------------------------------------------------------------- record building
def _record(hit: _Hit, *, relpath: str, order: int, context: str, origin: str | None = None,
            byte_offset: int | None = None) -> _Record:
    spec = DETECTORS[hit.detector]
    severity = hit.severity
    confidence = _context_adjusted(hit.confidence, context)
    if hit.example:
        severity = Severity.info
        confidence = min(confidence, DOCUMENTED_EXAMPLE_CONFIDENCE)
    evidence: dict[str, Any] = {
        "detector": hit.detector,
        "redacted": redaction.redact_value(hit.value, hit.detector, keep_prefix=spec.keep_prefix),
        "fingerprint": redaction.fingerprint(hit.value),
        "length": len(hit.value),
        "entropy": round(shannon_entropy(hit.value), 2),
        "context": context,
    }
    evidence.update(hit.extra)
    if hit.example:
        evidence["documented_example"] = True
    if hit.name:
        evidence["name"] = hit.name[:64]
    if origin:
        evidence["origin"] = origin
    if byte_offset is not None:
        evidence["byte_offset"] = byte_offset
    where = f"{relpath} line {hit.line}" if hit.line else relpath
    if hit.example:
        message = f"Documented example {spec.label} in {where} (not a live credential)"
    elif hit.detector == "generic_secret":
        message = f"Possible hard-coded secret assigned to '{hit.name}' in {where} (value redacted)"
    else:
        message = f"Hard-coded {spec.label} in {where} (value redacted)"
    return _Record(order, relpath, hit.line, hit.detector, severity, confidence, message, evidence,
                   Provenance.STATIC)


# --------------------------------------------------------------------------- gitleaks adapter
class GitleaksReportError(ValueError):
    """A gitleaks report could not be used. ``reason`` is machine-readable and log-safe."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class GitleaksResult:
    relpath: str
    line: int | None
    rule_id: str
    detector: str
    description: str | None
    entropy: float | None


def _version_tuple(version: str | None) -> tuple[int, int, int] | None:
    match = re.match(r"^\s*v?(\d+)\.(\d+)(?:\.(\d+))?", version or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def gitleaks_argv(binary: str, source: str | os.PathLike[str], report_path: str | os.PathLike[str], *,
                  version: str | None = None) -> list[str]:
    """argv for a no-git directory scan with a redacted JSON report (no shell, one item per argument).

    gitleaks ≥ 8.19 uses ``dir <path>``; older (or unknown) versions use ``detect --no-git --source``,
    which 8.19+ still accepts. ``--exit-code 0`` keeps "leaks found" distinguishable from failures.
    """
    common = ["--report-format", "json", "--report-path", os.fspath(report_path), "--redact", "--no-banner",
              "--exit-code", "0", "--log-level", "error"]
    parsed = _version_tuple(version)
    if parsed is not None and parsed >= _GITLEAKS_DIR_COMMAND_VERSION:
        return [binary, "dir", *common, os.fspath(source)]
    return [binary, "detect", "--no-git", "--source", os.fspath(source), *common]


def canonical_gitleaks_detector(rule_id: str) -> str:
    rule = rule_id.lower()
    if rule in GITLEAKS_RULE_MAP:
        return GITLEAKS_RULE_MAP[rule]
    for prefix, detector in _GITLEAKS_RULE_PREFIXES:
        if rule.startswith(prefix):
            return detector
    return "gitleaks_" + (re.sub(r"[^a-z0-9]+", "_", rule).strip("_")[:40] or "rule")


def _report_relpath(file_value: Any, root: str | None, known: dict[str, str]) -> str | None:
    if not isinstance(file_value, str) or not file_value or len(file_value) > 4096 or "\x00" in file_value:
        return None
    path = file_value.replace("\\", "/")
    folded = path.casefold()
    if root:
        root_folded = root.replace("\\", "/").rstrip("/").casefold()
        if folded.startswith(root_folded + "/"):
            candidate = folded[len(root_folded) + 1:]
            if candidate in known:
                return known[candidate]
    while folded.startswith("./"):
        folded = folded[2:]
    if folded in known:
        return known[folded]
    # Absolute paths through a differently spelled temp root (short names, symlinked /tmp): longest
    # known relative path that ends the reported path on a component boundary.
    best: str | None = None
    for key, rel in known.items():
        if folded.endswith("/" + key) and (best is None or len(rel) > len(best)):
            best = rel
    return best


def parse_gitleaks_report(raw: str | bytes, *, root: str | os.PathLike[str] | None, known_files: Iterable[str],
                          line_counts: dict[str, int] | None = None) -> tuple[list[GitleaksResult], dict[str, int]]:
    """Parse a gitleaks JSON report into results for files Warden materialised.

    Reads only ``RuleID``, ``Description``, ``File``, ``StartLine`` and ``Entropy``; ``Secret``,
    ``Match`` and ``Line`` are never accessed. Results for unknown files, and lines outside the
    file, are dropped / cleared rather than guessed.
    """
    if isinstance(raw, bytes):
        if len(raw) > MAX_GITLEAKS_REPORT_BYTES:
            raise GitleaksReportError("report_too_large")
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) > MAX_GITLEAKS_REPORT_BYTES:
        raise GitleaksReportError("report_too_large")
    try:
        data = json.loads(raw) if raw.strip() else []
    except (ValueError, RecursionError) as exc:
        raise GitleaksReportError("report_not_json") from exc
    if not isinstance(data, list):
        raise GitleaksReportError("report_not_a_list")
    known = {rel.casefold(): rel for rel in sorted(known_files)}
    root_s = os.fspath(root) if root is not None else None
    stats = {"results": 0, "dropped_unknown_file": 0, "dropped_invalid": 0, "truncated": 0}
    results: list[GitleaksResult] = []
    for index, item in enumerate(data):
        if index >= MAX_GITLEAKS_RESULTS:
            stats["truncated"] = len(data) - MAX_GITLEAKS_RESULTS
            break
        if not isinstance(item, dict):
            stats["dropped_invalid"] += 1
            continue
        rule = item.get("RuleID")
        if not isinstance(rule, str) or not rule.strip() or len(rule) > 200:
            stats["dropped_invalid"] += 1
            continue
        relpath = _report_relpath(item.get("File"), root_s, known)
        if relpath is None:
            stats["dropped_unknown_file"] += 1
            continue
        line = item.get("StartLine")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            line = None
        elif line_counts is not None and relpath in line_counts and line > line_counts[relpath]:
            line = None
        elif line_counts is not None and relpath not in line_counts:
            line = None  # binaries have no meaningful line
        entropy = item.get("Entropy")
        entropy_value = None
        if isinstance(entropy, (int, float)) and not isinstance(entropy, bool) and math.isfinite(entropy):
            entropy_value = round(max(0.0, min(8.0, float(entropy))), 2)
        description = item.get("Description")
        rule_id = re.sub(r"[^a-z0-9._-]+", "-", rule.strip().lower())[:64]
        results.append(GitleaksResult(
            relpath=relpath, line=line, rule_id=rule_id, detector=canonical_gitleaks_detector(rule_id),
            description=redaction.sanitize_text(description, max_len=120) if isinstance(description, str) else None,
            entropy=entropy_value,
        ))
    stats["results"] = len(results)
    return results, stats


def _gitleaks_record(result: GitleaksResult, order: int, *, binary: bool) -> _Record:
    spec = DETECTORS.get(result.detector)
    if spec is None:
        severity, confidence, label = Severity.medium, 0.6, "secret"
    elif result.detector == "generic_secret":
        severity, confidence, label = Severity.low, 0.3, spec.label
    else:
        # The value cannot be validated (the report is redacted), so confidence is slightly lower.
        severity, confidence, label = spec.severity, spec.confidence - 0.05, spec.label
    context = "binary" if binary else classify_context(result.relpath)
    evidence: dict[str, Any] = {
        "detector": result.detector,
        "tool": GITLEAKS_TOOL,
        "rule_id": result.rule_id,
        "redacted": "[REDACTED]",
        "context": context,
    }
    if result.entropy is not None:
        evidence["entropy"] = result.entropy
    if result.description:
        evidence["description"] = result.description
    where = f"{result.relpath} line {result.line}" if result.line else result.relpath
    return _Record(order, result.relpath, result.line, result.detector, severity,
                   _context_adjusted(confidence, context), f"Hard-coded {label} in {where} (reported by gitleaks)",
                   evidence, Provenance.tool(GITLEAKS_TOOL))


def merge_gitleaks(records: list[_Record], results: Sequence[GitleaksResult], order_of: dict[str, int], *,
                   binary_paths: Iterable[str] = ()) -> int:
    """Merge gitleaks results into built-in records in place; returns the number of new records."""
    binaries = frozenset(binary_paths)
    index: dict[tuple[str, int | None], list[_Record]] = {}
    for record in records:
        index.setdefault((record.relpath, record.line), []).append(record)
    added = 0
    seen: set[tuple[str, int | None, str]] = set()
    for result in results:
        key = (result.relpath, result.line, _family(result.detector))
        if key in seen:
            continue
        seen.add(key)
        duplicates = [
            r for r in index.get((result.relpath, result.line), [])
            if _family(r.detector) == _family(result.detector) or "generic_secret" in {r.detector, result.detector}
        ]
        if duplicates:
            for record in duplicates:
                corroborated = record.evidence.setdefault("corroborated_by", [])
                if GITLEAKS_TOOL not in corroborated:
                    corroborated.append(GITLEAKS_TOOL)
            continue
        record = _gitleaks_record(result, order_of.get(result.relpath, len(order_of)),
                                  binary=result.relpath in binaries)
        records.append(record)
        index.setdefault((record.relpath, record.line), []).append(record)
        added += 1
    return added


# --------------------------------------------------------------------------- analyzer
class SecretsAnalyzer(BaseAnalyzer):
    """Built-in secret detectors plus an optional gitleaks pass (see module docstring)."""

    name = ANALYZER_NAME
    version = ANALYZER_VERSION

    # ------------------------------------------------------------------ availability
    @staticmethod
    def gitleaks_status() -> ToolStatus:
        if not settings.GITLEAKS_ENABLED:
            return ToolStatus(name=GITLEAKS_TOOL, available=False, detail="disabled by configuration")
        from app.analysis import tools  # lazy: tools imports the analyzer package

        status = tools.find_tool(settings.GITLEAKS_BINARY)
        return ToolStatus(name=GITLEAKS_TOOL, available=bool(status.available), version=status.version,
                          detail=status.detail)

    def availability(self) -> ToolStatus:
        gitleaks = self.gitleaks_status()
        if gitleaks.available:
            detail = f"built-in detectors active; optional gitleaks {gitleaks.version or 'unknown version'} available"
        else:
            detail = f"built-in detectors active; optional gitleaks unavailable ({gitleaks.detail or 'not found'})"
        return ToolStatus(name=self.name, available=True, version=self.version, detail=detail)

    # ------------------------------------------------------------------ entry point
    def analyze(self, ctx: PackageContext) -> list[Finding]:
        started = time.monotonic()
        timeout = max(1.0, float(settings.ANALYZER_TIMEOUT_SECONDS))
        # Limits are read at call time (not as dataclass defaults) so configuration changes apply.
        budget = _Budget(deadline=started + timeout * BUILTIN_BUDGET_FRACTION, text_chars=MAX_TOTAL_TEXT_CHARS,
                         binary_bytes=MAX_BINARY_SCAN_BYTES)
        order_of: dict[str, int] = {}
        records = self._builtin(ctx, budget, order_of)

        extra: list[Finding] = []
        if settings.GITLEAKS_ENABLED:
            status = self.gitleaks_status()
            if status.available:
                remaining = started + timeout * GITLEAKS_BUDGET_FRACTION - time.monotonic()
                tool_timeout = min(float(settings.TOOL_TIMEOUT_SECONDS), remaining)
                failure: str | None
                if tool_timeout < MIN_GITLEAKS_TIMEOUT_SECONDS:
                    failure = "no_time_budget"
                else:
                    failure = self._gitleaks(ctx, status, tool_timeout, records, order_of)
                if failure:
                    log.warning("gitleaks_degraded", status=failure)
                    extra.append(Finding(
                        Code.TOOL_UNAVAILABLE, Severity.info, 0.0,
                        "Optional gitleaks secret scan did not complete; built-in secret detectors still ran",
                        {"analyzer": self.name, "tool": GITLEAKS_TOOL, "version": status.version, "status": failure},
                        confidence=1.0, provenance=Provenance.tool(GITLEAKS_TOOL),
                    ))
        findings = self._finalize(records, budget)
        return findings + extra

    # ------------------------------------------------------------------ built-in pass
    def _builtin(self, ctx: PackageContext, budget: _Budget, order_of: dict[str, int]) -> list[_Record]:
        records: list[_Record] = []
        files = list(ctx.files or [])
        sdist_digests = {hashlib.sha256((f.text or "").encode("utf-8", "surrogatepass")).digest() for f in files}
        wheel_only = [
            f for f in (ctx.wheel_files or [])
            if hashlib.sha256((f.text or "").encode("utf-8", "surrogatepass")).digest() not in sdist_digests
        ]
        queue = [(f, None) for f in files] + [(f, "wheel") for f in wheel_only]
        for position, (source, origin) in enumerate(queue):
            if budget.expired():
                budget.incomplete.update(reason="time_budget", files_skipped=len(queue) - position)
                break
            text = source.text or ""
            if len(text) > MAX_TEXT_FILE_CHARS:
                text = text[:MAX_TEXT_FILE_CHARS]
                budget.incomplete.setdefault("files_truncated", 0)
                budget.incomplete["files_truncated"] += 1
            if len(text) > budget.text_chars:
                budget.incomplete.update(reason="size_budget", files_skipped=len(queue) - position)
                break
            budget.text_chars -= len(text)
            relpath = source.relpath
            order = order_of.setdefault(relpath, len(order_of))
            context = classify_context(relpath)
            lowered_path = relpath.lower()
            python = lowered_path.endswith(_PYTHON_SUFFIXES)
            generic = context != "documentation" and not lowered_path.endswith(".txt")
            hits = scan_text(text, python=python, generic=generic)
            records.extend(_record(h, relpath=relpath, order=order, context=context, origin=origin) for h in hits)
        if "reason" not in budget.incomplete or budget.incomplete.get("reason") == "size_budget":
            self._binaries(ctx, budget, order_of, records)
        return records

    def _binaries(self, ctx: PackageContext, budget: _Budget, order_of: dict[str, int],
                  records: list[_Record]) -> None:
        items = sorted((ctx.binaries or {}).items())
        for position, (relpath, data) in enumerate(items):
            if budget.expired():
                budget.incomplete.update(reason="time_budget", binaries_skipped=len(items) - position)
                return
            remaining = budget.binary_bytes
            if remaining <= 0:
                budget.incomplete.update(reason="binary_budget", binaries_skipped=len(items) - position)
                return
            chunk = bytes(data[:remaining])
            if len(data) > remaining:  # only a prefix of this binary is searched
                budget.incomplete.setdefault("reason", "binary_budget")
                budget.incomplete["binaries_truncated"] = budget.incomplete.get("binaries_truncated", 0) + 1
            budget.binary_bytes -= len(chunk)
            masked = bytearray(len(chunk))  # non-run bytes stay NUL: offsets map 1:1 to the binary
            found_run = False
            for m in _PRINTABLE_RUN_RE.finditer(chunk):
                masked[m.start():m.end()] = m.group()
                found_run = True
            if not found_run:
                continue
            text = masked.decode("latin-1")
            order = order_of.setdefault(relpath, len(order_of))
            for hit in scan_binary_text(text):
                records.append(_record(hit, relpath=relpath, order=order, context="binary", byte_offset=hit.start))

    # ------------------------------------------------------------------ gitleaks pass
    def _gitleaks(self, ctx: PackageContext, status: ToolStatus, timeout: float, records: list[_Record],
                  order_of: dict[str, int]) -> str | None:
        from app.analysis import tools  # lazy: tools imports the analyzer package

        files = [f for f in (ctx.files or []) if _basename(f.relpath) not in _GITLEAKS_CONFIG_NAMES]
        binaries = {rel: data for rel, data in (ctx.binaries or {}).items()
                    if _basename(rel) not in _GITLEAKS_CONFIG_NAMES}
        line_counts = {f.relpath: _Lines(f.text or "").count() for f in files}
        view = SimpleNamespace(files=files, binaries=binaries)
        try:
            with tools.package_workspace(view) as workspace:
                report = workspace.root / GITLEAKS_REPORT_NAME
                argv = gitleaks_argv(settings.GITLEAKS_BINARY, workspace.root, report, version=status.version)
                result = tools.run_tool(argv, timeout=timeout, cwd=workspace.root)
                if result.timed_out:
                    return "timeout"
                if result.returncode != 0:
                    return f"exit_{result.returncode}"
                if not report.is_file():
                    return "no_report"
                if report.stat().st_size > MAX_GITLEAKS_REPORT_BYTES:
                    return "report_too_large"
                raw = report.read_bytes()
                known = list(workspace.files)
        except (tools.ToolError, ValueError, OSError) as exc:
            return f"launch_failed:{type(exc).__name__}"
        try:
            results, stats = parse_gitleaks_report(raw, root=str(workspace.root), known_files=known,
                                                   line_counts=line_counts)
        except GitleaksReportError as exc:
            return exc.reason
        added = merge_gitleaks(records, results, order_of, binary_paths=binaries.keys())
        log.info("gitleaks_scan_complete", results=stats["results"], added=added,
                 dropped_unknown_file=stats["dropped_unknown_file"], dropped_invalid=stats["dropped_invalid"])
        return None

    # ------------------------------------------------------------------ output
    def _finalize(self, records: list[_Record], budget: _Budget) -> list[Finding]:
        per_file: dict[str, int] = {}
        kept: list[_Record] = []
        omitted = 0
        # Strongest first when choosing what to keep under the caps; emitted in file/line order.
        ranked = sorted(records, key=lambda r: (-r.severity.rank, -r.confidence, r.order, r.line or 0, r.detector))
        for record in ranked:
            if len(kept) >= MAX_FINDINGS or per_file.get(record.relpath, 0) >= MAX_FINDINGS_PER_FILE:
                omitted += 1
                continue
            per_file[record.relpath] = per_file.get(record.relpath, 0) + 1
            kept.append(record)
        kept.sort(key=lambda r: (r.order, r.line or 0, r.detector, r.evidence.get("fingerprint", ""),
                                 r.evidence.get("byte_offset", 0)))
        findings = [r.to_finding() for r in kept]
        incomplete = dict(budget.incomplete)
        if omitted:
            incomplete.setdefault("reason", "finding_cap")
            incomplete["findings_omitted"] = omitted
        if incomplete:
            if "reason" not in incomplete:
                incomplete["reason"] = "file_truncated"
            findings.append(Finding(
                CODE_SCAN_INCOMPLETE, Severity.info, 0.0,
                "Secret scan was bounded: part of the package was not searched or findings were omitted",
                {**incomplete, "max_findings": MAX_FINDINGS, "max_findings_per_file": MAX_FINDINGS_PER_FILE},
                confidence=1.0,
            ))
        return findings


def _basename(relpath: str) -> str:
    return str(relpath).replace("\\", "/").rsplit("/", 1)[-1].casefold()


__all__ = [
    "ANALYZER_VERSION",
    "CODE_SCAN_INCOMPLETE",
    "DETECTORS",
    "GITLEAKS_RULE_MAP",
    "GitleaksReportError",
    "GitleaksResult",
    "SecretsAnalyzer",
    "canonical_gitleaks_detector",
    "classify_context",
    "generic_value_rejection",
    "gitleaks_argv",
    "is_secret_name",
    "merge_gitleaks",
    "parse_gitleaks_report",
    "pem_contains_key_material",
    "python_generic_candidates",
    "scan_text",
    "shannon_entropy",
]
