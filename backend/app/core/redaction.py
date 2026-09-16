"""Redaction and output-sanitisation helpers.

Warden handles two kinds of dangerous strings:

1. **Secrets** — credentials discovered inside packages/projects, and Warden's own tokens.
   These must never reach logs, the database, API responses, telemetry, or reports in
   recoverable form. ``redact_text`` replaces high-confidence secret patterns with a
   non-reversible marker; ``fingerprint`` gives a keyed, non-reversible identifier that can
   be used to de-duplicate a secret without storing it.
2. **Attacker-controlled text** — file names, string literals and registry metadata taken
   from hostile packages. Such text can carry terminal escape sequences, bidirectional
   overrides ("Trojan Source"), zero-width characters, or markup. ``sanitize_text`` escapes
   control/bidi characters and bounds length; ``terminal_safe``, ``html_escape`` and
   ``markdown_escape`` make text safe for a specific output sink.

Every function here is pure. The sanitisers (``redact_text``, ``sanitize_text``,
``sanitize_evidence``, ``redact_structure``) are also idempotent: sanitising already-sanitised
data is a no-op, which keeps identifiers derived from sanitised evidence (e.g. finding ids)
stable across serialisation round-trips. The sink escapers (``html_escape``,
``markdown_escape``) are deliberately *not* idempotent — escaping ``&`` twice yields
``&amp;amp;`` — so apply each exactly once, at the output boundary.

Redaction is pattern-based and high-precision: it is designed to remove the credential
formats listed in :data:`SECRET_PATTERNS` and :data:`EXTENDED_SECRET_PATTERNS` (applied together,
in the order of :data:`ALL_SECRET_PATTERNS`), and values stored under secret-named keys — not
arbitrary secrets such as free-form passwords in prose.

Token patterns are anchored with "no letter or digit before / after" rather than ``\\b``, so a
token glued to a preceding identifier (``MY_TOKEN_ghp_…``, ``url_postgres://…``) is still
redacted: ``_`` is a word character and used to defeat the ``\\b`` anchor.

Pattern order matters: patterns run one after another on the output of the previous one, and a
token marker (``AKIA…[REDACTED:…]``) contains ``[`` which later patterns deliberately refuse to
match (idempotency). ``url_credentials`` and the key-anchored patterns (``AccountKey=``,
``"private_key": "…"``, Heroku keys) therefore run before every token pattern, so a token-shaped
*prefix* cannot shield the secret that follows it. ``aws_secret_access_key`` runs last: it needs
exactly 40 key characters, and a marker inserted by an earlier token pattern could otherwise
shorten a longer run to exactly 40 characters on a second pass. Under a secret-named key
(``password``, ``token``, ``cookie``, ``credentials`` …) every value other than ``None``, a
boolean or an empty string is replaced — lists, mappings, bytes and numbers included — unless
the key is one of the explicitly safe metadata keys.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import math
import re
from collections.abc import Mapping
from typing import Any

# (detector id, pattern). Patterns are deliberately high-precision: they match credential
# formats with distinctive prefixes or structure, never "any long random-looking string".
# Patterns with a named ``secret`` group redact only that group (keeping e.g. the URL).
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)"
    )),
    # The user part may be empty (``redis://:password@host``). The password may itself contain
    # ``@`` (URL parsers split userinfo at the *last* ``@``), so the greedy secret group runs
    # to the last ``@`` of the authority. ``[`` / ``]`` are excluded so the ``[REDACTED]``
    # marker can never be re-matched (idempotency). Runs before the token patterns (see module docstring).
    # The scheme may follow an identifier character such as ``_`` (``DB_URL_postgres://``).
    ("url_credentials", re.compile(
        r"(?P<prefix>(?<![A-Za-z0-9+.\-])[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@\[\]]{0,128}:)"
        r"(?P<secret>[^\s/\[\]]{1,256})(?P<suffix>@)"
    )),
    # Token patterns: "no letter/digit before" instead of ``\b`` (see module docstring).
    ("aws_access_key_id", re.compile(
        r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}(?![A-Za-z0-9])"
    )),
    ("github_token", re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,251}(?![A-Za-z0-9])")),
    ("github_fine_grained_pat", re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,242}(?![A-Za-z0-9_])")),
    ("gitlab_token", re.compile(
        r"(?<![A-Za-z0-9])gl(?:pat|dt|rt|cbt|ptt|ft|imt)-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])"
    )),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]{20,}")),
    ("stripe_secret_key", re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}(?![A-Za-z0-9])")),
    ("google_api_key", re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])")),
    ("pypi_token", re.compile(r"(?<![A-Za-z0-9])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")),
    ("npm_token", re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])")),
    ("anthropic_api_key", re.compile(r"(?<![A-Za-z0-9])sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}")),
    ("openai_api_key", re.compile(
        r"(?<![A-Za-z0-9])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"
        r"|(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}(?![A-Za-z0-9])"
    )),
    ("jwt", re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer_token", re.compile(
        r"(?i)(?P<prefix>\bauthorization[\"']?\s*[:=]\s*[\"']?bearer\s+)(?P<secret>[A-Za-z0-9._~+/\-]{16,}=*)"
    )),
    # Any HTTP auth scheme after an (Proxy-)Authorization header name, including header-tuple
    # reprs such as ``(b'authorization', b'Basic ...')``. Basic credentials are reversible base64.
    ("authorization_header", re.compile(
        r"(?i)(?P<prefix>\b(?:proxy-)?authorization\b[\"']?(?:\s*[:=,]\s*b?|\s+)[\"']?\s*"
        r"(?:basic|bearer|token|digest|negotiate)\s+)(?P<secret>[A-Za-z0-9._~+/\-]{8,}=*)"
    )),
    # A bare ``Bearer <token>`` / ``Basic <credentials>`` without the header name. Requires a long
    # value with both a digit and a letter so ordinary prose ("basic authentication") is untouched.
    ("auth_scheme_credentials", re.compile(
        r"(?i)(?P<prefix>\b(?:bearer|basic)\s+)"
        r"(?P<secret>(?=[A-Za-z0-9._~+/\-]*\d)(?=[A-Za-z0-9._~+/\-]*[A-Za-z])[A-Za-z0-9._~+/\-]{20,}=*)"
    )),
)

# Warden X additions. Kept in a separate tuple so ``SECRET_PATTERNS`` stays the stable v1 set;
# ``ALL_SECRET_PATTERNS`` (below) is what every function in this module applies.
# Key-anchored formats: only the value after the key is redacted. They run right after
# ``url_credentials`` (see module docstring for why).
_KEY_ANCHORED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Azure Storage ``AccountKey=`` and Service Bus / Event Hubs ``SharedAccessKey=`` in connection strings.
    # ``SharedAccessKeyName=`` (a key *name*) does not match: ``=`` must follow the key.
    ("azure_storage_key", re.compile(
        r"(?P<prefix>(?<![A-Za-z0-9])(?i:AccountKey|SharedAccessKey)\s*=\s*)(?P<secret>[A-Za-z0-9+/]{20,}={0,2})"
    )),
    # ``"private_key": "<key material>"`` JSON/YAML fields (GCP service-account files, JWK-like
    # configs) whose value is not PEM armoured; PEM values are handled by ``private_key``.
    ("gcp_private_key_field", re.compile(
        r"(?P<prefix>\\?[\"']private_key\\?[\"']\s*:\s*\\?[\"'])(?!-----BEGIN)(?P<secret>[A-Za-z0-9+/=_\\\-]{40,})"
    )),
    # Heroku API keys are plain UUIDs, so they are only recognised next to a Heroku key name:
    # ``HEROKU_API_KEY=…``, ``heroku.token: …`` or a key directly nested under a ``heroku:`` YAML
    # mapping (``heroku:\n  api_key: …``). The line break may also be the escaped form that
    # ``sanitize_text`` produces (``\\n``, ``\\x0d\\n``), so sanitised text is redacted the same way.
    ("heroku_api_key", re.compile(
        r"(?i)(?P<prefix>(?<![A-Za-z0-9])heroku[A-Za-z0-9_.\-]{0,32}?"
        r"(?:[\"']?[ \t]{0,8}:[ \t]{0,8}(?:\r?\n|(?:\\r|\\x0d)?\\n)[ \t]{1,16})?(?:api[_-]?key|token|secret|key)"
        r"[\"']?\s*[:=]{1,2}>?\s*[\"']?)"
        r"(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![0-9a-z])"
    )),
)
# Provider token formats with distinctive prefixes. They run after the v1 patterns.
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("slack_app_token", re.compile(r"(?<![A-Za-z0-9])xapp-\d-[A-Za-z0-9]{8,}-\d{8,}-[A-Za-z0-9]{24,}(?![A-Za-z0-9])")),
    ("twilio_api_key", re.compile(r"(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![A-Za-z0-9])")),
    ("sendgrid_api_key", re.compile(
        r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-])"
    )),
    # Legacy Mailgun private keys. A preceding ``-`` or ``_`` (``api-key-…``, ``monkey-…``) does not match.
    ("mailgun_api_key", re.compile(r"(?<![A-Za-z0-9_\-])key-[0-9a-f]{32}(?![A-Za-z0-9])")),
)
# AWS secret access keys have no prefix: recognised only after an AWS secret-key name. Runs last.
_LAST_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_secret_access_key", re.compile(
        r"(?i)(?P<prefix>(?<![A-Za-z0-9])(?:aws_?secret_?(?:access_?)?key|secret_?access_?key)"
        r"[\"']?\s*[:=]{1,2}>?\s*[\"']?)"
        r"(?P<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"
    )),
)
EXTENDED_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    _KEY_ANCHORED_PATTERNS + _TOKEN_PATTERNS + _LAST_PATTERNS
)
# Application order: private key and URL credentials, key-anchored values, v1 tokens and HTTP
# authorization credentials, the new token formats, then AWS secret access keys.
ALL_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    SECRET_PATTERNS[:2] + _KEY_ANCHORED_PATTERNS + SECRET_PATTERNS[2:] + _TOKEN_PATTERNS + _LAST_PATTERNS
)
if [d for d, _ in SECRET_PATTERNS[:2]] != ["private_key", "url_credentials"]:  # pragma: no cover - import guard
    raise RuntimeError("ALL_SECRET_PATTERNS ordering assumes private_key and url_credentials come first")

# Keys whose *values* are always treated as secret, whatever they look like.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential)"
)
# Keys that match the sensitive pattern above but only ever hold safe metadata.
_SAFE_KEYS = frozenset({
    "token_type", "secret_type", "detector", "fingerprint", "secret_detector", "credential_type",
    "sensitive", "sensitive_env", "sensitive_paths", "expires_in",
    # Counters / flags logged and audited by the auth, users and system routes.
    "revoked_tokens", "revoked_refresh_tokens", "token_required",
})


def _is_secret_key(key: object) -> bool:
    return isinstance(key, str) and key not in _SAFE_KEYS and bool(_SENSITIVE_KEY_RE.search(key))


def _redactable(value: object) -> bool:
    """Values replaced under a secret-named key: everything except ``None``, booleans and ``""``."""
    return value is not None and not isinstance(value, bool) and value != ""

# Invisible or direction-changing characters, escaped by ``sanitize_text``: C0 controls (except
# TAB/LF), DEL, C1 controls, soft hyphen, ARABIC LETTER MARK, MONGOLIAN VOWEL SEPARATOR,
# zero-width chars and LRM/RLM, line/paragraph separators, bidi embeddings/overrides/isolates,
# word joiner / invisible operators, deprecated format chars, BOM, interlinear annotation
# controls, and Unicode "tag" characters (invisible ASCII look-alikes used to smuggle text).
_CONTROL_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\xad\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e"
    "\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]"
)
_MD_SPECIAL_RE = re.compile(r"([\\`*_{}\[\]()#+!|~])")

# The private-key marker includes an END line: a marker that ended at "[REDACTED]" would be
# re-matched by the (deliberately END-optional) private-key pattern on a second pass, which
# would then swallow all text after it.
PRIVATE_KEY_MARKER = "-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----"
# Strings accepted as "already redacted" under secret-named keys (see ``sanitize_evidence``):
# ``[REDACTED]``, the private-key marker, or the ``redact_value`` / ``redact_text`` forms whose
# visible prefix is at most four identifier characters (a type prefix such as ``AKIA``).
_MARKER_RE = re.compile(
    r"\[REDACTED\]"
    r"|-----BEGIN PRIVATE KEY-----\[REDACTED\](?:-----END PRIVATE KEY-----)?"
    r"|[A-Za-z0-9_\-]{0,4}…\[REDACTED:[a-z0-9_]{1,40}(?::len=[0-9]{1,10})?\]"
)
_MAX_SANITIZE_PASSES = 8


def _escape_char(match: re.Match[str]) -> str:
    code = ord(match.group(0))
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def _mask(match: re.Match[str], detector: str) -> str:
    groups = match.groupdict()
    if groups.get("secret") is not None:
        return f"{groups.get('prefix') or ''}[REDACTED]{groups.get('suffix') or ''}"
    if detector == "private_key":
        return PRIVATE_KEY_MARKER
    return f"{match.group(0)[:4]}…[REDACTED:{detector}]"


def redact_text(text: str) -> str:
    """Replace every high-confidence secret in ``text`` with a non-reversible marker."""
    if not text:
        return text
    out = text
    for detector, pattern in ALL_SECRET_PATTERNS:
        out = pattern.sub(lambda m, d=detector: _mask(m, d), out)
    return out


def is_redaction_marker(value: str) -> bool:
    """True when ``value`` is exactly one of the markers this module produces."""
    return bool(_MARKER_RE.fullmatch(value))


def find_secrets(text: str) -> list[tuple[str, int, int, str]]:
    """Return ``(detector, start, end, value)`` for each high-confidence secret match.

    The raw ``value`` is returned so a detector can compute a fingerprint or line number;
    callers must never persist, log or return it — use :func:`redact_value` instead.
    """
    hits: list[tuple[str, int, int, str]] = []
    for detector, pattern in ALL_SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if m.groupdict().get("secret") is not None:
                hits.append((detector, m.start("secret"), m.end("secret"), m.group("secret")))
            else:
                hits.append((detector, m.start(), m.end(), m.group(0)))
    return hits


def redact_value(value: str, detector: str = "secret", *, keep_prefix: bool = True) -> str:
    """A display-safe stand-in for a secret value: type prefix + length, never the secret.

    The first four characters are shown only for values of at least 16 characters, and only
    while ``keep_prefix`` is true. Pass ``keep_prefix=False`` for formats without a public type
    prefix (passwords, AWS secret access keys, generic secrets), where those four characters
    would be part of the secret itself.
    """
    if detector == "private_key":
        return PRIVATE_KEY_MARKER
    prefix = value[:4] if keep_prefix and len(value) >= 16 else ""
    return f"{prefix}…[REDACTED:{detector}:len={len(value)}]"


def fingerprint(value: str, *, key: bytes | None = None) -> str:
    """Keyed, non-reversible identifier for a secret (HMAC-SHA256, truncated).

    Keyed so that a leaked fingerprint cannot be used to confirm a guessed secret offline.
    """
    if key is None:
        from app.core.config import settings

        key = (settings.SECRET_FINGERPRINT_KEY or settings.SECRET_KEY).encode("utf-8")
    digest = hmac.new(key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
    return "hmac-sha256:" + digest[:32]


def sanitize_text(value: object, *, max_len: int = 300, redact: bool = True, keep_newlines: bool = False) -> str:
    """Escape control/bidi characters, redact secrets, and bound the length of ``value``."""
    s = value if isinstance(value, str) else str(value)
    # Lone surrogates (from surrogateescape-decoded bytes) cannot be UTF-8 encoded later.
    s = s.encode("utf-8", "backslashreplace").decode("utf-8")
    if not keep_newlines:
        s = s.replace("\n", "\\n")
    s = _CONTROL_RE.sub(_escape_char, s)
    if redact:
        s = redact_text(s)
    if max_len > 0 and len(s) > max_len:
        s = _truncate(s, max_len, redact)
    return s


def _first_match_start(text: str) -> int:
    starts = [m.start() for _, pattern in ALL_SECRET_PATTERNS if (m := pattern.search(text))]
    return min(starts) if starts else 0


def _truncate(s: str, max_len: int, redact: bool) -> str:
    """Bound ``s`` to ``max_len`` characters without leaving a secret match that the cut created.

    A cut can *create* a match (a long run of token characters gains the word boundary a
    pattern needs) or cut through a redaction marker so that it is re-matched and expanded.
    The candidate is therefore re-redacted; if that no longer fits, the text is cut again
    *before* the offending match. The result ``r`` satisfies ``redact_text(r) == r`` and
    ``len(r) <= max_len``, which is what keeps ``sanitize_text`` idempotent.
    """
    cut = max_len - 1
    for _ in range(_MAX_SANITIZE_PASSES):
        candidate = s[:cut] + "…"
        if not redact:
            return candidate
        redacted = redact_text(candidate)
        if redacted == candidate:
            return candidate
        if len(redacted) <= max_len:
            return redacted
        cut = max(0, min(_first_match_start(candidate), cut - 1))
    return "…"


def sanitize_evidence(
    value: Any,
    *,
    max_str: int = 300,
    max_items: int = 25,
    max_keys: int = 50,
    max_depth: int = 5,
    _depth: int = 0,
) -> Any:
    """Make an evidence structure JSON-safe, bounded, secret-free and control-char-free."""
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return sanitize_text(value, max_len=max_str)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<{len(value)} bytes>"
    if _depth >= max_depth:
        return "<max-depth>"
    kw = dict(max_str=max_str, max_items=max_items, max_keys=max_keys, max_depth=max_depth, _depth=_depth + 1)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        items = list(value.items())
        keep = items if len(items) <= max_keys else items[: max_keys - 1]
        for k, v in keep:
            key = sanitize_text(k, max_len=80)
            cleaned = sanitize_evidence(v, **kw)
            if _is_secret_key(key) and _redactable(cleaned):
                # Under a secret-named key only a string that is *exactly* a redaction marker is
                # kept; any other value (a hostile "[REDACTED] <secret>", a list or mapping of
                # secrets, a numeric PIN) is replaced. The check runs on the sanitised value, so a
                # second pass reaches the same result (idempotency).
                out[key] = cleaned if isinstance(cleaned, str) and is_redaction_marker(cleaned) else "[REDACTED]"
            else:
                out[key] = cleaned
        if len(items) > max_keys:
            out["_truncated_keys"] = len(items) - (max_keys - 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        seq = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        if len(seq) <= max_items:
            return [sanitize_evidence(v, **kw) for v in seq]
        out_list = [sanitize_evidence(v, **kw) for v in seq[: max_items - 1]]
        out_list.append(f"<{len(seq) - (max_items - 1)} more>")
        return out_list
    return sanitize_text(str(value), max_len=max_str)


def terminal_safe(value: object, *, max_len: int = 500) -> str:
    """Text safe to print to a terminal: no escape sequences can reach the TTY."""
    return sanitize_text(value, max_len=max_len)


def html_escape(value: object, *, max_len: int = 2000) -> str:
    """Text safe to interpolate into HTML element content or quoted attributes."""
    return html.escape(sanitize_text(value, max_len=max_len), quote=True)


def markdown_escape(value: object, *, max_len: int = 2000) -> str:
    """Text safe to interpolate into Markdown (tables included): no markup, links or HTML."""
    s = html.escape(sanitize_text(value, max_len=max_len), quote=False)
    return _MD_SPECIAL_RE.sub(r"\\\1", s)


def redact_structure(value: Any, _depth: int = 0) -> Any:
    """Redact secrets in an arbitrary nested structure without truncating it (for logs).

    Containers nested deeper than 8 levels are replaced by ``"<max-depth>"`` rather than
    passed through unredacted. Tuple subclasses (e.g. named tuples) and sets become plain
    tuples / lists of redacted items, so a log call can never fail inside this processor.
    """
    if isinstance(value, str):
        return redact_text(value)
    if _depth > 8:
        return "<max-depth>" if isinstance(value, (Mapping, list, tuple, set, frozenset)) else value
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            if _is_secret_key(k) and _redactable(v):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_structure(v, _depth + 1)
        return out
    if type(value) is list:
        return [redact_structure(v, _depth + 1) for v in value]
    if isinstance(value, (list, tuple)):
        return tuple(redact_structure(v, _depth + 1) for v in value)
    if isinstance(value, (set, frozenset)):
        return [redact_structure(v, _depth + 1) for v in sorted(value, key=str)]
    return value


def structlog_redactor(_logger: Any, _method: str, event_dict: dict) -> dict:
    """structlog processor: last line of defence against secrets in log events."""
    return redact_structure(event_dict)
