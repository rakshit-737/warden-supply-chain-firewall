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

Every function here is pure and idempotent: sanitising already-sanitised data is a no-op,
which keeps identifiers derived from sanitised evidence (e.g. finding ids) stable.
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
    ("aws_access_key_id", re.compile(
        r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b"
    )),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,242}\b")),
    ("gitlab_token", re.compile(r"\bgl(?:pat|dt|rt|cbt|ptt|ft|imt)-[A-Za-z0-9_\-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]{20,}")),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("pypi_token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}")),
    ("openai_api_key", re.compile(
        r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"
    )),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("url_credentials", re.compile(
        r"(?P<prefix>\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@\[\]]{1,128}:)"
        r"(?P<secret>[^\s/@\[\]]{1,256})(?P<suffix>@)"
    )),
    ("bearer_token", re.compile(
        r"(?i)(?P<prefix>\bauthorization[\"']?\s*[:=]\s*[\"']?bearer\s+)(?P<secret>[A-Za-z0-9._~+/\-]{16,}=*)"
    )),
)

# Keys whose *values* are always treated as secret, whatever they look like.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential)"
)
# Keys that match the sensitive pattern above but only ever hold safe metadata.
_SAFE_KEYS = frozenset({
    "token_type", "secret_type", "detector", "fingerprint", "secret_detector", "credential_type",
    "sensitive", "sensitive_env", "sensitive_paths", "expires_in",
})

# C0 controls (except TAB/LF), DEL, C1 controls, zero-width chars, line/paragraph separators,
# bidirectional embeddings/overrides/isolates, and BOM.
_CONTROL_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]"
)
_MD_SPECIAL_RE = re.compile(r"([\\`*_{}\[\]()#+!|~])")


def _escape_char(match: re.Match[str]) -> str:
    code = ord(match.group(0))
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def _mask(match: re.Match[str], detector: str) -> str:
    groups = match.groupdict()
    if groups.get("secret") is not None:
        return f"{groups.get('prefix') or ''}[REDACTED]{groups.get('suffix') or ''}"
    if detector == "private_key":
        return "-----BEGIN PRIVATE KEY-----[REDACTED]"
    return f"{match.group(0)[:4]}…[REDACTED:{detector}]"


def redact_text(text: str) -> str:
    """Replace every high-confidence secret in ``text`` with a non-reversible marker."""
    if not text:
        return text
    out = text
    for detector, pattern in SECRET_PATTERNS:
        out = pattern.sub(lambda m, d=detector: _mask(m, d), out)
    return out


def find_secrets(text: str) -> list[tuple[str, int, int, str]]:
    """Return ``(detector, start, end, value)`` for each high-confidence secret match.

    The raw ``value`` is returned so a detector can compute a fingerprint or line number;
    callers must never persist, log or return it — use :func:`redact_value` instead.
    """
    hits: list[tuple[str, int, int, str]] = []
    for detector, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if m.groupdict().get("secret") is not None:
                hits.append((detector, m.start("secret"), m.end("secret"), m.group("secret")))
            else:
                hits.append((detector, m.start(), m.end(), m.group(0)))
    return hits


def redact_value(value: str, detector: str = "secret") -> str:
    """A display-safe stand-in for a secret value: type prefix + length, never the secret."""
    if detector == "private_key":
        return "-----BEGIN PRIVATE KEY-----[REDACTED]"
    prefix = value[:4] if len(value) >= 16 else ""
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
        s = s[: max_len - 1] + "…"
    return s


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
            if _SENSITIVE_KEY_RE.search(key) and key not in _SAFE_KEYS and isinstance(v, str) and v:
                out[key] = v if v.startswith("[REDACTED") or "…[REDACTED" in v else "[REDACTED]"
            else:
                out[key] = sanitize_evidence(v, **kw)
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
    """Redact secrets in an arbitrary nested structure without truncating it (for logs)."""
    if _depth > 8:
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SENSITIVE_KEY_RE.search(k) and k not in _SAFE_KEYS and isinstance(v, str) and v:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_structure(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return type(value)(redact_structure(v, _depth + 1) for v in value)
    return value


def structlog_redactor(_logger: Any, _method: str, event_dict: dict) -> dict:
    """structlog processor: last line of defence against secrets in log events."""
    return redact_structure(event_dict)
