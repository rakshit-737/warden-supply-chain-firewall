"""Safe, bounded payload decoding and constant folding for obfuscation analysis.

This module is designed to let the obfuscation analyzer see *what* an embedded blob is
without ever running it. It provides two tools:

* :func:`decode_layers` peels up to ``max_depth`` layers of encoding — base64 (standard and
  URL-safe, with padding repair), base32, base16/hex, escaped hex (``\\x41\\x42``), ascii85 /
  base85, zlib / gzip / bz2 / xz / lzma, rot13 and reversed text — and classifies what the
  last layer produced: Python source with execution or network indicators, shell commands,
  PE / ELF / Mach-O executables (magic bytes), marshalled code objects and pickle streams
  (recognised from header and opcode bytes only), URLs and IPs, another encoded or compressed
  layer, common benign formats (images, fonts, DER, JSON, text) or opaque data.
* :func:`fold` / :func:`constant_fold` statically evaluate string constructions built only
  from constants: concatenation, small repetition, f-strings of constants, ``chr(int)``,
  ``bytes([ints]).decode()``, ``''.join([...])`` (including ``map(chr, ...)`` and simple
  comprehensions), slicing and ``[::-1]`` reversal, ``str.translate`` with a constant
  ``maketrans`` table, ``replace``, rot13 via ``codecs`` and a few explicit decoders.

Safety properties (all input is hostile):

* Nothing is executed or deserialised: there is no ``exec`` / ``eval`` / ``compile`` of
  content and no ``pickle`` / ``marshal`` loading. Decoded Python is only given to
  ``ast.parse`` (which builds a tree and runs nothing); JSON is parsed with ``json.loads``.
* Every decompressor is incremental with ``max_length``, so a decompression bomb stops at
  ``max_output`` bytes; lzma additionally runs with a memory limit.
* Work is bounded by depth, output size, input size, a fixed candidate list per layer and an
  optional ``time.monotonic()`` deadline. Folding is bounded by result length, a step budget
  and a nesting limit, and returns ``None`` whenever it is unsure.
* Results are deterministic for identical input unless the deadline fires, which is reported
  as ``DecodeResult.stopped == "deadline"``.

Layer selection is greedy. Speculative transforms (rot13, reversal, unframed ascii85/base85)
are accepted only when they lead — directly or after one decoding step — to something
meaningful (code, an executable, a URL or a compressed stream). That keeps ordinary data from
being "decoded" into noise, at the cost of not recognising custom alphabets, XOR with a key or
encryption, which this module does not attempt.
"""

from __future__ import annotations

import ast
import base64
import binascii
import bz2
import codecs
import ipaddress
import json
import lzma
import re
import time
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import cached_property
from typing import Any

from app.core.redaction import sanitize_text

KiB = 1024
MiB = 1024 * KiB

DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_OUTPUT = 2 * MiB
MAX_EXTRACTED_URLS = 10
PREVIEW_CHARS = 80
# Enough for xz/lzma streams made with the largest standard preset (64 MiB dictionary); a hostile header
# declaring a larger dictionary is rejected instead of allocated.
LZMA_MEMLIMIT = 96 * MiB

_CHUNK = 256 * KiB
_MIN_LAYER_CHARS = 8
_MIN_ENCODED_CHARS = 16
_SLOW_CODEC_MAX_INPUT = 1 * MiB  # ascii85/base85 decoders are pure Python
_SPECULATIVE_MAX_INPUT = 1 * MiB
_LOOKAHEAD_OUTPUT = 64 * KiB
_PARSE_MAX_CHARS = 512 * KiB
_TEXT_SAMPLE = 64 * KiB
_URL_SCAN_CHARS = 1 * MiB
_SHELL_SCAN_CHARS = 64 * KiB
_URL_DOMINATED_MAX_CHARS = 4096
_CORRUPT_STREAM_MIN_OUTPUT = 4 * KiB


class Kind:
    """What a decoded layer contains."""

    PYTHON = "python_source"
    SHELL = "shell_command"
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    MARSHAL = "marshal_code"
    PICKLE = "pickle"
    URL = "url"
    ENCODED = "encoded"
    COMPRESSED = "compressed"
    ARCHIVE = "archive"
    MEDIA = "media"
    DER = "asn1_der"
    JSON = "json"
    TEXT = "text"
    DATA = "data"
    EMPTY = "empty"


EXECUTABLE_KINDS = frozenset({Kind.PE, Kind.ELF, Kind.MACHO})
BINARY_CODE_KINDS = EXECUTABLE_KINDS | {Kind.MARSHAL, Kind.PICKLE}
SOURCE_CODE_KINDS = frozenset({Kind.PYTHON, Kind.SHELL})
CODE_KINDS = SOURCE_CODE_KINDS | BINARY_CODE_KINDS
# Formats that fully explain an encoded blob as ordinary data (icons, fonts, certificates, JSON, prose).
BENIGN_KINDS = frozenset({Kind.MEDIA, Kind.DER, Kind.JSON, Kind.TEXT})
TEXT_KINDS = frozenset({Kind.PYTHON, Kind.SHELL, Kind.URL, Kind.ENCODED, Kind.JSON, Kind.TEXT})
COMPRESSION_ENCODINGS = frozenset({"zlib", "gzip", "bz2", "xz", "lzma"})
TEXT_ENCODINGS = frozenset({"base64", "base64url", "base32", "hex", "escaped_hex", "ascii85", "base85"})
SPECULATIVE_ENCODINGS = frozenset({"rot13", "reversed"})


def _expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


# =========================================================================== results
@dataclass(frozen=True)
class Classification:
    kind: str
    format: str | None = None
    indicators: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "format": self.format,
            "indicators": list(self.indicators),
            "urls": list(self.urls),
            "ips": list(self.ips),
        }


@dataclass(frozen=True)
class Layer:
    encoding: str
    input_size: int
    output_size: int
    # "max_output" (output cut at the cap), "corrupt" (stream ended in an error) or None.
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"encoding": self.encoding, "input_size": self.input_size, "output_size": self.output_size,
                "note": self.note}


@dataclass(frozen=True)
class DecodeResult:
    layers: tuple[Layer, ...]
    output: bytes
    classification: Classification
    truncated: bool
    # Why decoding stopped early: "max_depth", "max_output", "deadline", "decode_failed" or None.
    stopped: str | None
    bytes_produced: int

    @property
    def depth(self) -> int:
        return len(self.layers)

    @property
    def kind(self) -> str:
        return self.classification.kind

    @property
    def encodings(self) -> tuple[str, ...]:
        return tuple(layer.encoding for layer in self.layers)

    @property
    def compressed(self) -> bool:
        return any(layer.encoding in COMPRESSION_ENCODINGS for layer in self.layers)

    def preview(self, max_chars: int = PREVIEW_CHARS) -> str:
        return preview(self.output, self.classification, max_chars)

    def to_evidence(self) -> dict[str, Any]:
        """Small, display-safe summary: never the decoded payload itself."""
        c = self.classification
        return {
            "layers": list(self.encodings),
            "kind": c.kind,
            "format": c.format,
            "decoded_size": len(self.output),
            "decoded_preview": self.preview(),
            "indicators": list(c.indicators[:10]),
            "urls": list(c.urls[:MAX_EXTRACTED_URLS]),
            "ips": list(c.ips[:MAX_EXTRACTED_URLS]),
            "truncated": self.truncated,
            "stopped": self.stopped,
        }


def preview(data: bytes, classification: Classification | None = None, max_chars: int = PREVIEW_CHARS) -> str:
    """At most ``max_chars`` sanitised characters of text, or a short hex prefix of binary data."""
    if not data:
        return ""
    kind = classification.kind if classification else None
    if kind in TEXT_KINDS:
        text = data[: max_chars * 4].decode("utf-8", "replace")[:max_chars]
        return sanitize_text(text, max_len=max_chars)
    return "hex:" + data[:16].hex()


# =========================================================================== classification
_MACHO_MAGICS = frozenset({b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"})
_DOS_STUB = b"This program cannot be run in DOS mode"
_DANGEROUS_MODULES = frozenset({
    "os", "posix", "nt", "subprocess", "builtins", "__builtin__", "socket", "sys", "shutil", "pty",
    "importlib", "runpy", "marshal", "pickle", "codecs", "ctypes", "webbrowser",
})
_PICKLE_GLOBAL_RE = re.compile(rb"c([A-Za-z_][\w.]{0,80})\n([A-Za-z_]\w{0,80})\n")
_PICKLE_NAME_RE = re.compile(rb"[A-Za-z_][\w.]{0,80}")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f�]")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s'\"<>`\\{}|^]{1,512}")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SHELL_RE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:ba|z|da)?sh\b"
    r"|\bpowershell(?:\.exe)?\b[^\n]{0,60}\s-(?:e|enc|encodedcommand)\b"
    r"|\b(?:bash|sh)\s+-c\s"
    r"|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s"
    r"|/dev/tcp/"
    r"|\bchmod\s+\+x\s"
    r"|\bcmd(?:\.exe)?\s+/c\s"
)
_PY_TOKEN_RE = re.compile(r"\b(?:import|exec|eval|compile|__import__|socket|subprocess|urllib|os)\b")
_PY_CALL_INDICATORS = frozenset({"exec", "eval", "compile", "__import__"})
_PY_ROOT_INDICATORS = frozenset({
    "os", "socket", "subprocess", "urllib", "urllib2", "urllib3", "requests", "http", "ctypes", "pty",
    "marshal", "base64", "zlib", "builtins", "shutil", "webbrowser",
})
_HEX_RE = re.compile(rb"[0-9a-fA-F]+")
_ESC_HEX_RE = re.compile(rb"(?:\\x[0-9a-fA-F]{2})+")
_B32_RE = re.compile(rb"[A-Z2-7]+=*")
_B64_RE = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
_B64URL_RE = re.compile(rb"[A-Za-z0-9_\-]+={0,2}")
_A85_RE = re.compile(rb"[!-uz]+")
_B85_RE = re.compile(rb"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+")
_LINE_BREAK_RE = re.compile(rb"[ \t]*[\r\n]+[ \t]*")


def compact(data: bytes) -> bytes:
    """Remove line breaks (and indentation around them) the way wrapped blobs are written in source."""
    return _LINE_BREAK_RE.sub(b"", data).strip()


def _is_pe(data: bytes) -> bool:
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    if 0x40 <= offset <= len(data) - 4 and data[offset:offset + 4] == b"PE\x00\x00":
        return True
    return _DOS_STUB in data[:512]


def _is_marshal_code(data: bytes) -> bool:
    """Header of a marshalled code object (TYPE_CODE, optionally FLAG_REF). Never loaded."""
    if len(data) < 26 or data[0] not in (0x63, 0xE3):
        return False
    if any(int.from_bytes(data[i:i + 4], "little") > 255 for i in (1, 5, 9)):
        return False
    # co_code follows the fixed int32 fields (5 of them on 3.11+, 6 before) as a bytes object.
    return data[21] in (0x73, 0xF3) or data[25] in (0x73, 0xF3)


def _pickle_indicators(data: bytes) -> tuple[str, ...] | None:
    """Recognise a pickle stream from its protocol header / GLOBAL opcodes. Never loaded."""
    if not data.endswith(b"."):
        return None
    head = data[: 64 * KiB]
    binary = len(data) >= 3 and data[0] == 0x80 and 2 <= data[1] <= 5
    globals_found = [(m.group(1), m.group(2)) for m in _PICKLE_GLOBAL_RE.finditer(head)][:32]
    if not binary and not (data[:1] in (b"c", b"(", b"]", b"}") and globals_found):
        return None
    refs: list[str] = []
    for module, name in globals_found:
        refs.append(f"global:{module.decode('ascii')}.{name.decode('ascii')}")
    if binary:
        strings: list[str] = []
        pos = 0
        while len(strings) < 64:
            pos = head.find(b"\x8c", pos)
            if pos < 0 or pos + 2 > len(head):
                break
            size = head[pos + 1]
            value = head[pos + 2:pos + 2 + size]
            if size and len(value) == size and _PICKLE_NAME_RE.fullmatch(value):
                strings.append(value.decode("ascii"))
            pos += 1
        if b"\x93" in head:  # STACK_GLOBAL: module and name are pushed as consecutive strings
            refs.extend(f"global:{m}.{n}" for m, n in zip(strings, strings[1:]) if m in _DANGEROUS_MODULES)
    dangerous = [r for r in refs if r.split(":", 1)[1].split(".", 1)[0] in _DANGEROUS_MODULES]
    return tuple(dict.fromkeys(dangerous or refs))[:10]


def compression_format(data: bytes) -> str | None:
    """Compression container recognised from its header, or ``None``."""
    if data[:3] == b"\x1f\x8b\x08":
        return "gzip"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(data) >= 4 and data[:3] == b"BZh" and 0x31 <= data[3] <= 0x39:
        return "bz2"
    if len(data) >= 2:
        cmf, flg = data[0], data[1]
        if cmf & 0x0F == 8 and cmf >> 4 <= 7 and ((cmf << 8) | flg) % 31 == 0 and not flg & 0x20:
            return "zlib"
    if len(data) >= 13 and data[0] == 0x5D:
        dict_size = int.from_bytes(data[1:5], "little")
        base = dict_size // 3 if dict_size % 3 == 0 else dict_size
        if 4096 <= dict_size <= 1 << 30 and base & (base - 1) == 0:
            return "lzma"
    return None


def _media_format(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if len(data) >= 22 and data[:4] == b"\x00\x00\x01\x00":
        count = int.from_bytes(data[4:6], "little")
        if 1 <= count <= 256 and 6 + 16 * count <= len(data):
            return "ico"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] in (b"wOFF", b"wOF2"):
        return "woff"
    if data[:4] == b"OTTO":
        return "otf"
    if len(data) >= 12 and data[:4] == b"\x00\x01\x00\x00" and 1 <= int.from_bytes(data[4:6], "big") <= 64:
        return "ttf"
    if data[:5] == b"%PDF-":
        return "pdf"
    return None


def _is_der(data: bytes) -> bool:
    """A single DER SEQUENCE whose length field matches the data exactly (certificates, keys)."""
    if len(data) < 64 or data[0] != 0x30:
        return False
    if data[1] == 0x81:
        return data[2] + 3 == len(data)
    if data[1] == 0x82:
        return int.from_bytes(data[2:4], "big") + 4 == len(data)
    if data[1] == 0x83:
        return int.from_bytes(data[2:5], "big") + 5 == len(data)
    return False


def _signature(data: bytes) -> Classification | None:
    """Classification from magic bytes / binary structure alone."""
    if data[:4] == b"\x7fELF":
        return Classification(Kind.ELF, "elf")
    if _is_pe(data):
        return Classification(Kind.PE, "pe")
    if data[:4] in _MACHO_MAGICS:
        return Classification(Kind.MACHO, "macho")
    if len(data) >= 8 and data[:4] == b"\xca\xfe\xba\xbe" and 0 < int.from_bytes(data[4:8], "big") < 20:
        return Classification(Kind.MACHO, "macho-fat")
    if len(data) >= 42 and data[2:4] == b"\r\n" and _is_marshal_code(data[16:]):
        return Classification(Kind.MARSHAL, "pyc")
    if _is_marshal_code(data):
        return Classification(Kind.MARSHAL, "marshal")
    pickle_refs = _pickle_indicators(data)
    if pickle_refs is not None:
        return Classification(Kind.PICKLE, "pickle", pickle_refs)
    fmt = compression_format(data)
    if fmt:
        return Classification(Kind.COMPRESSED, fmt)
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return Classification(Kind.ARCHIVE, "zip")
    media = _media_format(data)
    if media:
        return Classification(Kind.MEDIA, media)
    if _is_der(data):
        return Classification(Kind.DER, "der")
    return None


def _text_sample(data: bytes) -> str | None:
    """The leading sample decoded as UTF-8 when it looks like text, else ``None``."""
    sample = data[:_TEXT_SAMPLE]
    try:
        text = codecs.getincrementaldecoder("utf-8")().decode(sample, final=len(data) <= _TEXT_SAMPLE)
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    if len(_CONTROL_RE.findall(text)) > 0.05 * len(text):
        return None
    return text


def extract_network_indicators(text: str, limit: int = MAX_EXTRACTED_URLS) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Up to ``limit`` distinct URLs and IPv4 addresses, in order of appearance."""
    scan = text[:_URL_SCAN_CHARS]
    urls: list[str] = []
    for m in _URL_RE.finditer(scan):
        url = m.group(0).rstrip(".,;:)]'\"")
        if url not in urls:
            urls.append(url)
            if len(urls) >= limit:
                break
    ips: list[str] = []
    for m in _IPV4_RE.finditer(scan):
        try:
            ip = str(ipaddress.IPv4Address(m.group(0)))
        except ValueError:
            continue
        if ip not in ips:
            ips.append(ip)
            if len(ips) >= limit:
                break
    return tuple(urls), tuple(ips)


def _call_root(func: ast.expr) -> str | None:
    node = func
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def python_indicators(text: str) -> tuple[str, ...]:
    """Execution / network indicators of Python source (empty when it does not parse or has none).

    Indicators are imports, calls to ``exec``/``eval``/``compile``/``__import__`` and calls rooted
    at modules such as ``os``, ``socket`` or ``subprocess``. Source is parsed, never compiled or run.
    """
    if len(text) < 6 or not _PY_TOKEN_RE.search(text, 0, _PARSE_MAX_CHARS):
        return ()
    if len(text) > _PARSE_MAX_CHARS:
        head = text[:_PARSE_MAX_CHARS]
        if re.search(r"(?m)^[ \t]*(?:import[ \t]+[A-Za-z_]|from[ \t]+[\w.]+[ \t]+import[ \t])", head):
            return ("unparsed_large_source",)
        return ()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return ()
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update("import:" + alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add("import:" + node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _PY_CALL_INDICATORS:
                found.add("call:" + func.id)
            elif isinstance(func, ast.Attribute):
                root = _call_root(func)
                if root in _PY_ROOT_INDICATORS:
                    found.add(f"call:{root}.{func.attr}")
        if len(found) >= 16:
            break
    return tuple(sorted(found))


def _is_json(stripped: str) -> bool:
    if stripped[:1] not in ("{", "["):
        return False
    try:
        return isinstance(json.loads(stripped), (dict, list))
    except (ValueError, RecursionError, MemoryError):
        return False


def _url_dominated(stripped: str, urls: tuple[str, ...], ips: tuple[str, ...]) -> bool:
    if not (urls or ips) or len(stripped) > _URL_DOMINATED_MAX_CHARS:
        return False
    covered = sum(len(u) for u in urls) + sum(len(i) for i in ips)
    dense = len(re.sub(r"\s", "", stripped))
    return covered * 2 >= dense


def encoded_format(data: bytes) -> str | None:
    """Encoding alphabet a (compacted) text blob fully matches, or ``None``."""
    blob = compact(data)
    if len(blob) < _MIN_ENCODED_CHARS:
        return None
    if _ESC_HEX_RE.fullmatch(blob):
        return "escaped_hex"
    if len(blob) % 2 == 0 and _HEX_RE.fullmatch(blob):
        return "hex"
    if _B32_RE.fullmatch(blob):
        return "base32"
    if _B64_RE.fullmatch(blob):
        return "base64"
    if _B64URL_RE.fullmatch(blob):
        return "base64url"
    if blob.startswith(b"<~") and blob.endswith(b"~>"):
        return "ascii85"
    return None


def classify(data: bytes) -> Classification:
    """Classify decoded bytes without executing or deserialising them."""
    if not data:
        return Classification(Kind.EMPTY)
    sig = _signature(data)
    if sig is not None:
        return sig
    if _text_sample(data) is None:
        return Classification(Kind.DATA)
    text = data.decode("utf-8", "replace")
    urls, ips = extract_network_indicators(text)
    stripped = text.strip()
    if _is_json(stripped):
        return Classification(Kind.JSON, "json", (), urls, ips)
    indicators = python_indicators(text)
    if indicators:
        return Classification(Kind.PYTHON, "python", indicators, urls, ips)
    if _SHELL_RE.search(text, 0, _SHELL_SCAN_CHARS):
        return Classification(Kind.SHELL, "shell", ("shell_command",), urls, ips)
    if _url_dominated(stripped, urls, ips):
        return Classification(Kind.URL, None, (), urls, ips)
    fmt = encoded_format(data)
    if fmt:
        return Classification(Kind.ENCODED, fmt, (), urls, ips)
    return Classification(Kind.TEXT, "text", (), urls, ips)


def _score(data: bytes) -> int:
    """Cheap plausibility score used to choose between candidate decodings (no parsing)."""
    if not data:
        return 0
    if _signature(data) is not None:
        return 6
    sample = _text_sample(data)
    if sample is None:
        return 1
    if _PY_TOKEN_RE.search(sample) or _SHELL_RE.search(sample) or _URL_RE.search(sample):
        return 5
    if encoded_format(data[:_TEXT_SAMPLE] if len(data) > _TEXT_SAMPLE else data):
        return 4
    return 3


# =========================================================================== decoders
# Each decoder returns ``(output, note)`` or ``None`` when the input is not in its format.
Decoded = tuple[bytes, "str | None"]


def _cap(output: bytes, note: str | None, max_output: int) -> Decoded:
    if len(output) > max_output:
        return output[:max_output], "max_output"
    return output, note


def _dec_base64(blob: bytes, max_output: int, *, urlsafe: bool = False) -> Decoded | None:
    regex = _B64URL_RE if urlsafe else _B64_RE
    if len(blob) < _MIN_LAYER_CHARS or not regex.fullmatch(blob):
        return None
    if urlsafe and b"-" not in blob and b"_" not in blob:
        return None  # plain alphabet: handled by the standard decoder
    body, note = blob.rstrip(b"="), None
    limit = (max_output // 3) * 4
    if len(body) > limit:
        body, note = body[:limit], "max_output"
    if len(body) % 4 == 1:
        body = body[:-1]  # a dangling sextet carries no complete byte: padding repair drops it
    body += b"=" * (-len(body) % 4)
    try:
        out = base64.b64decode(body, altchars=b"-_" if urlsafe else None, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _cap(out, note, max_output) if out else None


def _dec_base32(blob: bytes, max_output: int) -> Decoded | None:
    if len(blob) < _MIN_ENCODED_CHARS or not _B32_RE.fullmatch(blob):
        return None
    body, note = blob.rstrip(b"="), None
    limit = (max_output // 5) * 8
    if len(body) > limit:
        body, note = body[:limit], "max_output"
    valid = {0: 0, 1: 0, 2: 2, 3: 2, 4: 4, 5: 5, 6: 5, 7: 7}
    rem = len(body) % 8
    body = body[: len(body) - rem + valid[rem]]
    body += b"=" * (-len(body) % 8)
    try:
        out = base64.b32decode(body)
    except (binascii.Error, ValueError):
        return None
    return _cap(out, note, max_output) if out else None


def _dec_hex(blob: bytes, max_output: int) -> Decoded | None:
    if len(blob) < _MIN_LAYER_CHARS or len(blob) % 2 or not _HEX_RE.fullmatch(blob):
        return None
    note = None
    if len(blob) > max_output * 2:
        blob, note = blob[: max_output * 2], "max_output"
    return binascii.unhexlify(blob), note


def _dec_escaped_hex(blob: bytes, max_output: int) -> Decoded | None:
    if len(blob) < _MIN_LAYER_CHARS or not _ESC_HEX_RE.fullmatch(blob):
        return None
    note = None
    if len(blob) > max_output * 4:
        blob, note = blob[: max_output * 4], "max_output"
    return binascii.unhexlify(blob.replace(b"\\x", b"")), note


def _dec_ascii85(blob: bytes, max_output: int, *, framed: bool = True) -> Decoded | None:
    if len(blob) > _SLOW_CODEC_MAX_INPUT:
        return None
    if framed:
        if not (blob.startswith(b"<~") and blob.endswith(b"~>")):
            return None
    elif len(blob) < 20 or not _A85_RE.fullmatch(blob) or _B64URL_RE.fullmatch(blob) or _B64_RE.fullmatch(blob):
        return None
    try:
        out = base64.a85decode(blob, adobe=framed)
    except (ValueError, binascii.Error):
        return None
    return _cap(out, None, max_output) if out else None


def _dec_base85(blob: bytes, max_output: int) -> Decoded | None:
    if (len(blob) < 20 or len(blob) > _SLOW_CODEC_MAX_INPUT or not _B85_RE.fullmatch(blob)
            or _B64URL_RE.fullmatch(blob) or _B64_RE.fullmatch(blob)):
        return None
    try:
        out = base64.b85decode(blob)
    except (ValueError, binascii.Error):
        return None
    return _cap(out, None, max_output) if out else None


def _inflate(data: bytes, wbits: int, max_output: int, deadline: float | None) -> Decoded | None:
    """zlib/gzip stream, decompressed incrementally with ``max_length`` (bomb-safe)."""
    decompressor = zlib.decompressobj(wbits)
    out = bytearray()
    pending = data
    while True:
        if _expired(deadline):
            return bytes(out), "deadline"
        room = max_output - len(out)
        if room <= 0:
            return bytes(out), None if decompressor.eof else "max_output"
        try:
            chunk = decompressor.decompress(pending, min(room, _CHUNK))
        except zlib.error:
            return (bytes(out), "corrupt") if len(out) >= _CORRUPT_STREAM_MIN_OUTPUT else None
        out += chunk
        pending = decompressor.unconsumed_tail
        if decompressor.eof or (not chunk and not pending):
            break
    return (bytes(out), None) if out else None


def _drain(decompressor: Any, data: bytes, max_output: int, deadline: float | None) -> Decoded | None:
    """bz2/lzma stream, decompressed incrementally with ``max_length`` (bomb-safe)."""
    out = bytearray()
    pending = data
    while True:
        if _expired(deadline):
            return bytes(out), "deadline"
        room = max_output - len(out)
        if room <= 0:
            return bytes(out), None if decompressor.eof else "max_output"
        try:
            chunk = decompressor.decompress(pending, min(room, _CHUNK))
        except (OSError, EOFError, ValueError, lzma.LZMAError, MemoryError):
            return (bytes(out), "corrupt") if len(out) >= _CORRUPT_STREAM_MIN_OUTPUT else None
        pending = b""
        out += chunk
        if decompressor.eof or decompressor.needs_input or not chunk:
            break
    return (bytes(out), None) if out else None


def decompress(fmt: str, data: bytes, max_output: int = DEFAULT_MAX_OUTPUT,
               deadline: float | None = None) -> Decoded | None:
    """Bounded decompression of one container format (``zlib``, ``gzip``, ``bz2``, ``xz``, ``lzma``)."""
    try:
        if fmt == "zlib":
            return _inflate(data, zlib.MAX_WBITS, max_output, deadline)
        if fmt == "gzip":
            return _inflate(data, zlib.MAX_WBITS | 16, max_output, deadline)
        if fmt == "bz2":
            return _drain(bz2.BZ2Decompressor(), data, max_output, deadline)
        if fmt == "xz":
            return _drain(lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=LZMA_MEMLIMIT), data, max_output,
                          deadline)
        if fmt == "lzma":
            return _drain(lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=LZMA_MEMLIMIT), data,
                          max_output, deadline)
    except (zlib.error, lzma.LZMAError, OSError, ValueError, MemoryError):
        return None
    return None


_STRICT_DECODERS: tuple[tuple[str, Callable[[bytes, int], Decoded | None]], ...] = (
    ("escaped_hex", _dec_escaped_hex),
    ("hex", _dec_hex),
    ("base32", _dec_base32),
    ("base64", _dec_base64),
    ("base64url", lambda b, m: _dec_base64(b, m, urlsafe=True)),
    ("ascii85", _dec_ascii85),
)


def _text_of(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _speculative(name: str, data: bytes, blob: bytes, max_output: int) -> Decoded | None:
    if name in ("rot13", "reversed"):
        text = _text_of(data)
        if text is None or not text.strip():
            return None
        if name == "rot13":
            if not re.search(r"[A-Za-z]", text):
                return None
            out = codecs.encode(text, "rot13").encode("utf-8")
        else:
            out = text[::-1].encode("utf-8")
        return None if out == data else _cap(out, None, max_output)
    if name == "ascii85":
        return _dec_ascii85(blob, max_output, framed=False)
    if name == "base85":
        return _dec_base85(blob, max_output)
    return None


_SPECULATIVE_ORDER = ("rot13", "reversed", "ascii85", "base85")


def _strict_candidates(data: bytes, max_output: int, deadline: float | None) -> list[tuple[str, bytes, str | None]]:
    blob = compact(data)
    found: list[tuple[str, bytes, str | None]] = []
    for name, decoder in _STRICT_DECODERS:
        if _expired(deadline):
            break
        result = decoder(blob, max_output)
        if result is not None and result[0]:
            found.append((name, result[0], result[1]))
    return found


def _lookahead_score(data: bytes) -> int:
    fmt = compression_format(data)
    if fmt:
        return 6
    best = 0
    for _, out, _note in _strict_candidates(data, _LOOKAHEAD_OUTPUT, None):
        best = max(best, _score(out))
    return best


def _next_layer(data: bytes, max_output: int, deadline: float | None,
                previous: str | None) -> tuple[str, bytes, str | None] | None:
    fmt = compression_format(data)
    if fmt:
        result = decompress(fmt, data, max_output, deadline)
        return (fmt, result[0], result[1]) if result else None
    if _signature(data) is not None or _text_sample(data) is None:
        return None  # an executable, a known format or opaque binary: nothing further to peel
    best: tuple[str, bytes, str | None] | None = None
    best_score = -1
    for name, out, note in _strict_candidates(data, max_output, deadline):
        score = _score(out)
        if score > best_score:
            best, best_score = (name, out, note), score
    if best_score >= 5 or len(data) > _SPECULATIVE_MAX_INPUT:
        return best
    blob = compact(data)
    for name in _SPECULATIVE_ORDER:
        if name == previous or _expired(deadline):
            continue  # rot13 and reversal are their own inverse
        result = _speculative(name, data, blob, max_output)
        if result is None:
            continue
        score = _score(result[0])
        if score == 4:
            score = max(score, _lookahead_score(result[0]))
        if score >= 5 and score > best_score:
            return name, result[0], result[1]
    return best


def _to_bytes(data: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8", "surrogatepass")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"cannot decode {type(data).__name__}")


def decode_layers(
    data: str | bytes,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_output: int = DEFAULT_MAX_OUTPUT,
    deadline: float | None = None,
) -> DecodeResult:
    """Peel up to ``max_depth`` encoding layers from ``data`` and classify the result.

    ``max_output`` bounds every layer's output (and therefore decompression bombs);
    ``deadline`` is an absolute ``time.monotonic()`` value. Never executes or deserialises.
    """
    current = _to_bytes(data)
    max_output = max(1, int(max_output))
    max_depth = max(0, int(max_depth))
    truncated = False
    stopped: str | None = None
    if len(current) > max_output * 4:
        current, truncated = current[: max_output * 4], True
    layers: list[Layer] = []
    produced = 0
    previous: str | None = None
    while True:
        if _expired(deadline):
            stopped = "deadline"
            break
        if len(layers) >= max_depth:
            if compression_format(current) or (_signature(current) is None and encoded_format(current)):
                stopped = "max_depth"
            break
        step = _next_layer(current, max_output, deadline, previous)
        if step is None:
            break
        name, output, note = step
        layers.append(Layer(name, len(current), len(output), note))
        produced += len(output)
        current, previous = output, name
        if note == "deadline":
            stopped = "deadline"
            break
        if note == "max_output":
            truncated, stopped = True, "max_output"
        elif note == "corrupt":
            truncated = True
    return DecodeResult(tuple(layers), current, classify(current), truncated, stopped, produced)


def apply_layer(encoding: str, data: str | bytes, *, max_output: int = DEFAULT_MAX_OUTPUT,
                deadline: float | None = None) -> Decoded | None:
    """Apply one *declared* decoding step (e.g. the ``b64decode`` a loader calls). ``None`` on failure.

    ``marshal`` and ``pickle`` are deliberately unsupported: their payloads are classified, never loaded.
    """
    raw = _to_bytes(data)
    if encoding in COMPRESSION_ENCODINGS:
        fmt = compression_format(raw) if encoding in ("xz", "lzma") else encoding
        return decompress(fmt or encoding, raw, max_output, deadline)
    blob = compact(raw)
    if encoding in ("base64", "base64url"):
        cleaned = re.sub(rb"[^A-Za-z0-9+/=\-_]", b"", blob)
        urlsafe = encoding == "base64url" or (b"-" in cleaned or b"_" in cleaned)
        return _dec_base64(cleaned, max_output, urlsafe=urlsafe) or _dec_base64(cleaned, max_output)
    if encoding == "base32":
        return _dec_base32(blob.upper(), max_output)
    if encoding == "hex":
        return _dec_hex(re.sub(rb"\s", b"", blob), max_output) or _dec_escaped_hex(blob, max_output)
    if encoding == "escaped_hex":
        return _dec_escaped_hex(blob, max_output)
    if encoding == "ascii85":
        return _dec_ascii85(blob, max_output) or _dec_ascii85(blob, max_output, framed=False)
    if encoding == "base85":
        return _dec_base85(blob, max_output)
    if encoding in SPECULATIVE_ENCODINGS:
        return _speculative(encoding, raw, blob, max_output)
    return None


def decode_chain(
    data: str | bytes,
    encodings: tuple[str, ...] | list[str],
    *,
    max_output: int = DEFAULT_MAX_OUTPUT,
    deadline: float | None = None,
) -> DecodeResult:
    """Apply declared decoding steps in order (innermost first) and classify the result."""
    current = _to_bytes(data)
    layers: list[Layer] = []
    produced = 0
    truncated = False
    stopped: str | None = None
    for encoding in list(encodings)[:16]:
        if _expired(deadline):
            stopped = "deadline"
            break
        result = apply_layer(encoding, current, max_output=max_output, deadline=deadline)
        if result is None:
            stopped = "decode_failed"
            break
        output, note = result
        layers.append(Layer(encoding, len(current), len(output), note))
        produced += len(output)
        current = output
        if note in ("max_output", "corrupt", "deadline"):
            truncated = True
            stopped = stopped or (note if note != "corrupt" else None)
    return DecodeResult(tuple(layers), current, classify(current), truncated, stopped, produced)


# =========================================================================== constant folding
MAX_FOLD_LEN = 1 * MiB
MAX_FOLD_STEPS = 50_000
MAX_FOLD_DEPTH = 48
MAX_FOLD_SEQUENCE = 65_536
MAX_FOLD_INT = 1 << 32
_MAX_LEAVES = 4096
_SAFE_TEXT_CODECS = frozenset({"utf-8", "utf8", "utf_8", "ascii", "us-ascii", "latin-1", "latin1", "iso-8859-1"})
_ROT13_CODECS = frozenset({"rot13", "rot_13"})
_SAFE_ERRORS = frozenset({"strict", "ignore", "replace"})
_CASE_METHODS = frozenset({"lower", "upper", "strip", "lstrip", "rstrip", "swapcase", "casefold", "title"})
_DECODER_FUNCS = {
    "base64.b64decode": "base64", "base64.standard_b64decode": "base64", "base64.urlsafe_b64decode": "base64url",
    "base64.b32decode": "base32", "base64.b16decode": "hex", "binascii.unhexlify": "hex", "binascii.a2b_hex": "hex",
    "binascii.a2b_base64": "base64", "base64.decodebytes": "base64",
}
_MODULE_CALLS = frozenset({
    "str.maketrans", "bytes.maketrans", "bytearray.maketrans", "bytes.fromhex", "bytearray.fromhex",
    "codecs.decode", "codecs.encode",
})
# Techniques that exist to hide text rather than to lay it out.
OBFUSCATING_TECHNIQUES = frozenset({
    "chr", "bytes", "char_join", "reverse", "slice", "index", "translate", "rot13", "xor", "base64", "hex",
})
_MISSING = object()


class _TransTable(dict):
    """A translation table produced by a folded ``maketrans`` call."""


@dataclass(frozen=True)
class FoldResult:
    value: str | bytes
    techniques: frozenset[str]
    # The str/bytes constants the value was assembled from (bounded; see ``leaves_complete``).
    leaves: tuple[str | bytes, ...]
    leaves_complete: bool

    @property
    def text(self) -> str:
        return self.value if isinstance(self.value, str) else self.value.decode("latin-1")

    @property
    def obfuscating(self) -> bool:
        return bool(self.techniques & OBFUSCATING_TECHNIQUES)

    @cached_property
    def _leaf_text(self) -> str:
        # NUL-separated so a fragment can never match across two pieces (fragments never contain NUL).
        return "\x00".join(leaf if isinstance(leaf, str) else leaf.decode("latin-1") for leaf in self.leaves)

    @cached_property
    def _leaf_text_folded(self) -> str:
        return self._leaf_text.casefold()

    def hides(self, fragment: str, *, casefold: bool = False) -> bool:
        """True when ``fragment`` appears in the folded value but inside none of its constant pieces.

        With ``casefold`` a piece that contains the fragment in another letter case also counts as
        containing it (so ``"EXEC".lower()`` does not "hide" ``exec``). Bytes pieces are compared
        as latin-1 text.
        """
        if not fragment or "\x00" in fragment or not self.leaves_complete or fragment not in self.text:
            return False
        if casefold:
            return fragment.casefold() not in self._leaf_text_folded
        return fragment not in self._leaf_text


class _Unfoldable(Exception):
    pass


class _Folder:
    def __init__(self, names: Any, qualname: Callable[[ast.expr], str | None] | None, max_len: int,
                 max_steps: int, max_depth: int) -> None:
        self.names = names
        self.qualname = qualname
        self.max_len = max_len
        self.max_steps = max_steps
        self.max_depth = max_depth
        self.steps = 0
        self.techniques: set[str] = set()
        self.leaves: list[str | bytes] = []
        self.leaves_complete = True
        self._leaf_ids: set[int] = set()
        self._active: set[str] = set()
        self._bindings: dict[str, Any] = {}

    # ------------------------------------------------------------------ helpers
    def _tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > self.max_steps:
            raise _Unfoldable

    def _len(self, n: int) -> None:
        if n > self.max_len:
            raise _Unfoldable

    def _leaf(self, value: str | bytes) -> None:
        if id(value) in self._leaf_ids:
            return
        if len(self.leaves) >= _MAX_LEAVES:
            self.leaves_complete = False
            return
        self._leaf_ids.add(id(value))
        self.leaves.append(value)

    @staticmethod
    def _int(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or abs(value) > MAX_FOLD_INT:
            raise _Unfoldable
        return value

    def fold(self, node: ast.AST, depth: int = 0) -> Any:
        self._tick()
        if depth > self.max_depth:
            raise _Unfoldable
        handler = getattr(self, "_fold_" + type(node).__name__, None)
        if handler is None:
            raise _Unfoldable
        return handler(node, depth + 1)

    def _args(self, node: ast.Call, depth: int) -> tuple[list[Any], dict[str, Any]]:
        if len(node.args) + len(node.keywords) > 3:
            raise _Unfoldable
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                raise _Unfoldable
            args.append(self.fold(arg, depth))
        kwargs = {}
        for kw in node.keywords:
            if kw.arg is None:
                raise _Unfoldable
            kwargs[kw.arg] = self.fold(kw.value, depth)
        return args, kwargs

    # ------------------------------------------------------------------ nodes
    def _fold_Constant(self, node: ast.Constant, depth: int) -> Any:
        value = node.value
        if isinstance(value, (str, bytes)):
            self._len(len(value))
            self._leaf(value)
            return value
        return self._int(value)

    def _fold_Name(self, node: ast.Name, depth: int) -> Any:
        if node.id in self._bindings:
            return self._bindings[node.id]
        if self.names is None or node.id in self._active:
            raise _Unfoldable
        target = self.names(node.id) if callable(self.names) else self.names.get(node.id)
        if target is None:
            raise _Unfoldable
        self.techniques.add("name")
        if isinstance(target, ast.AST):
            self._active.add(node.id)
            try:
                return self.fold(target, depth)
            finally:
                self._active.discard(node.id)
        if isinstance(target, (str, bytes)):
            self._len(len(target))
            self._leaf(target)
            return target
        return self._int(target)

    def _fold_BinOp(self, node: ast.BinOp, depth: int) -> Any:
        if isinstance(node.op, ast.Add):
            operands: list[ast.expr] = []
            current: ast.expr = node
            while isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
                self._tick()
                operands.append(current.right)
                current = current.left
            operands.append(current)
            return self._add([self.fold(op, depth) for op in reversed(operands)])
        left, right = self.fold(node.left, depth), self.fold(node.right, depth)
        op = node.op
        if isinstance(op, ast.Mult):
            return self._mult(left, right)
        a, b = self._int(left), self._int(right)
        if isinstance(op, ast.Sub):
            result = a - b
        elif isinstance(op, ast.BitXor):
            self.techniques.add("xor")
            result = a ^ b
        elif isinstance(op, ast.BitAnd):
            result = a & b
        elif isinstance(op, ast.BitOr):
            result = a | b
        elif isinstance(op, (ast.Mod, ast.FloorDiv)) and b != 0:
            result = a % b if isinstance(op, ast.Mod) else a // b
        elif isinstance(op, (ast.LShift, ast.RShift)) and 0 <= b <= 32:
            result = a << b if isinstance(op, ast.LShift) else a >> b
        else:
            raise _Unfoldable
        return self._int(result)

    def _add(self, values: list[Any]) -> Any:
        if all(isinstance(v, str) for v in values):
            self._len(sum(len(v) for v in values))
            if len(values) > 1:
                self.techniques.add("concat")
            return "".join(values)
        if all(isinstance(v, bytes) for v in values):
            self._len(sum(len(v) for v in values))
            if len(values) > 1:
                self.techniques.add("concat")
            return b"".join(values)
        if all(isinstance(v, list) for v in values):
            if sum(len(v) for v in values) > MAX_FOLD_SEQUENCE:
                raise _Unfoldable
            return [item for v in values for item in v]
        return self._int(sum(self._int(v) for v in values))

    def _mult(self, left: Any, right: Any) -> Any:
        if isinstance(left, int) and not isinstance(left, bool) and isinstance(right, (str, bytes, list)):
            left, right = right, left
        if isinstance(left, (str, bytes, list)):
            count = max(0, self._int(right))
            size = len(left) * count
            if size > (MAX_FOLD_SEQUENCE if isinstance(left, list) else self.max_len):
                raise _Unfoldable
            self._tick(1 + size // 4096)
            self.techniques.add("repeat")
            return left * count
        return self._int(self._int(left) * self._int(right))

    def _fold_UnaryOp(self, node: ast.UnaryOp, depth: int) -> Any:
        value = self._int(self.fold(node.operand, depth))
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return value
        if isinstance(node.op, ast.Invert):
            return ~value
        raise _Unfoldable

    def _fold_JoinedStr(self, node: ast.JoinedStr, depth: int) -> str:
        parts: list[str] = []
        total = 0
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                piece = value.value
                self._leaf(piece)
            elif isinstance(value, ast.FormattedValue) and value.format_spec is None and value.conversion in (-1, 115):
                inner = self.fold(value.value, depth)
                piece = inner if isinstance(inner, str) else str(self._int(inner))
            else:
                raise _Unfoldable
            total += len(piece)
            self._len(total)
            parts.append(piece)
        self.techniques.add("fstring")
        return "".join(parts)

    def _fold_List(self, node: ast.List | ast.Tuple, depth: int) -> list[Any]:
        if len(node.elts) > MAX_FOLD_SEQUENCE:
            raise _Unfoldable
        out = []
        for elt in node.elts:
            if isinstance(elt, ast.Starred):
                raise _Unfoldable
            out.append(self.fold(elt, depth))
        return out

    _fold_Tuple = _fold_List

    def _fold_ListComp(self, node: ast.ListComp | ast.GeneratorExp, depth: int) -> list[Any]:
        if len(node.generators) != 1:
            raise _Unfoldable
        gen = node.generators[0]
        if gen.ifs or gen.is_async or not isinstance(gen.target, ast.Name):
            raise _Unfoldable
        items = self._sequence(self.fold(gen.iter, depth))
        name = gen.target.id
        saved = self._bindings.get(name, _MISSING)
        out = []
        try:
            for item in items:
                self._tick()
                self._bindings[name] = item
                out.append(self.fold(node.elt, depth))
        finally:
            if saved is _MISSING:
                self._bindings.pop(name, None)
            else:
                self._bindings[name] = saved
        return out

    _fold_GeneratorExp = _fold_ListComp

    @staticmethod
    def _sequence(value: Any) -> list[Any]:
        if isinstance(value, (str, bytes, list)):
            if len(value) > MAX_FOLD_SEQUENCE:
                raise _Unfoldable
            return list(value)
        raise _Unfoldable

    def _fold_Subscript(self, node: ast.Subscript, depth: int) -> Any:
        value = self.fold(node.value, depth)
        if not isinstance(value, (str, bytes, list)):
            raise _Unfoldable
        sl = node.slice
        if isinstance(sl, ast.Slice):
            bounds = [None if part is None else self._int(self.fold(part, depth)) for part in (sl.lower, sl.upper,
                                                                                               sl.step)]
            if bounds[2] == 0:
                raise _Unfoldable
            self.techniques.add("reverse" if bounds == [None, None, -1] else "slice")
            return value[slice(*bounds)]
        index = self._int(self.fold(sl, depth))
        if not -len(value) <= index < len(value):
            raise _Unfoldable
        self.techniques.add("index")
        return value[index]

    def _dotted(self, func: ast.expr) -> str | None:
        if self.qualname is not None:
            resolved = self.qualname(func)
            if resolved:
                return resolved
        parts: list[str] = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(node.id)
        return ".".join(reversed(parts))

    def _fold_Call(self, node: ast.Call, depth: int) -> Any:
        func = node.func
        if isinstance(func, ast.Name) and func.id in self._bindings:
            raise _Unfoldable  # a comprehension variable is never a callable we emulate
        if not isinstance(func, (ast.Name, ast.Attribute)):
            raise _Unfoldable
        dotted = self._dotted(func)
        if dotted in _DECODER_FUNCS or dotted in _MODULE_CALLS:
            return self._module_call(dotted, node, depth)
        if isinstance(func, ast.Name):
            if dotted is not None and dotted != func.id:
                raise _Unfoldable  # imported under this name: not the builtin
            return self._builtin(func.id, node, depth)
        receiver = self.fold(func.value, depth)
        return self._method(receiver, func.attr, node, depth)

    def _map(self, node: ast.Call, depth: int) -> list[Any]:
        """``map(chr, ints)`` / ``map(ord, chars)`` / ``map(str, values)`` over a folded sequence."""
        if len(node.args) != 2 or node.keywords:
            raise _Unfoldable
        fn = node.args[0]
        if not isinstance(fn, ast.Name) or fn.id not in ("chr", "ord", "str") or fn.id in self._bindings:
            raise _Unfoldable
        if self.qualname is not None and self.qualname(fn) not in (None, fn.id):
            raise _Unfoldable
        items = self._sequence(self.fold(node.args[1], depth))
        self._tick(len(items))
        if fn.id == "chr":
            self.techniques.add("chr")
            return [self._chr(v) for v in items]
        if fn.id == "ord":
            return [ord(v) if isinstance(v, str) and len(v) == 1 else self._fail() for v in items]
        return [v if isinstance(v, str) else str(self._int(v)) for v in items]

    def _chr(self, value: Any) -> str:
        code = self._int(value)
        if not 0 <= code <= 0x10FFFF:
            raise _Unfoldable
        return chr(code)

    def _builtin(self, name: str, node: ast.Call, depth: int) -> Any:
        if name == "map":
            return self._map(node, depth)
        args, kwargs = self._args(node, depth)
        if name == "chr" and len(args) == 1 and not kwargs:
            self.techniques.add("chr")
            return self._chr(args[0])
        if name in ("bytes", "bytearray") and len(args) == 1 and not kwargs and isinstance(args[0], list):
            self.techniques.add("bytes")
            return bytes(self._byte(v) for v in args[0])
        if name in ("str", "bytes", "bytearray") and args and isinstance(args[0], (str, bytes)):
            if len(args) == 1 and not kwargs:
                if name == "str" and isinstance(args[0], str):
                    return args[0]
                if name != "str" and isinstance(args[0], bytes):
                    return args[0]
                raise _Unfoldable
            codec = self._codec(args[1] if len(args) > 1 else kwargs.get("encoding"))
            if name == "str" and isinstance(args[0], bytes):
                return args[0].decode(codec, self._errors(args[2] if len(args) > 2 else kwargs.get("errors")))
            if name != "str" and isinstance(args[0], str):
                return args[0].encode(codec)
            raise _Unfoldable
        if name in ("list", "tuple") and len(args) == 1 and not kwargs:
            return self._sequence(args[0])
        if name == "reversed" and len(args) == 1 and not kwargs:
            self.techniques.add("reverse")
            return self._sequence(args[0])[::-1]
        if name == "range" and 1 <= len(args) <= 3 and not kwargs:
            bounds = range(*(self._int(v) for v in args))
            if len(bounds) > MAX_FOLD_SEQUENCE:
                raise _Unfoldable
            self._tick(len(bounds))
            return list(bounds)
        raise _Unfoldable

    @staticmethod
    def _fail() -> Any:
        raise _Unfoldable

    def _byte(self, value: Any) -> int:
        v = self._int(value)
        if not 0 <= v <= 255:
            raise _Unfoldable
        return v

    @staticmethod
    def _codec(value: Any, default: str = "utf-8") -> str:
        codec = default if value is None else value
        if not isinstance(codec, str) or codec.lower() not in _SAFE_TEXT_CODECS:
            raise _Unfoldable
        return codec.lower()

    @staticmethod
    def _errors(value: Any) -> str:
        errors = "strict" if value is None else value
        if errors not in _SAFE_ERRORS:
            raise _Unfoldable
        return errors

    def _module_call(self, dotted: str, node: ast.Call, depth: int) -> Any:
        args, kwargs = self._args(node, depth)
        if dotted in _DECODER_FUNCS and len(args) == 1 and not kwargs and isinstance(args[0], (str, bytes)):
            encoding = _DECODER_FUNCS[dotted]
            result = apply_layer(encoding, args[0], max_output=self.max_len)
            if result is None or result[1] is not None:
                raise _Unfoldable
            self._tick(1 + len(result[0]) // 4096)
            self.techniques.add("hex" if encoding == "hex" else "base64")
            return result[0]
        if dotted.endswith(".maketrans") and len(args) in (2, 3) and not kwargs:
            if dotted.startswith("str") and all(isinstance(a, str) for a in args) and len(args[0]) == len(args[1]):
                self._tick(sum(len(a) for a in args))
                return _TransTable(str.maketrans(*args))
            if not dotted.startswith("str") and len(args) == 2 and all(isinstance(a, bytes) for a in args):
                if len(args[0]) != len(args[1]):
                    raise _Unfoldable
                return _TransTable({"bytes": bytes.maketrans(args[0], args[1])})
            raise _Unfoldable
        if dotted.endswith(".fromhex") and len(args) == 1 and not kwargs and isinstance(args[0], str):
            self._len(len(args[0]) // 2)
            self.techniques.add("hex")
            return bytes.fromhex(args[0])
        if dotted in ("codecs.decode", "codecs.encode") and len(args) in (1, 2):
            obj = args[0]
            codec = args[1] if len(args) > 1 else kwargs.get("encoding", "utf-8")
            if not isinstance(codec, str):
                raise _Unfoldable
            codec = codec.lower()
            if codec in _ROT13_CODECS and isinstance(obj, str):
                self.techniques.add("rot13")
                return codecs.encode(obj, "rot13")
            if codec in ("hex", "hex_codec") and dotted == "codecs.decode" and isinstance(obj, bytes):
                self.techniques.add("hex")
                return self._module_call_value("hex", obj)
            if codec in ("base64", "base64_codec") and dotted == "codecs.decode" and isinstance(obj, bytes):
                self.techniques.add("base64")
                return self._module_call_value("base64", obj)
            codec = self._codec(codec)
            if dotted == "codecs.decode" and isinstance(obj, bytes):
                return obj.decode(codec)
            if dotted == "codecs.encode" and isinstance(obj, str):
                return obj.encode(codec)
        raise _Unfoldable

    def _module_call_value(self, encoding: str, value: bytes) -> bytes:
        result = apply_layer(encoding, value, max_output=self.max_len)
        if result is None or result[1] is not None:
            raise _Unfoldable
        return result[0]

    def _method(self, receiver: Any, attr: str, node: ast.Call, depth: int) -> Any:
        args, kwargs = self._args(node, depth)
        if not isinstance(receiver, (str, bytes)):
            raise _Unfoldable
        is_str = isinstance(receiver, str)
        if attr == "join" and len(args) == 1 and not kwargs:
            items = self._sequence(args[0])
            kind = str if is_str else bytes
            if not all(isinstance(item, kind) for item in items):
                raise _Unfoldable
            self._len(sum(len(item) for item in items) + len(receiver) * max(0, len(items) - 1))
            self._tick(len(items))
            self.techniques.add("join")
            if len(items) > 1 and all(len(item) == 1 for item in items):
                self.techniques.add("char_join")
            return receiver.join(items)
        if attr == "maketrans" and is_str:
            return self._module_call_value_table(args, kwargs)
        if attr == "translate" and len(args) == 1 and not kwargs and isinstance(args[0], _TransTable):
            self._tick(1 + len(receiver) // 4096)
            self.techniques.add("translate")
            table = args[0]
            if is_str and "bytes" not in table:
                return receiver.translate(table)
            if not is_str and "bytes" in table:
                return receiver.translate(table["bytes"])
            raise _Unfoldable
        if attr == "replace" and len(args) in (2, 3) and not kwargs:
            old, new = args[0], args[1]
            if not (isinstance(old, type(receiver)) and isinstance(new, type(receiver))):
                raise _Unfoldable
            hits = receiver.count(old) if old else len(receiver) + 1
            if len(args) == 3:
                hits = min(hits, max(0, self._int(args[2])))
            self._len(len(receiver) + hits * max(0, len(new) - len(old)))
            self.techniques.add("replace")
            return receiver.replace(old, new, *(args[2:]))
        if attr == "decode" and not is_str and len(args) <= 2:
            codec = self._codec(args[0] if args else kwargs.get("encoding"))
            self.techniques.add("decode")
            return receiver.decode(codec, self._errors(args[1] if len(args) > 1 else kwargs.get("errors")))
        if attr == "encode" and is_str and len(args) <= 2:
            codec = self._codec(args[0] if args else kwargs.get("encoding"))
            return receiver.encode(codec, self._errors(args[1] if len(args) > 1 else kwargs.get("errors")))
        if attr in _CASE_METHODS and not kwargs and len(args) <= 1:
            if args and (attr not in ("strip", "lstrip", "rstrip") or not isinstance(args[0], type(receiver))):
                raise _Unfoldable
            self.techniques.add("case")
            return getattr(receiver, attr)(*args)
        raise _Unfoldable

    def _module_call_value_table(self, args: list[Any], kwargs: dict[str, Any]) -> _TransTable:
        if kwargs or len(args) not in (2, 3) or not all(isinstance(a, str) for a in args) or len(args[0]) != len(
                args[1]):
            raise _Unfoldable
        self._tick(sum(len(a) for a in args))
        return _TransTable(str.maketrans(*args))


def fold(
    node: ast.AST,
    *,
    names: Mapping[str, Any] | Callable[[str], Any] | None = None,
    qualname: Callable[[ast.expr], str | None] | None = None,
    max_len: int = MAX_FOLD_LEN,
    max_steps: int = MAX_FOLD_STEPS,
    max_depth: int = MAX_FOLD_DEPTH,
) -> FoldResult | None:
    """Statically evaluate a string/bytes construction made only of constants, or return ``None``.

    ``names`` resolves variables (a mapping or a callable returning an AST node, a str/bytes/int
    value, or ``None``); ``qualname`` optionally resolves import aliases of called functions.
    Nothing is executed: only the operations listed in the module docstring are emulated, each
    with size checks performed *before* the result is built.
    """
    return fold_counted(node, names=names, qualname=qualname, max_len=max_len, max_steps=max_steps,
                        max_depth=max_depth)[0]


def fold_counted(
    node: ast.AST,
    *,
    names: Mapping[str, Any] | Callable[[str], Any] | None = None,
    qualname: Callable[[ast.expr], str | None] | None = None,
    max_len: int = MAX_FOLD_LEN,
    max_steps: int = MAX_FOLD_STEPS,
    max_depth: int = MAX_FOLD_DEPTH,
) -> tuple[FoldResult | None, int]:
    """:func:`fold` plus the number of folding steps it used (so callers can keep a work budget)."""
    if not isinstance(node, ast.AST):
        return None, 0
    folder = _Folder(names, qualname, max(0, int(max_len)), max(1, int(max_steps)), max(1, int(max_depth)))
    try:
        value = folder.fold(node)
    except Exception:  # hostile input: any failure to emulate means "unsure", never a crash
        return None, min(folder.steps, folder.max_steps)
    steps = min(folder.steps, folder.max_steps)
    if isinstance(value, bytearray):
        value = bytes(value)
    if not isinstance(value, (str, bytes)) or len(value) > folder.max_len:
        return None, steps
    return FoldResult(value, frozenset(folder.techniques), tuple(folder.leaves), folder.leaves_complete), steps


def constant_fold(node: ast.AST, **kwargs: Any) -> str | bytes | None:
    """The folded str/bytes value of ``node`` (see :func:`fold`), or ``None`` when unsure."""
    result = fold(node, **kwargs)
    return None if result is None else result.value


__all__ = [
    "BENIGN_KINDS",
    "BINARY_CODE_KINDS",
    "CODE_KINDS",
    "COMPRESSION_ENCODINGS",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_OUTPUT",
    "EXECUTABLE_KINDS",
    "OBFUSCATING_TECHNIQUES",
    "SOURCE_CODE_KINDS",
    "Classification",
    "DecodeResult",
    "FoldResult",
    "Kind",
    "Layer",
    "apply_layer",
    "classify",
    "compact",
    "compression_format",
    "constant_fold",
    "decode_chain",
    "decode_layers",
    "decompress",
    "encoded_format",
    "extract_network_indicators",
    "fold",
    "fold_counted",
    "preview",
    "python_indicators",
]
