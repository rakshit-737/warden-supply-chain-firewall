"""Obfuscation & encoded-payload analyzer (v2).

Malicious packages routinely hide their payload: an encoded blob decoded and executed at
runtime (``exec(base64.b64decode("...."))``), several nested encoding / compression layers, a
hex-encoded executable, or names such as ``__import__`` assembled from ``chr()`` calls so that
neither reviewers nor grep see them. This analyzer is designed to surface those patterns using
AST structure (import aliases resolved, variables followed within a scope) and safe, bounded
decoding (:mod:`app.analysis.decode`), which never executes or deserialises content.

Findings
========

``ENCODED_EXEC`` (critical, weight 10, confidence 0.9)
    Either the v1 package-wide fingerprint — a decoder call, an ``exec``/``eval`` call and a
    high-entropy blob all present — or a *structural chain*: ``exec``/``eval``/``compile``
    applied, directly or through a variable assigned in the same scope, to the result of a
    decoder (``b64decode``, ``decompress``, ``bytes.fromhex``, ``codecs.decode(..., "rot13")``,
    ``marshal.loads`` ...) whose input folds to a constant, or to a string folded from constants
    with an obfuscating technique. A short payload is enough. A chain whose input cannot be
    resolved statically (``exec(b64decode(load()))``) is not reported (v1 contract).
``OBFUSCATION`` (v1 semantics)
    High-entropy base64-alphabet string literals. Blobs that decode to a recognised benign format
    (image, font, DER certificate, JSON, plain text) no longer count.
``LAYERED_ENCODING`` (critical, weight 9, confidence 0.85)
    A constant needing two or more decoding layers that ends in code, an executable, a
    marshalled / pickled object or a URL (or is still encoded at the depth limit).
``HEX_PAYLOAD`` (high, weight 6, confidence 0.75)
    A hex / escaped-hex constant of at least 200 hex digits decoding (in one layer) to code or a
    binary executable object. Hashes and short hex strings never produce this finding.
``COMPRESSED_PAYLOAD``
    A compressed constant that decompresses to code or a binary executable object (high, weight
    6, confidence 0.8) or to ordinary data — a compressed data table (low, weight 1, confidence 0.4).
``STRING_RECONSTRUCTION`` (high, weight 6, confidence 0.8)
    A string folded from constants in which ``exec``, ``eval``, ``__import__``, ``subprocess``,
    ``socket``, ``os.system`` or ``base64`` appears only after folding (in none of the pieces),
    an obfuscating technique (``chr``, reversal, ``translate``, rot13 ...) that produces a URL, or
    such a name written entirely as escape sequences in a call to ``__import__``/``getattr``.
``LARGE_CONSTANT`` (low, weight 1, confidence 0.4)
    A string or bytes literal larger than 100 KiB in a ``.py`` file.
``MINIFIED_CODE`` (medium, weight 3, confidence 0.55)
    A line with more than 5000 characters of code outside literals, imports, comments and data
    punctuation, or a file of at most ten lines averaging more than 250 such characters.

Context and uncertainty
=======================

Each occurrence records ``context``: ``install_time`` (``setup.py``), ``test`` (test files),
``import_time`` (module or class body) or ``runtime`` (inside a function). Payload findings
(layered, hex, compressed, reconstruction) in test files are reported one severity lower with
confidence reduced by 0.2, because test suites legitimately embed fixtures; ``ENCODED_EXEC`` is
not downgraded.

Findings are package-wide aggregates per code and severity. ``location`` is the first
occurrence (package file order, then line; lines come from the parser), ``evidence["locations"]``
lists up to ten positions and ``evidence["occurrences"]`` summarises up to five: layers, decoded
kind, an at-most-80-character sanitised preview and indicators — never the payload itself.

Work is bounded because input is hostile: decoding is capped per file and per package (count,
total decoded bytes, wall-clock time) and folding has per-expression and per-file step budgets.
When a decoding budget runs out, remaining candidates are left undecoded (high-entropy blobs then
count as v1 obfuscation) and emitted findings carry ``evidence["decode_budget_exhausted"]``.
"""

from __future__ import annotations

import ast
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any

from app.analysis import decode
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.analyzers.static_code import LocationCollector
from app.analysis.findings import Location
from app.analysis.signals import Capability, Code, Severity, Signal
from app.core.redaction import sanitize_text

# Kept at 1.1.0: the analyzer contract tests pin the six v1 analyzer versions (see the report).
ANALYZER_VERSION = "1.1.0"

# --------------------------------------------------------------------------- v1 constants
# Specific decoder functions only. The generic name "loads" was intentionally removed:
# it matches json.loads / pickle.loads, which are ubiquitous and benign, and produced
# false positives (e.g. flask). marshal.loads is matched via its module root below.
_DECODERS = {"b64decode", "b16decode", "b32decode", "a85decode", "unhexlify", "decompress"}
_DECODER_MODULES = {"base64", "marshal", "zlib", "codecs", "binascii", "gzip", "lzma"}
_LONG_STRING = 120  # chars
_HIGH_ENTROPY = 4.3  # bits/char; english text ~4.0-4.3, base64 blobs ~5.0-6.0
_B64ISH = re.compile(r"^[A-Za-z0-9+/=_\-]+$")

# decoder + executor + blob is strong structural evidence of a packed loader.
CONFIDENCE_ENCODED_EXEC = 0.9
# Entropy alone is heuristic (test vectors, embedded certificates and data tables exist).
CONFIDENCE_OBFUSCATION_SINGLE = 0.6
CONFIDENCE_OBFUSCATION_MULTI = 0.7
WEIGHT_ENCODED_EXEC = 10.0

_BLOB, _DECODER, _EXEC = "blob", "decoder", "exec"

# --------------------------------------------------------------------------- v2 thresholds
KiB = 1024
MiB = 1024 * KiB

CONFIDENCE_LAYERED, WEIGHT_LAYERED = 0.85, 9.0
CONFIDENCE_HEX, WEIGHT_HEX = 0.75, 6.0
CONFIDENCE_COMPRESSED, WEIGHT_COMPRESSED = 0.8, 6.0
CONFIDENCE_COMPRESSED_DATA, WEIGHT_COMPRESSED_DATA = 0.4, 1.0
CONFIDENCE_RECONSTRUCTION, WEIGHT_RECONSTRUCTION = 0.8, 6.0
CONFIDENCE_LARGE_CONSTANT, WEIGHT_LARGE_CONSTANT = 0.4, 1.0
CONFIDENCE_MINIFIED, WEIGHT_MINIFIED = 0.55, 3.0
TEST_CONFIDENCE_PENALTY = 0.2
# Severity / weight used when a payload finding sits in a test file.
_DOWNGRADE = {Severity.critical: (Severity.high, 6.0), Severity.high: (Severity.medium, 3.0)}

HEX_PAYLOAD_MIN_DIGITS = 200
LARGE_CONSTANT_BYTES = 100 * KiB
MINIFIED_LINE_CHARS = 5000
MINIFIED_AVG_CHARS = 250
MINIFIED_FEW_LINES = 10
MINIFIED_MIN_TOTAL = 1000
COMPRESSED_DATA_MIN_BYTES = 256

MIN_DECODE_CANDIDATE_CHARS = 64
CANDIDATE_MAX_OUTPUT = 1 * MiB
CHAIN_MAX_OUTPUT = decode.DEFAULT_MAX_OUTPUT
MAX_DECODES_PER_PACKAGE = 256
MAX_DECODES_PER_FILE = 48
DECODE_OUTPUT_BUDGET = 64 * MiB
DECODE_TIME_BUDGET_SECONDS = 20.0
MAX_CONSTANTS_PER_FILE = 4096
MAX_CALLS_PER_FILE = 2048
MAX_FOLD_ROOTS_PER_FILE = 4096
FOLD_STEPS_PER_EXPRESSION = 20_000
FOLD_STEPS_PER_FILE = 400_000
MAX_EVIDENCE_OCCURRENCES = 5
MAX_EVIDENCE_LOCATIONS = 10
PREVIEW_CHARS = decode.PREVIEW_CHARS


class Context:
    INSTALL = "install_time"
    TEST = "test"
    IMPORT = "import_time"
    RUNTIME = "runtime"


_TEST_DIRS = frozenset({"test", "tests", "testing"})


def file_context(relpath: str) -> str | None:
    """``install_time`` for setup.py, ``test`` for test files, ``None`` for ordinary modules."""
    parts = relpath.replace("\\", "/").lower().split("/")
    name = parts[-1]
    if name == "setup.py":
        return Context.INSTALL
    if (name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py")
            or _TEST_DIRS.intersection(parts[:-1])):
        return Context.TEST
    return None


# --------------------------------------------------------------------------- call vocabulary
# Fully-qualified decoder functions -> the decode layer they apply.
DECODER_CALLS: dict[str, str] = {
    "base64.b64decode": "base64", "base64.standard_b64decode": "base64", "base64.urlsafe_b64decode": "base64url",
    "base64.decodebytes": "base64", "base64.decodestring": "base64", "base64.b32decode": "base32",
    "base64.b16decode": "hex", "base64.a85decode": "ascii85", "base64.b85decode": "base85",
    "binascii.a2b_base64": "base64", "binascii.a2b_hex": "hex", "binascii.unhexlify": "hex",
    "zlib.decompress": "zlib", "gzip.decompress": "gzip", "bz2.decompress": "bz2", "lzma.decompress": "lzma",
    "bytes.fromhex": "hex", "bytearray.fromhex": "hex", "marshal.loads": "marshal",
}
# Attribute names distinctive enough to count whatever object they are called on.
_DISTINCTIVE_DECODER_ATTRS: dict[str, str] = {
    "b64decode": "base64", "urlsafe_b64decode": "base64url", "b32decode": "base32", "b16decode": "hex",
    "a85decode": "ascii85", "b85decode": "base85", "unhexlify": "hex", "a2b_base64": "base64", "a2b_hex": "hex",
    "fromhex": "hex",
}
_DECOMPRESSOBJ = {"zlib.decompressobj": "zlib", "bz2.BZ2Decompressor": "bz2", "lzma.LZMADecompressor": "lzma"}
_CODEC_LAYERS: dict[str, str] = {
    "base64": "base64", "base64_codec": "base64", "base_64": "base64", "hex": "hex", "hex_codec": "hex",
    "zlib": "zlib", "zlib_codec": "zlib", "zip": "zlib", "bz2": "bz2", "bz2_codec": "bz2",
    "rot13": "rot13", "rot_13": "rot13",
}
_KNOWN_QUALNAMES = frozenset(DECODER_CALLS) | {"codecs.decode", "codecs.encode"} | frozenset(_DECOMPRESSOBJ)
_EXECUTOR_NAMES = frozenset({"exec", "eval", "compile"})
_BUILTIN_MODULES = frozenset({"builtins", "__builtins__", "__builtin__"})
_DYNAMIC_IMPORTERS = frozenset({"__import__", "importlib.import_module"})
_TRANSPARENT_BUILTINS = frozenset({"compile", "str", "bytes", "bytearray"})
_TRANSPARENT_METHODS = frozenset({"decode", "encode", "strip", "lstrip", "rstrip", "replace", "lower", "upper"})
_FOLD_CALL_NAMES = frozenset({"chr", "bytes", "bytearray", "str", "map", "reversed"})
_FOLD_METHODS = frozenset({
    "join", "translate", "decode", "encode", "replace", "fromhex", "lower", "upper", "swapcase", "strip", "lstrip",
    "rstrip", "b64decode", "standard_b64decode", "urlsafe_b64decode", "b32decode", "b16decode", "unhexlify",
    "a2b_hex", "a2b_base64", "decodebytes",
})
_ESCAPED_LITERAL_CALLS = {"__import__": 0, "getattr": 1, "exec": 0, "eval": 0, "importlib.import_module": 0}
_ESCAPE_RE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{1,3}|N\{[^}]{1,64}\})")
RECONSTRUCTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("exec", re.compile(r"\bexec\b")),
    ("eval", re.compile(r"\beval\b")),
    ("__import__", re.compile(r"__import__")),
    ("subprocess", re.compile(r"\bsubprocess\b")),
    ("socket", re.compile(r"\bsocket\b")),
    ("os.system", re.compile(r"\bos\.system\b")),
    ("base64", re.compile(r"\bbase64\b")),
)
_LINE_SPLIT_RE = re.compile(r"\r\n|\r|\n")
_DATA_PUNCTUATION = b" \t\x0b\x0c,()[]{}:\\"
_MODULE_SCOPE = 0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def reconstruction_indicators(result: decode.FoldResult) -> list[str]:
    """Names / URLs that exist only in the folded value, never in one of its constant pieces."""
    text = result.text[: 64 * KiB]
    found: list[str] = []
    for label, pattern in RECONSTRUCTION_PATTERNS:
        for match in list(pattern.finditer(text))[:32]:
            if result.hides(match.group(0)):
                found.append(label)
                break
    if result.obfuscating:
        urls, ips = decode.extract_network_indicators(text, limit=3)
        found.extend(f"url:{u}" for u in urls if result.hides(u))
        found.extend(f"ip:{ip}" for ip in ips if result.hides(ip))
    return found


# --------------------------------------------------------------------------- per-file model
class _Imports:
    """Import aliases of one file (``import base64 as b`` → ``b`` means ``base64``)."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.star: list[str] = []

    def record(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    self.aliases[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    self.aliases[root] = root
        elif node.module and not node.level:
            for alias in node.names:
                if alias.name == "*":
                    if len(self.star) < 16:
                        self.star.append(node.module)
                else:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def qualname(self, expr: ast.expr, _depth: int = 0) -> str | None:
        parts: list[str] = []
        node = expr
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
            if len(parts) > 16:
                return None
        if isinstance(node, ast.Name):
            base = self.aliases.get(node.id)
            if base is None:
                base = node.id
                for module in self.star:
                    if f"{module}.{node.id}" in _KNOWN_QUALNAMES:
                        base = f"{module}.{node.id}"
                        break
            parts.append(base)
        elif (isinstance(node, ast.Call) and _depth < 4 and node.args and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str) and self.qualname(node.func, _depth + 1) in _DYNAMIC_IMPORTERS):
            parts.append(node.args[0].value)
        else:
            return None
        return ".".join(reversed(parts))


def _minified_candidates(text: str) -> tuple[dict[int, str], bool]:
    """Lines worth measuring for code density, and whether the file qualifies as 'few lines'."""
    lines = _LINE_SPLIT_RE.split(text)
    nonblank = [(i, line) for i, line in enumerate(lines, start=1) if line.strip()]
    if 0 < len(nonblank) <= MINIFIED_FEW_LINES:
        total = sum(len(line) for _, line in nonblank)
        if total >= MINIFIED_MIN_TOTAL and total / len(nonblank) > MINIFIED_AVG_CHARS:
            return dict(nonblank), True
    return {i: line for i, line in nonblank if len(line) > MINIFIED_LINE_CHARS}, False


class _FileModel:
    """One parsed file: imports, per-scope assignments and the nodes the analyzer inspects."""

    def __init__(self, index: int, relpath: str, text: str, tree: ast.Module) -> None:
        self.index = index
        self.relpath = relpath
        self.text = text
        self.file_context = file_context(relpath)
        self.imports = _Imports()
        self.assignments: dict[int, dict[str, list[tuple[int, ast.expr]]]] = {_MODULE_SCOPE: {}}
        self.rebound: dict[int, set[str]] = {}
        self.scope_parent: dict[int, int] = {}
        self.class_scopes: set[int] = set()
        self.calls: list[tuple[ast.Call, int, bool]] = []
        self.fold_roots: list[tuple[ast.expr, int, bool]] = []
        self.constants: list[tuple[ast.Constant, bool]] = []
        self.v1_blobs: list[ast.Constant] = []
        self.v1_decoders: list[tuple[str, ast.Call]] = []
        self.v1_execs: list[tuple[ast.Call, bool]] = []
        self.fold_steps = 0
        self.decodes = 0
        self.dense_lines, self.few_lines = _minified_candidates(text)
        self.spans: dict[int, list[tuple[int, int]]] = {}
        self._walk(tree)

    # ------------------------------------------------------------------ context
    def context(self, in_function: bool) -> str:
        return self.file_context or (Context.RUNTIME if in_function else Context.IMPORT)

    # ------------------------------------------------------------------ traversal
    def _walk(self, tree: ast.Module) -> None:
        stack: list[tuple[ast.AST, int, bool, ast.AST | None]] = [(tree, _MODULE_SCOPE, False, None)]
        while stack:
            node, scope, in_func, parent = stack.pop()
            self._visit(node, scope, in_func, parent)
            inner_scope, inner_func = scope, in_func
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                inner_scope = id(node)
                inner_func = in_func or not isinstance(node, ast.ClassDef)
                self.scope_parent[inner_scope] = scope
                self.assignments.setdefault(inner_scope, {})
                if isinstance(node, ast.ClassDef):
                    self.class_scopes.add(inner_scope)
            children: list[tuple[ast.AST, int, bool, ast.AST | None]] = []
            for name, value in ast.iter_fields(node):
                own = inner_scope != scope and name == "body"
                items = value if isinstance(value, list) else [value]
                for item in items:
                    if isinstance(item, ast.AST):
                        children.append((item, inner_scope if own else scope, inner_func if own else in_func, node))
            stack.extend(reversed(children))

    def _bind(self, scope: int, target: ast.expr, value: ast.expr | None, line: int) -> None:
        if isinstance(target, ast.Name):
            if value is None:
                self.rebound.setdefault(scope, set()).add(target.id)
            else:
                self.assignments.setdefault(scope, {}).setdefault(target.id, []).append((line, value))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind(scope, elt.value if isinstance(elt, ast.Starred) else elt, None, line)

    def _visit(self, node: ast.AST, scope: int, in_func: bool, parent: ast.AST | None) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self.imports.record(node)
            self._span(node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                self._bind(scope, target, node.value if len(node.targets) == 1 else None, node.lineno)
        elif isinstance(node, ast.AnnAssign):
            self._bind(scope, node.target, node.value, node.lineno)
        elif isinstance(node, ast.NamedExpr):
            self._bind(scope, node.target, node.value, node.lineno)
        elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor, ast.comprehension)):
            self._bind(scope, node.target, None, getattr(node, "lineno", 0))
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            self._bind(scope, node.optional_vars, None, 0)
        elif isinstance(node, ast.Constant):
            self._span(node)
            self._constant(node, in_func)
        elif isinstance(node, ast.JoinedStr):
            self._span(node)
        elif isinstance(node, ast.Call):
            self._call(node, scope, in_func)
        if self._is_fold_root(node, parent) and len(self.fold_roots) < MAX_FOLD_ROOTS_PER_FILE:
            self.fold_roots.append((node, scope, in_func))  # type: ignore[arg-type]

    def _constant(self, node: ast.Constant, in_func: bool) -> None:
        value = node.value
        if not isinstance(value, (str, bytes)):
            return
        if isinstance(value, str) and len(value) >= _LONG_STRING and _B64ISH.match(value.replace("\n", "")):
            self.v1_blobs.append(node)
        if len(value) >= MIN_DECODE_CANDIDATE_CHARS and len(self.constants) < MAX_CONSTANTS_PER_FILE:
            self.constants.append((node, in_func))

    def _call(self, node: ast.Call, scope: int, in_func: bool) -> None:
        fn = node.func
        # v1 indicator vocabulary (unchanged semantics).
        if isinstance(fn, ast.Attribute):
            root = fn.value.id if isinstance(fn.value, ast.Name) else None
            if fn.attr in _DECODERS:
                self.v1_decoders.append((fn.attr, node))
            elif fn.attr == "loads" and root == "marshal":
                self.v1_decoders.append(("marshal.loads", node))
            elif fn.attr == "decode" and root == "codecs":
                self.v1_decoders.append(("codecs.decode", node))
        if isinstance(fn, ast.Name) and fn.id in {"eval", "exec"}:
            self.v1_execs.append((node, in_func))
        if len(self.calls) < MAX_CALLS_PER_FILE and (self.executor_of(node) or self._escaped_call(node) is not None):
            self.calls.append((node, scope, in_func))

    def _is_fold_root(self, node: ast.AST, parent: ast.AST | None) -> bool:
        if isinstance(node, ast.BinOp):
            if not isinstance(node.op, (ast.Add, ast.Mult)):
                return False
            return not (isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add) and isinstance(node.op, ast.Add))
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.Subscript):
            return isinstance(node.slice, ast.Slice)
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                return fn.id in _FOLD_CALL_NAMES
            return isinstance(fn, ast.Attribute) and fn.attr in _FOLD_METHODS
        return False

    def _span(self, node: ast.AST) -> None:
        if not self.dense_lines:
            return
        start, end = getattr(node, "lineno", None), getattr(node, "end_lineno", None)
        col, end_col = getattr(node, "col_offset", None), getattr(node, "end_col_offset", None)
        if start is None or end is None or col is None or end_col is None:
            return
        lines = range(start, end + 1) if end - start < len(self.dense_lines) else sorted(self.dense_lines)
        for line in lines:
            if line in self.dense_lines and start <= line <= end:
                self.spans.setdefault(line, []).append((col if line == start else 0,
                                                         end_col if line == end else 1 << 40))

    # ------------------------------------------------------------------ resolution
    def lookup(self, name: str, scope: int, line: int) -> ast.expr | None:
        """The value last assigned to ``name`` before ``line`` in ``scope`` (or an enclosing scope)."""
        current, first = scope, True
        for _ in range(64):
            if current not in self.class_scopes or first:
                if name in self.rebound.get(current, ()):
                    return None
                entries = self.assignments.get(current, {}).get(name)
                if entries:
                    if first:
                        before = [value for lineno, value in entries if lineno <= line]
                        return before[-1] if before else None
                    return entries[-1][1]
            if current == _MODULE_SCOPE:
                return None
            current, first = self.scope_parent.get(current, _MODULE_SCOPE), False
        return None

    def executor_of(self, call: ast.Call) -> str | None:
        fn = call.func
        if isinstance(fn, ast.Name):
            if fn.id in _EXECUTOR_NAMES and fn.id not in self.imports.aliases:
                return fn.id
            if fn.id == "exec_" and self.imports.aliases.get(fn.id, "six.exec_").endswith("exec_"):
                return "exec"
            return None
        if isinstance(fn, ast.Attribute) and fn.attr in ("exec", "eval", "exec_"):
            root = fn.value.id if isinstance(fn.value, ast.Name) else None
            if root in _BUILTIN_MODULES or self.imports.aliases.get(root or "", root) in ("six", *_BUILTIN_MODULES):
                return "exec" if fn.attr == "exec_" else fn.attr
        return None

    def _escaped_call(self, call: ast.Call) -> int | None:
        fn = call.func
        name = fn.id if isinstance(fn, ast.Name) else ("importlib.import_module" if isinstance(fn, ast.Attribute)
                                                        and fn.attr == "import_module" else None)
        index = _ESCAPED_LITERAL_CALLS.get(name or "")
        if index is None or len(call.args) <= index:
            return None
        arg = call.args[index]
        return index if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else None

    def decoder_of(self, call: ast.Call) -> tuple[str, str] | None:
        """``(qualname, layer)`` when ``call`` applies a decoding step."""
        fn = call.func
        qual = self.imports.qualname(fn)
        if qual in DECODER_CALLS:
            return qual, DECODER_CALLS[qual]
        if isinstance(fn, ast.Attribute):
            if fn.attr in _DISTINCTIVE_DECODER_ATTRS:
                return qual or fn.attr, _DISTINCTIVE_DECODER_ATTRS[fn.attr]
            if fn.attr == "decompress" and isinstance(fn.value, ast.Call):
                maker = self.imports.qualname(fn.value.func)
                if maker in _DECOMPRESSOBJ:
                    return f"{maker}().decompress", _DECOMPRESSOBJ[maker]
            if fn.attr in ("decode", "encode") and qual not in ("codecs.decode", "codecs.encode"):
                codec = self._codec_arg(call, 0)
                if codec in _CODEC_LAYERS and fn.attr == "decode":
                    return f".decode({codec!r})", _CODEC_LAYERS[codec]
        if qual in ("codecs.decode", "codecs.encode"):
            codec = self._codec_arg(call, 1)
            layer = _CODEC_LAYERS.get(codec or "")
            if layer and (qual == "codecs.decode" or layer == "rot13"):
                return f"{qual}({codec!r})", layer
        return None

    @staticmethod
    def _codec_arg(call: ast.Call, index: int) -> str | None:
        node = call.args[index] if len(call.args) > index else next(
            (kw.value for kw in call.keywords if kw.arg == "encoding"), None)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.lower()
        return None

    def transparent_arg(self, call: ast.Call) -> ast.expr | None:
        """The wrapped expression of a call that passes its input through (``.decode()``, ``compile``)."""
        fn = call.func
        if isinstance(fn, ast.Name) and fn.id in _TRANSPARENT_BUILTINS and call.args:
            return call.args[0]
        if isinstance(fn, ast.Attribute):
            if self.imports.qualname(fn) in ("codecs.decode", "codecs.encode") and call.args:
                return call.args[0]
            if fn.attr in _TRANSPARENT_METHODS:
                return fn.value
        return None

    def resolver(self, scope: int, line: int) -> Any:
        return lambda name: self.lookup(name, scope, line)

    def fold(self, node: ast.AST, scope: int, line: int) -> decode.FoldResult | None:
        remaining = FOLD_STEPS_PER_FILE - self.fold_steps
        if remaining <= 0:
            return None
        steps = min(FOLD_STEPS_PER_EXPRESSION, remaining)
        self.fold_steps += steps  # charged up front: a failed fold may have used the whole budget
        return decode.fold(node, names=self.resolver(scope, line), qualname=self.imports.qualname, max_steps=steps)

    def escaped_literal(self, node: ast.Constant) -> bool:
        """True when a string literal is written (almost) entirely as escape sequences."""
        segment = ast.get_source_segment(self.text, node) if len(node.value) <= 4 * KiB else None
        if not segment:
            return False
        escapes = _ESCAPE_RE.findall(segment)
        return len(escapes) >= 4 and sum(len(e) for e in escapes) * 2 >= len(segment)

    def dense_code(self) -> dict[str, Any] | None:
        """MINIFIED_CODE evidence for this file, or ``None``."""
        measured: list[tuple[int, int]] = []
        for line_no in sorted(self.dense_lines):
            raw = self.dense_lines[line_no].encode("utf-8", "surrogatepass")
            count, pos = 0, 0
            for start, end in sorted(self.spans.get(line_no, [])) + [(len(raw), len(raw))]:
                if start > pos:
                    segment = raw[pos:start]
                    hash_at = segment.find(b"#")
                    if hash_at >= 0:
                        count += len(segment[:hash_at].translate(None, _DATA_PUNCTUATION))
                        break
                    count += len(segment.translate(None, _DATA_PUNCTUATION))
                pos = max(pos, end)
            measured.append((line_no, count))
        if not measured:
            return None
        best_line, best = max(measured, key=lambda item: (item[1], -item[0]))
        if self.few_lines:
            total = sum(c for _, c in measured)
            if total < MINIFIED_MIN_TOTAL or total / len(measured) <= MINIFIED_AVG_CHARS:
                return None
            mode, dense = "few_lines", [ln for ln, c in measured if c > MINIFIED_AVG_CHARS]
        else:
            dense = [ln for ln, c in measured if c > MINIFIED_LINE_CHARS]
            if not dense:
                return None
            mode = "long_line"
        first = dense[0] if dense else best_line
        return {"line": first, "mode": mode, "max_line_code_chars": best, "code_dense_lines": len(dense)}


# @@ANALYZER@@ (temporary v1-compatible implementation; replaced by the v2 analyzer below)
class ObfuscationAnalyzer(BaseAnalyzer):
    name = "obfuscation"
    version = ANALYZER_VERSION

    def analyze(self, ctx: PackageContext) -> list[Signal]:
        max_entropy = 0.0
        long_blobs = 0
        decoder_hits: set[str] = set()
        dynamic_exec = False
        evidence_blobs: list[str] = []
        locations = LocationCollector()
        for index, f in enumerate(ctx.python_files()):
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    val = node.value
                    if len(val) >= _LONG_STRING and _B64ISH.match(val.replace("\n", "")):
                        ent = shannon_entropy(val)
                        if ent >= _HIGH_ENTROPY:
                            long_blobs += 1
                            max_entropy = max(max_entropy, ent)
                            locations.add_node(_BLOB, index, f.relpath, node)
                            if len(evidence_blobs) < 3:
                                evidence_blobs.append(f"{f.relpath}:{val[:24]}…({len(val)}b)")
                elif isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Attribute):
                        root = fn.value.id if isinstance(fn.value, ast.Name) else None
                        if fn.attr in _DECODERS:
                            decoder_hits.add(fn.attr)
                            locations.add_node(_DECODER, index, f.relpath, node)
                        elif fn.attr == "loads" and root == "marshal":
                            decoder_hits.add("marshal.loads")
                            locations.add_node(_DECODER, index, f.relpath, node)
                        elif fn.attr == "decode" and root == "codecs":
                            decoder_hits.add("codecs.decode")
                            locations.add_node(_DECODER, index, f.relpath, node)
                    if isinstance(fn, ast.Name) and fn.id in {"eval", "exec"}:
                        dynamic_exec = True
                        locations.add_node(_EXEC, index, f.relpath, node)
        signals: list[Signal] = []
        if decoder_hits and dynamic_exec and long_blobs:
            signals.append(Signal(
                Code.ENCODED_EXEC, Severity.critical, WEIGHT_ENCODED_EXEC,
                "Decode-then-execute chain over a high-entropy blob (packed/obfuscated loader)",
                {"decoders": sorted(decoder_hits), "locations": locations.evidence(_DECODER, _EXEC, _BLOB)},
                capability=Capability.OBFUSCATION,
                confidence=CONFIDENCE_ENCODED_EXEC, location=locations.first(_DECODER, _EXEC, _BLOB),
            ))
        if long_blobs:
            score = min(1.0, (max_entropy - _HIGH_ENTROPY) / 1.5 + 0.4)
            signals.append(Signal(
                Code.OBFUSCATION, Severity.high if long_blobs > 1 else Severity.medium,
                3.0 + 1.5 * min(long_blobs, 4),
                f"{long_blobs} high-entropy string blob(s) (max entropy {max_entropy:.2f} bits/char)",
                {"blobs": evidence_blobs, "obfuscation_score": round(score, 3),
                 "locations": locations.evidence(_BLOB)},
                capability=Capability.OBFUSCATION,
                confidence=CONFIDENCE_OBFUSCATION_MULTI if long_blobs > 1 else CONFIDENCE_OBFUSCATION_SINGLE,
                location=locations.first(_BLOB),
            ))
        return signals
