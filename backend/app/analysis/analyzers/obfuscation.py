"""Obfuscation & encoded-payload analyzer.

Malicious packages routinely hide their payload as an encoded blob that is decoded and
executed at runtime, e.g. ``exec(base64.b64decode("...."))`` or a ``marshal.loads`` of a
long byte string. This analyzer is designed to surface two things:

* **High-entropy string literals** — long strings whose Shannon entropy approaches that of
  encoded/encrypted data rather than natural source code.
* **Decode-then-execute chains** — the co-occurrence of a decoder (``base64``, ``marshal``,
  ``zlib``, ``codecs``) with a dynamic executor (``exec``/``eval``) and a high-entropy blob,
  which is the fingerprint of a packed loader.

Both findings are package-wide aggregates. ``location`` is the first contributing AST node
(file order, then line) and ``evidence["locations"]`` lists up to ten contributing positions.
Nothing is decoded or executed.
"""

from __future__ import annotations

import ast
import math
import re

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext
from app.analysis.analyzers.static_code import LocationCollector
from app.analysis.signals import Capability, Code, Severity, Signal

ANALYZER_VERSION = "1.1.0"

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

_BLOB, _DECODER, _EXEC = "blob", "decoder", "exec"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


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
                # Skip files that cannot be parsed (including parser-stack bombs, which raise
                # MemoryError) so one hostile file cannot hide blobs in the rest of the package.
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

        # The packed-loader fingerprint requires all three: a real decoder, a dynamic
        # executor, AND a high-entropy embedded blob. Requiring the blob eliminates false
        # positives from code that merely decodes data and separately uses exec().
        if decoder_hits and dynamic_exec and long_blobs:
            signals.append(Signal(
                Code.ENCODED_EXEC, Severity.critical, 10.0,
                "Decode-then-execute chain over a high-entropy blob (packed/obfuscated loader)",
                {"decoders": sorted(decoder_hits), "locations": locations.evidence(_DECODER, _EXEC, _BLOB)},
                capability=Capability.OBFUSCATION,
                confidence=CONFIDENCE_ENCODED_EXEC, location=locations.first(_DECODER, _EXEC, _BLOB),
            ))
        if long_blobs:
            # Normalise an obfuscation score into 0..1 for the feature vector.
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
