"""Run the synthetic detection benchmark: ``python -m benchmark.run [--output report.json]``.

Each corpus sample is wrapped in an sdist-style directory (``bench-pkg-1.0.0/...``), handed to the
real :class:`~app.analysis.orchestrator.Orchestrator` through an in-memory fetcher, analysed
offline (no registry, intelligence or provenance calls) and evaluated with the policy engine's
built-in default policy, or with ``--policy`` when given.

A malicious sample counts as *detected* when the decision is ``warn`` or ``block``; a benign sample
is a *false positive* when it is not ``allow``. The report lists every sample with its decision,
risk score and the finding codes that fired, plus totals per technique. The corpus is synthetic
and small: the numbers measure these patterns, not real-world detection.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.analysis.analyzers.base import PackageContext, ScanOptions, SourceFile
from app.analysis.orchestrator import Orchestrator
from app.policy.engine import evaluate
from benchmark.corpus import BENIGN, MALICIOUS, SAMPLES, Sample

VERSION = "1.0.0"
DETECTED = frozenset({"warn", "block"})


class _MemoryFetcher:
    def __init__(self, sample: Sample) -> None:
        self.sample = sample

    def build_context(self, name: str, version: str | None, options: ScanOptions | None = None) -> PackageContext:
        root = f"{self.sample.name}-1.0.0"
        files = [SourceFile(relpath=f"{root}/{path}", text=text, size=len(text.encode()))
                 for path, text in self.sample.files.items()]
        return PackageContext(ecosystem="pypi", name=self.sample.name, version="1.0.0",
                              metadata=dict(self.sample.metadata), files=files,
                              options=options or ScanOptions(offline=True))


class _NoCache:
    def get_json(self, key: str) -> None:
        return None

    def set_json(self, key: str, value: Any, ttl: int) -> None:
        return None


@dataclass
class SampleResult:
    id: str
    label: str
    technique: str
    evasive: bool
    decision: str
    risk_score: int
    severity: str
    codes: list[str]
    duration_ms: int

    @property
    def correct(self) -> bool:
        flagged = self.decision in DETECTED
        return flagged if self.label == MALICIOUS else not flagged


def run_sample(sample: Sample, policy: Any = None) -> SampleResult:
    options = ScanOptions(offline=True, intel=False, provenance=False, analyze_wheels=False)
    started = time.monotonic()
    result = Orchestrator(_MemoryFetcher(sample), cache_backend=_NoCache()).analyze(
        "pypi", sample.name, "1.0.0", options)
    decision = evaluate(result, policy)
    codes = sorted({s["code"] for s in result.signals if s.get("severity") not in ("info",)})
    return SampleResult(sample.id, sample.label, sample.technique, sample.evasive, decision.decision.value,
                        result.risk_score, result.severity, codes, int((time.monotonic() - started) * 1000))


def summarize(results: list[SampleResult]) -> dict[str, Any]:
    malicious = [r for r in results if r.label == MALICIOUS]
    benign = [r for r in results if r.label == BENIGN]
    evasive = [r for r in malicious if r.evasive]
    by_technique: dict[str, dict[str, int]] = defaultdict(lambda: {"samples": 0, "correct": 0})
    for r in results:
        by_technique[f"{r.label}:{r.technique}"]["samples"] += 1
        by_technique[f"{r.label}:{r.technique}"]["correct"] += int(r.correct)

    def rate(part: list[SampleResult]) -> float | None:
        return round(sum(r.correct for r in part) / len(part), 3) if part else None

    from app.analysis.analyzers import all_analyzers

    tools = {}
    for analyzer in all_analyzers():
        status = analyzer.availability() if hasattr(analyzer, "availability") else None
        if status is not None and analyzer.name in ("yara_scan", "semgrep_scan"):
            tools[analyzer.name] = bool(status.available)
    return {
        "benchmark_version": VERSION,
        "optional_tools": tools,
        "samples": len(results),
        "malicious": len(malicious),
        "benign": len(benign),
        "detection_rate": rate(malicious),
        "evasive_detection_rate": rate(evasive),
        "false_positive_rate": round(sum(not r.correct for r in benign) / len(benign), 3) if benign else None,
        "missed": [r.id for r in malicious if not r.correct],
        "false_positives": [r.id for r in benign if not r.correct],
        "by_technique": dict(sorted(by_technique.items())),
        "results": [{**r.__dict__, "correct": r.correct} for r in results],
        "disclaimer": "Synthetic, hand-written corpus; results describe these samples only.",
    }


def _load_policy(path: str | None) -> Any:
    if not path:
        return None
    from app.policy.document import validate_policy_text

    raw = Path(path).read_bytes()
    outcome = validate_policy_text(raw, "json" if path.endswith(".json") else "yaml")
    if not outcome.valid:
        raise SystemExit(f"invalid policy: {path}")
    return outcome.document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmark.run", description=__doc__.split("\n")[0])
    parser.add_argument("--output", "-o", help="write the JSON report here")
    parser.add_argument("--policy", help="policy document to evaluate with (default: built-in policy)")
    args = parser.parse_args(argv)

    policy = _load_policy(args.policy)
    report = summarize([run_sample(sample, policy) for sample in SAMPLES])
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"optional tools: {report['optional_tools']}")
    print(f"samples {report['samples']}  detection {report['detection_rate']}  "
          f"evasive {report['evasive_detection_rate']}  false positives {report['false_positive_rate']}")
    for row in report["results"]:
        mark = "ok  " if row["correct"] else "MISS" if row["label"] == MALICIOUS else "FP  "
        print(f"{mark} {row['id']:28} {row['decision']:5} risk {row['risk_score']:3}  {', '.join(row['codes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
