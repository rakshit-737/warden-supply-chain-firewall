"""The synthetic detection benchmark runs and keeps its measured level (regression gate)."""

from __future__ import annotations

import json
import re

from benchmark import run
from benchmark.corpus import BENIGN, MALICIOUS, SAMPLES

# Measured with this corpus when the benchmark was added; see docs/BENCHMARK.md. The gate stops
# silent regressions - it is not a claim about real-world detection.
MIN_DETECTION_RATE = 0.9
MAX_FALSE_POSITIVE_RATE = 0.125
NEVER_BLOCKED = {"ben-native-build", "ben-editable-pth", "ben-test-fixtures", "ben-base64-assets"}


def test_corpus_is_labelled_and_inert():
    assert {s.label for s in SAMPLES} == {MALICIOUS, BENIGN}
    assert len({s.id for s in SAMPLES}) == len(SAMPLES)
    for sample in SAMPLES:
        text = json.dumps(sample.files)
        # Every URL host is under the reserved .invalid TLD (RFC 2606), so nothing can ever resolve -
        # except the source-repository URL in the shared registry metadata, which is never fetched.
        hosts = [re.match(r"[A-Za-z0-9.-]*", part).group(0) for part in text.split("://")[1:]]
        assert hosts and all(h.endswith(".invalid") for h in hosts) or "://" not in text, sample.id


def test_benchmark_meets_its_measured_level(tmp_path, capsys):
    output = tmp_path / "report.json"
    assert run.main(["--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["detection_rate"] >= MIN_DETECTION_RATE, report["missed"]
    assert report["false_positive_rate"] <= MAX_FALSE_POSITIVE_RATE, report["false_positives"]
    decisions = {r["id"]: r["decision"] for r in report["results"]}
    assert not any(decisions[i] == "block" for i in NEVER_BLOCKED)
    assert "Synthetic" in report["disclaimer"]
    assert "detection" in capsys.readouterr().out
