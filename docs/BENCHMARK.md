# Detection benchmark

Warden ships a small, synthetic benchmark that runs labelled packages through the real analysis
pipeline and reports what it caught and what it wrongly flagged. It exists to make detection
changes measurable and to stop regressions — **it is not an estimate of real-world detection**.

```bash
cd backend
python -m benchmark.run                     # summary table
python -m benchmark.run -o report.json      # full JSON report
python -m benchmark.run --policy ../policies/staging.yaml
```

`tests/test_benchmark.py` runs it in CI and fails if detection drops below 0.9, the false-positive
rate rises above 0.125, or any of the listed hard benign samples is blocked.

## How it works

* **Corpus** — `backend/benchmark/corpus.py`: 22 hand-written packages, 14 malicious (4 of them
  written to evade simple pattern matching) and 8 benign. Malicious samples reproduce the *shape*
  of published techniques with inert content: hosts are under the reserved `.invalid` TLD and
  encoded payloads decode to a `print` call. Nothing is executed; the text is only analysed.
  Benign samples deliberately use the same modules and file types (a process call in `setup.py`,
  an editable-install `.pth`, base64 image data, an HTTP client).
* **Pipeline** — each sample is wrapped in an sdist-style directory and analysed by the normal
  `Orchestrator` with every registered analyzer, offline (no registry, intelligence or provenance
  calls). Every sample carries the registry facts of an established package (age, several
  maintainers, a source repository), so reputation findings do not inflate the scores.
* **Verdict** — the policy engine's built-in default policy. A malicious sample counts as detected
  when the decision is `warn` or `block`; a benign sample is a false positive when it is not `allow`.

## Results

Recorded in `backend/benchmark/results/latest.json` (benchmark version 1.0.0, default policy):

| | |
|---|---|
| Detection (malicious, 14) | **13 / 14 = 0.929** |
| Evasive variants (4) | 4 / 4 = 1.0 |
| False positives (benign, 8) | **1 / 8 = 0.125** (a `warn`, not a `block`) |

| Sample | Expected | Decision | Risk | Main findings |
|---|---|---|---|---|
| install-time network call | detect | block | 61 | INSTALL_HOOK_EXEC, NETWORK_EGRESS |
| install-time `exec(b64decode(...))` | detect | block | 100 | ATTACK_CHAIN, ENCODED_EXEC, YARA_MATCH |
| environment dump sent over HTTP | detect | warn | 47 | ENV_HARVEST, NETWORK_EGRESS |
| SSH private key read and sent over a socket | detect | **allow (missed)** | 33 | FS_SENSITIVE, NETWORK_EGRESS |
| `.pth` hook running an encoded payload | detect | block | 100 | PTH_STARTUP_HOOK, YARA_MATCH |
| in-tree PEP 517 backend piping curl to sh | detect | block | 85 | BUILD_BACKEND_HOOK, YARA_MATCH |
| console script named `pip` | detect | block | 40 | ENTRYPOINT_SHADOWING |
| reverse shell | detect | block | 80 | NETWORK_EGRESS, SUBPROCESS_EXEC, YARA_MATCH |
| install-time download and execute | detect | block | 100 | ATTACK_CHAIN |
| typosquat of `requests` | detect | warn | 47 | TYPOSQUAT, NETWORK_EGRESS |
| evasive: `getattr(__builtins__, 'ex' + 'ec')` | detect | block | 99 | ATTACK_CHAIN, DYNAMIC_EXEC |
| evasive: `__import__('urllib' + '.request')` | detect | block | 54 | INSTALL_HOOK_EXEC |
| evasive: hex-encoded payload | detect | block | 100 | DYNAMIC_EXEC, YARA_MATCH |
| evasive: aliased modules in a nested file | detect | warn | 47 | ENV_HARVEST, NETWORK_EGRESS |
| compiler call in `setup.py` | allow | **warn (false positive)** | 40 | INSTALL_HOOK_EXEC, SUBPROCESS_EXEC |
| other benign samples (7) | allow | allow | 0–20 | — |

### Known misses and why they stay

* **SSH key read + socket in a runtime module** is not escalated. The correlation engine requires
  corroboration (install-time context, evasion or a strong finding in the same file) before it
  turns a capability-grade network finding plus a credential-path reference into an attack chain,
  because legitimate SSH, deployment and upload tools do exactly this. Checked variants: the same
  code in `setup.py` forms the credential-exfiltration chain and is blocked (risk 100); the same
  module plus an `exec` of decoded data is blocked on its other findings (risk 96).
* **A process call in `setup.py`** warns. Running a process at install time is how every native
  extension build works, and it is also how droppers work; Warden surfaces it for review rather
  than blocking or ignoring it.

### With the shipped environment policies

`--policy ../policies/production.yaml` warns on every sample, benign included. That is the policy
working as written: an offline scan cannot verify distribution hashes or look up vulnerabilities,
and the production policy treats both unknowns as reasons to warn. The benchmark therefore uses the
default policy for its numbers.

## What the benchmark changed

Building it exposed real problems, all fixed in the same change set:

* With no registry metadata every sample scored 34 from reputation findings alone, and the ML
  model escalated small packages with only low-confidence findings into `block` (a compiler call
  scored 99). Model escalation is now capped below the high band unless a high or critical finding
  with confidence ≥ 0.7 supports it (`app/analysis/scoring.py`).
* The static analyzer did not recognise a serialised dump of the whole environment
  (`json.dumps(dict(os.environ))`, credential-filtered comprehensions), import aliases
  (`import os as _o`), socket connection calls, or `getattr` names assembled from string pieces.

## Limits

22 samples cannot represent the package ecosystem. The corpus was written by the same people who
wrote the analyzers, so it shares their blind spots. Treat the numbers as a regression baseline and
extend the corpus whenever a real-world technique is missed.
