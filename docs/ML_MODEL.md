# ML Model

## 1. What the model is for — and what it is not allowed to do

Warden's rule engine is transparent and deterministic, but rules are brittle to novel
*combinations* of weak signals and every weight is hand-tuned. The model exists to learn those
interactions. It is not allowed to decide a verdict on its own.

Two components serve a scan:

1. **Supervised probability** — a calibrated `RandomForestClassifier` over the feature vector.
2. **Unsupervised novelty** — an `IsolationForest` fitted on benign training rows, giving an
   anomaly score for vectors unlike anything seen in training.

Deterministic checks stay deterministic: typosquat distance, indicator matches, hash mismatches and
install-time execution are rules, not model outputs.

### The guardrail, and why it exists

Fusion is `max(rule, ml)` — the model can never lower a deterministic score. Measurement showed that
is not enough on its own. A model trained only on synthetic samples separated the synthetic classes
almost perfectly (hold-out PR-AUC ≈ 1.0) and *still* assigned ~0.99 malicious probability to
ordinary libraries such as `requests`, `jinja2` and `flask`, whose only unusual traits were a network
import, a dynamic-evaluation call and TLS keys inside their own test suites.

So `app/analysis/scoring.py` bounds model-only escalation: when the rule score is below
`ML_TRUSTED_RULE_SCORE` (35) the model may add at most `ML_ESCALATION_MARGIN` (25) points. A
model-only opinion therefore lands in the medium band — visible for review — instead of blocking a
build. Above that threshold the deterministic layer has real evidence and the model is free to
escalate.

## 2. Features

`app/analysis/features.py` reduces findings to a fixed, append-only vector identified by
`FEATURE_SET_VERSION` and a `feature_schema_hash` over the names and their order. Version 2 keeps the
v1 features and adds the phase-2 behavioural signals (attack chains, `.pth` startup hooks, build
backend hooks, persistence, browser credential access, download-and-execute, DNS exfiltration, shell
invocation, reflective execution, layered encoding, string reconstruction, secrets, binaries, nested
archives, hash mismatches, dependency confusion, dormancy, maintainer changes, yanked releases).

Two properties matter for correctness:

- **The same code builds features at training time and serving time**, so there is no train/serve
  skew.
- **Context is weighted.** A secret in a test fixture counts less than one in runtime code, and
  findings in test files are discounted. This is what stopped "ships TLS test certificates" from
  reading as "malicious".

Vulnerability findings are deliberately *not* features: vulnerability risk is scored separately, so
the behavioural model cannot be swayed by an unrelated CVE.

The model store refuses an artifact whose `feature_schema_hash` differs from the running code (it
falls back to rules-only and says why), and honours `MODEL_ARTIFACT_SHA256` when set. Loading a
joblib artifact is loading a pickle, so the artifact is treated as trusted input: it ships with the
image and is pinned by hash in deployments that care.

## 3. Training data

Two sources, mixed:

1. **Synthetic** (`ml/generate_dataset.py`) — seeded, versioned archetypes grounded in documented
   attack patterns (credential stealers, install-time droppers, obfuscated loaders, `.pth` hooks,
   build-backend hooks, typosquat and dependency-confusion payloads, browser stealers, persistence
   implants, takeover drift) and **hard negatives**: SDKs that read credentials and call the network,
   CLIs that spawn processes, namespace `.pth` files, compiled extensions, fresh releases, revived
   projects, and libraries that ship test-fixture credentials.
2. **Measured** (`ml/collect_real_features.py` → `ml/data/real_benign_features.csv`) — feature
   vectors produced by running Warden's own analyzers over established PyPI projects. Only numbers
   and package coordinates are stored: no third-party source, no finding evidence.

The measured rows are few next to thousands of synthetic ones, so `MixedDataset` gives them a
training weight (default 25). Their label is an *assumption* — these are long-established projects,
which is not a proof about any particular release — and that assumption is recorded in the CSV
header rather than hidden.

`CSVLabeledDataset` accepts an external labelled corpus in the same feature order, so swapping in a
real malicious dataset is a one-file change.

## 4. Training and evaluation

`python -m ml.train --n 4000` (`--no-measured` to ignore the measured corpus, `--csv` for an external
dataset) performs a stratified split, calibrates the forest with cross-validation, fits the isolation
forest on benign training rows, and writes `model.joblib`, `metrics.json` and a generated
`MODEL_CARD.md`.

Reported: accuracy, precision, recall, F1, ROC-AUC, PR-AUC, Brier score, a confusion matrix, a
calibration curve, a threshold table, impurity and permutation importances, plus per-group results so
the measured rows are visible separately.

**Every number is a synthetic hold-out result.** It describes how well the model separates
*generated* samples, and the artifacts label it that way. It is not evidence of real-world detection
rates, and the measured corpus is far too small to claim one.

Training is reproducible: same seed and dataset produce the same `model_version` (a hash of the
artifact bytes). Estimators predict single-threaded so that floating-point addition order cannot
change the artifact.

## 5. Serving and monitoring

- `predict` returns a 0–100 score plus an anomaly score; if the artifact is missing, stale or refused,
  scans continue rules-only and the scan records why.
- `app/analysis/explain.py` decomposes a prediction into per-feature contributions along the tree
  paths, which explain the *uncalibrated* forest probability — stated as such.
- `GET /ml/model` exposes metadata and metrics with their scope label. `GET /ml/drift` compares the
  population stability index of recent scan inputs against the training reference, for rows built by
  the current feature set only, and reports `insufficient_data` below 50 samples. Drift means inputs
  moved away from the training distribution — not that an attack happened.

## 6. Honest limitations

- Synthetic data cannot establish real-world precision or recall. The measured corpus corrects the
  most obvious distribution error; it does not turn these metrics into field results.
- Benign labels on measured packages are assumed from their standing, not verified.
- The model sees only Warden's own features, so anything the analyzers miss is invisible to it.
- A determined attacker who knows the feature set can aim to stay inside the benign region; that is
  why the deterministic layer, not the model, decides blocking.
