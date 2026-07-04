# ML Model

## 1. Why ML at all (and where it stops)

Warden's rule engine is deliberately transparent, but rules alone have two weaknesses:
they are brittle to novel combinations of weak signals, and a human must hand-tune every
weight. ML is used **only** where it adds value over rules:

1. **Supervised risk probability** — a `RandomForestClassifier` learns non-linear
   interactions between behavioural features (e.g. "network egress *and* base64 decode *and*
   a package under 7 days old" is far worse than the sum of its parts).
2. **Unsupervised novelty** — an `IsolationForest` flags packages whose feature vector is
   unlike anything in the benign training distribution, catching attacks that don't match
   any single rule.

ML is *not* used to replace the transparent rule score, and it is *not* used where a
simple deterministic check is sufficient (typosquat distance, IOC match). This is the
"ML only where it genuinely adds value" principle made concrete.

## 2. Feature vector

Signals from the analyzers are reduced to a fixed-length numeric vector
(`app/analysis/features.py`). Features are intentionally interpretable:

| Feature | Meaning |
|---------|---------|
| `install_hook_exec` | install-time code execution present (0/1) |
| `network_egress` | network calls in code (count, capped) |
| `subprocess_exec` | process spawning present (0/1) |
| `dynamic_exec` | `eval`/`exec`/`compile`/dynamic import count |
| `obfuscation_score` | entropy/encoding-chain score 0–1 |
| `env_harvest` | reads sensitive env vars / credential paths (0/1) |
| `fs_sensitive_write` | writes to sensitive filesystem paths (0/1) |
| `dangerous_import_count` | count of high-risk imports |
| `typosquat_distance` | min edit distance to a popular name (inverted) |
| `ioc_hits` | indicator matches (count) |
| `package_age_days` | age of the release (log-scaled) |
| `maintainer_count` | number of maintainers |
| `has_repo_url` | source repo declared (0/1) |
| `release_count` | total releases (maturity proxy) |

## 3. Training data

Real labelled malicious-package corpora exist but are not redistributable inside a public
portfolio repo. Warden therefore ships a **reproducible synthetic generator**
(`ml/generate_dataset.py`) that samples benign and malicious feature vectors from
distributions grounded in documented real-world attacks (install-time exfiltration,
typosquats, obfuscated loaders). The generator is seeded, so anyone who clones the repo
produces the identical dataset and model.

This is stated openly: the synthetic dataset demonstrates the *methodology and pipeline*
(feature engineering → training → calibration → persistence → serving). Swapping in a real
labelled corpus is a one-file change, and the roadmap's analyst-override feedback loop is
how a production deployment would grow a real dataset.

## 4. Training & evaluation

`ml/train.py`:

1. Generates the dataset (or loads a provided CSV).
2. Splits train/test, fits the `RandomForestClassifier`, calibrates probabilities.
3. Fits the `IsolationForest` on benign samples only.
4. Reports accuracy, precision, recall, F1, ROC-AUC, and the confusion matrix, plus
   feature importances.
5. Persists `model.joblib` (both estimators + the feature order + metadata) into
   `app/analysis/artifacts/`.

The API loads this artifact once at startup. If it is missing, the scorer **degrades
gracefully to rules-only** and logs a warning — the product still works, it just loses the
ML component. That graceful degradation is itself a deliberate reliability property.

## 5. Serving & explainability

At scan time the same `features.py` code builds the vector (no training/serving skew), the
model yields `ml_score = round(100 * P(malicious))`, and the dashboard displays the top
contributing features alongside the transparent rule signals. An operator therefore never
sees an unexplained number.

## 6. Honest limitations

- Synthetic training limits real-world precision claims; the pipeline, not the accuracy
  figure, is the deliverable.
- Random forests can be gamed by an attacker who knows the feature set; this is why ML
  *augments* rather than *replaces* rules and IOC matching, and why fusion is
  `max(rule, ml)`.
