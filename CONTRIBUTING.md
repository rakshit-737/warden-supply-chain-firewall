# Contributing

## Setup

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt                 # optional: pip install -r requirements-optional.txt (YARA)
python -m ml.train --n 4000                         # builds the model artifact
pytest -q                                           # offline; a test that touches the network fails
```

```bash
cd frontend
npm ci
npm run lint && npm run typecheck && npm run test && npm run build
```

## Standards

- **Backend** — `ruff check .` and `bandit -q -r app -x tests` must pass; justify any `# nosec` on the
  same line. `pip-audit --strict -r requirements.txt` must stay clean.
- **Frontend** — ESLint with zero warnings; no rules disabled to get green; no raw HTML sinks.
- **Tests** — every behaviour change needs a test. Security-sensitive code needs adversarial tests,
  and every detector needs false-positive tests built from realistic benign code. Tests stay offline:
  mock HTTP with `respx`.
- **Fake credentials in tests** are assembled at runtime (for example `"gh" + "p_" + "A" * 36`) so
  secret scanners and GitHub push protection never see a literal token.
- **Honest language** — "designed to detect", never "detects all". Metrics from synthetic data are
  labelled as such.

## Adding an analyzer

1. Subclass `BaseAnalyzer` in `backend/app/analysis/analyzers/`, set `name` and `version`, and return
   `Finding` objects. Never execute package code; declare `requires_network` if you need intelligence,
   and implement `availability()` if you depend on an external tool.
2. Use codes from `app/analysis/signals.py`; register new codes with `taxonomy.register(...)`,
   including only defensible CWE and ATT&CK mappings.
3. Choose confidence deliberately: policy rules only fire at or above the configured confidence.
   Record `evidence["context"]` and real line numbers.
4. Register the analyzer in `analyzers/__init__.py`, and add its name to the risk dimension it feeds.
5. If it adds model-relevant information, append a feature in `features.py` (never reorder), extend
   the generator, retrain, and consider re-measuring the real-package corpus
   (`python -m ml.collect_real_features`).

## Commits

Small, focused commits with conventional prefixes (`feat:`, `fix:`, `security:`, `docs:`, `test:`).
CI (lint, security, tests, migrations, frontend, images) must pass before merge.
