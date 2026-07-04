# Contributing

Thanks for your interest in Warden. This guide gets you productive quickly.

## Development setup

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m ml.train      # build the model artifact
pytest -q               # everything runs offline on SQLite
```

Frontend:

```bash
cd frontend && npm install && npm run dev
```

## Standards

- **Lint**: `ruff check .` (backend) must pass. Config in `backend/pyproject.toml`.
- **Security**: `bandit -r app -x tests` must pass; new dependencies are audited with
  `pip-audit`.
- **Tests**: add or update tests for any behaviour change. The suite must stay green and
  fully offline (mock the network; never hit real PyPI in tests).
- **Types**: backend uses pydantic v2 + SQLAlchemy typed models; frontend is strict
  TypeScript.

## Adding a new analyzer

1. Create `backend/app/analysis/analyzers/<name>.py` implementing the `Analyzer` protocol
   (`analyze(ctx) -> list[Signal]`). Analyzers must be pure and must not execute package
   code or perform network I/O.
2. Register it in `analyzers/__init__.py`.
3. If it introduces new numeric information, extend `features.py` (append to
   `FEATURE_ORDER` — never reorder) and retrain.
4. Add unit tests with in-memory `PackageContext` inputs.

## Adding a new ecosystem (e.g. npm)

The `Analyzer`/`PackageContext` abstractions are ecosystem-agnostic. Implement a fetcher
that populates `PackageContext.files` and metadata, and gate it behind the `ecosystem`
field validated in `schemas/scan.py`.

## Commit style

Small, focused commits with imperative messages (`Add npm fetcher`, `Fix Zip-Slip guard`).
CI (lint, security, tests, build) must pass before merge.
