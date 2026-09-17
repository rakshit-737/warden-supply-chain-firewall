# Getting started

## Try it with demo data

```bash
git clone https://github.com/rakshit-737/warden-supply-chain-security
cd warden-supply-chain-security
cd backend && pip install -r requirements-dev.txt && cd ..
make train      # builds the ML model artifact
make demo       # fills a local SQLite database with real results from the inert benchmark samples
make run        # API on http://localhost:8000
```

In a second terminal:

```bash
cd frontend && npm install && npm run dev   # console on http://localhost:5173
```

Sign in with the development admin account printed by `make demo` (the password is
`FIRST_ADMIN_PASSWORD`; change both before exposing anything).

!!! note
    The demo packages are named `demo-…` (plus one deliberate typosquat, `reqeusts`). They are
    hand-written, inert samples, not packages from PyPI.

## Run the full stack

```bash
cp .env.example .env          # fill in every required value; the stack refuses to start otherwise
docker compose up -d --build
```

The console is on <http://127.0.0.1:8080>. Optional profiles add Prometheus and Grafana
(`--profile observability`) and the monitoring worker (`--profile worker`). Deployment details,
hardening and scaling are described in
[`deploy/README.md`](https://github.com/rakshit-737/warden-supply-chain-security/blob/main/deploy/README.md).

## Scan your first project without a server

```bash
cd backend
python -m cli.warden_cli project scan /path/to/your/project
python -m cli.warden_cli sbom generate /path/to/your/project --format cyclonedx -o bom.json
```

Nothing from the project is installed or executed. See the [CLI reference](cli.md) for every command.

## Configure a policy

Policies are YAML documents with thresholds, deny rules and required controls per environment
(`policies/development.yaml`, `staging.yaml`, `production.yaml`). Validate one before loading it:

```bash
python -m cli.warden_cli policy validate ../policies/production.yaml
```

Load and activate policies through the console (Policies) or `POST /api/v1/policies`.
