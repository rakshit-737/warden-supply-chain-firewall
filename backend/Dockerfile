# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# Warden API image.
#
# Supply chain
# * Base images are pinned by the digest of their multi-arch image index; the tag is kept only for
#   readability (when a digest is given, it alone selects the image). Digests were resolved from
#   registry-1.docker.io on 2026-09-15 (see deploy/README.md for the command and how to bump them).
#   python:3.12.14-slim-trixie was the same index as python:3.12-slim on that date.
# * Python dependencies are version-pinned in requirements.txt but NOT hash-pinned (no
#   --require-hashes), so this build does not detect a tampered artifact for a pinned version.
#
# Runtime hardening
# * Multi-stage: compilers and build headers exist only in the builder stage.
# * The app runs as UID/GID 10001 with no login shell and no home directory.
# * Code, virtualenv and model artifact are owned by root and not writable by the app user;
#   bytecode is precompiled so the container works with a read-only root filesystem.

# ---- Stage 1: dependencies + model training --------------------------------------------------
FROM python:3.12.14-slim-trixie@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build tooling for any dependency that has no prebuilt wheel for the target platform.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Dependencies go into a self-contained virtualenv that is copied into the runtime stage as-is
# (same base image digest, so the interpreter path the venv points at is identical).
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

WORKDIR /src
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Train and persist the model artifact at build time (seeded; same parameters as before).
COPY app ./app
COPY ml ./ml
RUN PYTHONPATH=/src python -m ml.train --n 6000 --seed 1337 \
    && test -s app/analysis/artifacts/model.joblib

# Nothing at runtime installs packages: drop pip from the virtualenv before it is copied.
RUN python -m pip uninstall --yes pip

# ---- Stage 2: runtime (no compilers) ---------------------------------------------------------
FROM python:3.12.14-slim-trixie@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS runtime

LABEL org.opencontainers.image.title="warden-api" \
      org.opencontainers.image.description="Warden software supply-chain security API" \
      org.opencontainers.image.source="https://github.com/rakshit-737/warden-supply-chain-security" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12.14-slim-trixie" \
      org.opencontainers.image.base.digest="sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"

# UVICORN_WORKERS: Prometheus metrics live in a per-process registry (app/core/metrics.py), so with
#   several workers each scrape would see only one worker's counters. Default 1; scale out with
#   more containers instead.
# FORWARDED_ALLOW_IPS: peers whose X-Forwarded-For/-Proto uvicorn honours. The default trusts only
#   the container itself; docker-compose.yml sets it to the web (nginx) container's fixed address.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    TMPDIR=/tmp \
    ENV=production \
    UVICORN_WORKERS=1 \
    FORWARDED_ALLOW_IPS=127.0.0.1

# Apply Debian security updates at build time. The base is pinned by digest for reproducibility,
# but upstream rebuilds lag behind Debian's security fixes: the CI Trivy gate found fixable
# CRITICAL/HIGH issues (perl-base, gzip, libpcre2, libsqlite3) in the newest published digest.
# Upgrading here closes that gap; the Trivy gate still verifies the result on every build.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime identity: fixed UID/GID 10001, no home directory, no login shell. The
# analyzer ingests hostile archives, so it must never run as root. The base image's pip is removed
# as well (less tooling left in the image; this is hygiene, not a security boundary).
RUN groupadd --gid 10001 warden \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --no-log-init warden \
    && python -m pip uninstall --yes pip

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic
COPY cli ./cli
COPY app ./app
# The build-trained model is copied after `app`, so a stale workstation artifact can never replace
# it (backend/.dockerignore also keeps local artifacts out of the build context).
COPY --from=builder /src/app/analysis/artifacts ./app/analysis/artifacts

# Precompile bytecode at build time (as root) so the read-only runtime never needs to write .pyc
# files, then clear group/other write bits. Files stay owned by root: the app user can read and
# execute them but cannot modify them.
RUN python -m compileall -q /app \
    && chmod -R go-w /app /opt/venv

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=4).status == 200 else 1)"]

# The API process only. Database migrations are a separate step so that several api containers never
# apply them concurrently: docker-compose.yml runs `alembic upgrade head` once, in its one-shot
# `migrate` service, before any api container starts. Without Compose, run this image once with the
# command `alembic upgrade head` before starting it. `exec` replaces the shell so uvicorn receives
# stop signals.
# --timeout-keep-alive 75 exceeds nginx's 60s upstream keepalive_timeout, so nginx never reuses a
# connection uvicorn has just closed (which would surface as sporadic 502s).
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers \"${UVICORN_WORKERS}\" --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS}\" --timeout-keep-alive 75 --no-server-header"]
