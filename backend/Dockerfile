# syntax=docker/dockerfile:1

# ---- Stage 1: build wheels & train the model -------------------------------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

COPY app ./app
COPY ml ./ml
# Train and persist the model artifact at build time (reproducible, seeded).
ENV PYTHONPATH=/app
RUN PATH="/install/bin:$PATH" PYTHONPATH="/install/lib/python3.12/site-packages:/app" \
    python -m ml.train --n 6000 --seed 1337

# ---- Stage 2: minimal runtime ---------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ENV=production
WORKDIR /app

# Create an unprivileged user — the analyzer ingests hostile archives, so it must never
# run as root.
RUN useradd --create-home --uid 10001 warden

COPY --from=builder /install /usr/local
COPY --from=builder /app/app/analysis/artifacts ./app/analysis/artifacts
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
COPY cli ./cli

USER warden
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live').status==200 else 1)"

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2"]
