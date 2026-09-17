"""Dockerfile and Compose linting (text only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.containers.dockerfile import is_compose_file, is_dockerfile, lint_compose, lint_dockerfile, lint_files

REPO = Path(__file__).resolve().parents[2]
FAKE_TOKEN = "gh" + "p_" + "E" * 36
DIGEST = "sha256:" + "a" * 64


def codes(findings) -> list[str]:
    return sorted(f.code for f in findings)


def test_hardened_dockerfile_is_clean():
    text = f"""
    # syntax=docker/dockerfile:1
    FROM python:3.12-slim@{DIGEST} AS builder
    RUN pip install --require-hashes -r requirements.txt
    FROM builder AS test
    FROM python:3.12-slim@{DIGEST}
    COPY --from=builder /app /app
    USER 10001:10001
    """
    assert lint_dockerfile(text) == []


def test_every_dockerfile_rule_fires_with_a_location():
    text = "\n".join([
        "FROM ubuntu:24.04",
        "ENV DB_PASSWORD=hunter2hunter2 \\",
        "    LOG_LEVEL=info",
        "ADD https://example.invalid/tool.tgz /opt/",
        "RUN apt-get update && \\",
        "    curl -fsSL https://example.invalid/install.sh | bash",
        "USER root",
    ])
    findings = {f.code: f for f in lint_dockerfile(text)}
    assert set(findings) == {"DOCKERFILE_UNPINNED_BASE", "DOCKERFILE_SECRET_IN_ENV", "DOCKERFILE_REMOTE_ADD",
                             "DOCKERFILE_CURL_PIPE_SHELL", "DOCKERFILE_ROOT_USER"}
    assert findings["DOCKERFILE_SECRET_IN_ENV"].location.line == 2
    assert findings["DOCKERFILE_CURL_PIPE_SHELL"].location.line == 5
    assert findings["DOCKERFILE_ROOT_USER"].location.line == 7
    assert "hunter2" not in json.dumps([f.to_dict() for f in findings.values()])


def test_missing_user_is_reported_at_the_final_from():
    findings = lint_dockerfile(f"FROM alpine@{DIGEST} AS a\nUSER app\nFROM alpine@{DIGEST}\nRUN true\n")
    assert codes(findings) == ["DOCKERFILE_ROOT_USER"] and findings[0].location.line == 3


@pytest.mark.parametrize("line", [
    "ADD --checksum=sha256:abc https://example.invalid/x /x",
    "ENV API_TOKEN=${API_TOKEN}",
    "ARG GITHUB_TOKEN",
    "ENV COOKIE_SAMESITE=strict",
    "ENV PASSWORD_FILE=/run/secrets/db",
    "ENV DB_PASSWORD=changeme",
    "RUN curl -fsSLo tool.sh https://example.invalid/tool.sh && sha256sum -c sums && sh tool.sh",
])
def test_safe_patterns_are_not_reported(line):
    text = f"FROM alpine@{DIGEST}\n{line}\nUSER app\n"
    assert lint_dockerfile(text) == []


def test_known_token_format_is_reported_under_any_name():
    findings = lint_dockerfile(f"FROM alpine@{DIGEST}\nENV SETTINGS={FAKE_TOKEN}\nUSER app\n")
    assert codes(findings) == ["DOCKERFILE_SECRET_IN_ENV"]
    assert FAKE_TOKEN not in json.dumps(findings[0].to_dict())


def test_build_arg_base_image_has_lower_confidence():
    finding = lint_dockerfile("ARG BASE\nFROM ${BASE}\nUSER app\n")[0]
    assert finding.code == "DOCKERFILE_UNPINNED_BASE" and finding.confidence == 0.5


def test_compose_rules():
    text = f"""
services:
  agent:
    image: example/agent:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      SECRET_KEY: s3cr3t-value-123
      LOG_LEVEL: debug
  web:
    build: .
    image: example/web
    environment:
      - API_TOKEN={FAKE_TOKEN}
  db:
    image: postgres:16@{DIGEST}
    environment:
      POSTGRES_PASSWORD: ${{POSTGRES_PASSWORD:?required}}
"""
    findings = lint_compose(text)
    assert codes(findings) == sorted(["COMPOSE_PRIVILEGED", "COMPOSE_HOST_NETWORK", "COMPOSE_DOCKER_SOCKET",
                                      "DOCKERFILE_UNPINNED_BASE", "DOCKERFILE_SECRET_IN_ENV",
                                      "DOCKERFILE_SECRET_IN_ENV"])
    lines = {f.code: f.location.line for f in findings}
    assert lines["COMPOSE_PRIVILEGED"] == 5 and lines["COMPOSE_DOCKER_SOCKET"] == 8
    dumped = json.dumps([f.to_dict() for f in findings])
    assert FAKE_TOKEN not in dumped and "s3cr3t" not in dumped


def test_unparseable_compose_is_reported_not_raised():
    findings = lint_compose("services: [unclosed")
    assert codes(findings) == ["CONTAINER_MISCONFIG"]


def test_compose_yaml_tags_are_never_constructed(monkeypatch):
    import os

    calls = []
    monkeypatch.setattr(os, "system", lambda *a: calls.append(a))
    # Composition builds a node tree only; no Python object behind a tag is ever created.
    assert lint_compose("services:\n  x: !!python/object/apply:os.system ['true']\n") == []
    assert calls == []


def test_file_name_detection():
    assert is_dockerfile("backend/Dockerfile") and is_dockerfile("Dockerfile.dev") and is_dockerfile("api.dockerfile")
    assert not is_dockerfile("docs/dockerfiles.md")
    assert is_compose_file("compose.yaml") and is_compose_file("docker-compose.prod.yml")
    assert not is_compose_file("config.yml")


def test_wardens_own_container_files_are_clean():
    files = {p: (REPO / p).read_text(encoding="utf-8")
             for p in ("backend/Dockerfile", "frontend/Dockerfile", "docker-compose.yml")}
    assert lint_files(files) == []
