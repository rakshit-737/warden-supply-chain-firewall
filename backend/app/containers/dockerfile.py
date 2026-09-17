"""Static checks for Dockerfiles and Docker Compose files.

The checks read text only; they never build, pull or run anything. Each rule is designed to catch
a common supply-chain or hardening mistake, not to prove an image safe:

* ``DOCKERFILE_UNPINNED_BASE`` (low) - ``FROM`` without an ``@sha256:`` digest. ``scratch`` and
  references to earlier build stages are exempt; images built from ``ARG`` values are reported
  with lower confidence because the digest may be supplied at build time.
* ``DOCKERFILE_ROOT_USER`` (medium) - the final stage never switches to a non-root ``USER``.
* ``DOCKERFILE_REMOTE_ADD`` (medium) - ``ADD`` of an ``http(s)`` URL without ``--checksum``.
* ``DOCKERFILE_CURL_PIPE_SHELL`` (high) - a ``RUN`` step that pipes ``curl``/``wget`` output into a
  shell or interpreter.
* ``DOCKERFILE_SECRET_IN_ENV`` (high) - an ``ENV``/``ARG`` (or Compose ``environment``) literal
  under a secret-like name, or any value matching a known credential format. The value itself is
  never reported.
* ``COMPOSE_PRIVILEGED`` (high), ``COMPOSE_DOCKER_SOCKET`` (high), ``COMPOSE_HOST_NETWORK``
  (medium) - dangerous service settings.

Compose service ``image:`` values without a digest are reported as ``DOCKERFILE_UNPINNED_BASE``
unless the service also has a ``build:`` section.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable
from typing import Any

import yaml

from app.analysis.findings import Finding, Location, Provenance, Severity
from app.analysis.signals import Code
from app.core.redaction import find_secrets, sanitize_text

ANALYZER_NAME = "container-config"
ANALYZER_VERSION = "1.0.0"

MAX_INPUT_BYTES = 1_000_000

_INSTRUCTION_RE = re.compile(r"^\s*([A-Za-z]+)(?:\s+(.*))?$", re.DOTALL)
_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:env\s+\S+\s+)?"
    r"(?:/usr/bin/|/bin/)?(?:sh|bash|zsh|dash|ash|ksh|python[0-9.]*|perl|ruby|node)\b"
)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
# ${NAME} or $NAME. The brace body is bounded and cannot contain another "$", so unterminated input such
# as "${{${{${{..." is scanned in linear time (CodeQL py/polynomial-redos).
_VARIABLE_RE = re.compile(r"\$(?:\{[^}$]{0,256}\}|[A-Za-z_][A-Za-z0-9_]*)")
# Variable names that hold a credential: the secret word ends the name (DB_PASSWORD, GITHUB_TOKEN),
# so settings such as COOKIE_SAMESITE or TOKEN_TTL are not mistaken for secrets.
_SECRET_NAME_RE = re.compile(
    r"(?i)(?:^|[_.-])(?:pass(?:word|wd|phrase)?|secret(?:_?key)?|token|api_?key|private_?key|access_?key"
    r"|client_?secret|credentials?|auth_?key)$"
)
_ROOT_USERS = frozenset({"root", "0", "0:0", "root:root", "root:0", "0:root"})
_PLACEHOLDERS = frozenset({"", "changeme", "change-me", "example", "placeholder", "xxx", "none", "null", "dummy"})


# "Dockerfile.<variant>" is a Dockerfile; "dockerfile.py" or "dockerfile.md" is source or documentation.
_NOT_DOCKERFILE_SUFFIXES = frozenset({
    "py", "pyc", "js", "ts", "tsx", "jsx", "go", "rs", "java", "rb", "sh", "md", "rst", "txt", "json", "yml",
    "yaml", "toml", "cfg", "ini", "html", "lock", "bak", "orig", "swp",
})


def is_dockerfile(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name == "dockerfile" or name.endswith(".dockerfile"):
        return True
    return name.startswith("dockerfile.") and name.rsplit(".", 1)[-1] not in _NOT_DOCKERFILE_SUFFIXES


def is_compose_file(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} or (
        name.startswith(("docker-compose.", "compose.")) and name.endswith((".yml", ".yaml"))
    )


def _finding(code: str, severity: Severity, message: str, evidence: dict, file: str, line: int | None,
             confidence: float = 0.9) -> Finding:
    return Finding(code, severity, 1.0, sanitize_text(message, max_len=300), evidence, confidence=confidence,
                   location=Location(file=file, line=line), provenance=Provenance.STATIC,
                   ).with_defaults(analyzer=ANALYZER_NAME, analyzer_version=ANALYZER_VERSION)


def looks_like_secret(key: str, value: str) -> bool:
    """True when ``value`` under variable ``key`` looks like a baked-in credential (never logs it)."""
    if find_secrets(value):
        return True
    literal = value.strip().strip("'\"")
    if not _SECRET_NAME_RE.search(key) or literal.lower() in _PLACEHOLDERS or _VARIABLE_RE.fullmatch(literal):
        return False
    # A value that only references a variable or a file path is not a baked-in secret.
    return not literal.startswith(("/", "$")) and len(literal) >= 6


# --------------------------------------------------------------------------- Dockerfile
def _logical_lines(text: str) -> Iterable[tuple[int, str]]:
    """Yield (first line number, joined instruction), honouring ``\\`` continuations and comments."""
    buffer: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if buffer and stripped.startswith("#"):
            continue  # comment lines inside a continued instruction are ignored by Docker
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1])
            continue
        buffer.append(stripped)
        yield start, " ".join(buffer)
        buffer = []
    if buffer:
        yield start, " ".join(buffer)


def _env_pairs(args: str) -> list[tuple[str, str]]:
    try:
        tokens = shlex.split(args, posix=True)
    except ValueError:
        tokens = args.split()
    if len(tokens) >= 2 and "=" not in tokens[0]:
        return [(tokens[0], " ".join(tokens[1:]))]  # legacy "ENV KEY value"
    pairs = []
    for token in tokens:
        key, sep, value = token.partition("=")
        pairs.append((key, value if sep else ""))
    return pairs


def lint_dockerfile(text: str, path: str = "Dockerfile") -> list[Finding]:
    text = text[:MAX_INPUT_BYTES]
    findings: list[Finding] = []
    stages: list[str] = []
    final_user: tuple[str, int] | None = None
    final_from_line = 0

    for line, instruction in _logical_lines(text):
        match = _INSTRUCTION_RE.match(instruction)
        if not match:
            continue
        keyword, args = match.group(1).upper(), (match.group(2) or "").strip()

        if keyword == "FROM":
            parts = [p for p in args.split() if not p.startswith("--")]
            image = parts[0] if parts else ""
            lowered = image.lower()
            earlier_stage = lowered in stages
            if len(parts) >= 3 and parts[1].lower() == "as":
                stages.append(parts[2].lower())
            final_user, final_from_line = None, line
            if lowered == "scratch" or earlier_stage:
                continue
            if "@sha256:" not in lowered:
                from_arg = bool(_VARIABLE_RE.search(image))
                findings.append(_finding(
                    Code.DOCKERFILE_UNPINNED_BASE, Severity.low,
                    f"Base image '{image}' is not pinned by digest", {"image": sanitize_text(image, max_len=200),
                                                                      "from_build_arg": from_arg},
                    path, line, confidence=0.5 if from_arg else 0.95,
                ))
        elif keyword == "USER":
            final_user = (args.split()[0] if args else "", line)
        elif keyword == "ADD":
            tokens = args.split()
            has_checksum = any(t.startswith("--checksum") for t in tokens)
            sources = [t for t in tokens if not t.startswith("--")][:-1]
            for source in sources:
                if _URL_RE.match(source) and not has_checksum:
                    findings.append(_finding(
                        Code.DOCKERFILE_REMOTE_ADD, Severity.medium,
                        "ADD downloads a remote URL without a pinned checksum",
                        {"url": sanitize_text(source, max_len=300)}, path, line,
                    ))
        elif keyword == "RUN":
            if _PIPE_TO_SHELL_RE.search(args):
                findings.append(_finding(
                    Code.DOCKERFILE_CURL_PIPE_SHELL, Severity.high,
                    "RUN pipes downloaded content straight into a shell or interpreter",
                    {"command": sanitize_text(args, max_len=200)}, path, line,
                ))
        elif keyword in ("ENV", "ARG"):
            for key, value in _env_pairs(args):
                if value and looks_like_secret(key, value):
                    findings.append(_finding(
                        Code.DOCKERFILE_SECRET_IN_ENV, Severity.high,
                        f"{keyword} {key} bakes a secret-like literal into the image",
                        {"instruction": keyword, "name": sanitize_text(key, max_len=100)}, path, line,
                        confidence=0.9 if find_secrets(value) else 0.7,
                    ))

    if final_from_line:
        user = final_user[0].strip("'\"").lower() if final_user else None
        if user is None or user in _ROOT_USERS:
            findings.append(_finding(
                Code.DOCKERFILE_ROOT_USER, Severity.medium,
                "The final stage runs as root" if user else "The final stage never sets a non-root USER",
                {"user": user or "(default: root)"}, path,
                final_user[1] if final_user else final_from_line,
            ))
    return findings


# --------------------------------------------------------------------------- Compose
def _line_of(node: Any) -> int | None:
    mark = getattr(node, "start_mark", None)
    return mark.line + 1 if mark is not None else None


def _mapping(node: Any) -> dict[str, tuple[Any, Any]]:
    """{key: (key node, value node)} for a YAML mapping node."""
    if not isinstance(node, yaml.MappingNode):
        return {}
    return {str(k.value): (k, v) for k, v in node.value if isinstance(k, yaml.ScalarNode)}


def _scalar(node: Any) -> str | None:
    return str(node.value) if isinstance(node, yaml.ScalarNode) else None


def lint_compose(text: str, path: str = "docker-compose.yml") -> list[Finding]:
    try:
        root = yaml.compose(text[:MAX_INPUT_BYTES], Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return [_finding(Code.CONTAINER_MISCONFIG, Severity.low, "Compose file could not be parsed",
                         {"check": "parse_error"}, path, None, confidence=0.5)]
    services = _mapping(root).get("services")
    if not services:
        return []
    findings: list[Finding] = []
    for name, (_, service) in sorted(_mapping(services[1]).items()):
        fields = _mapping(service)
        label = sanitize_text(name, max_len=100)
        privileged = fields.get("privileged")
        if privileged and (_scalar(privileged[1]) or "").lower() == "true":
            findings.append(_finding(Code.COMPOSE_PRIVILEGED, Severity.high,
                                     f"Service '{label}' runs privileged", {"service": label}, path,
                                     _line_of(privileged[0])))
        network = fields.get("network_mode")
        if network and (_scalar(network[1]) or "").lower() == "host":
            findings.append(_finding(Code.COMPOSE_HOST_NETWORK, Severity.medium,
                                     f"Service '{label}' uses the host network", {"service": label}, path,
                                     _line_of(network[0])))
        volumes = fields.get("volumes")
        for item in (volumes[1].value if volumes and isinstance(volumes[1], yaml.SequenceNode) else []):
            source = _scalar(item) or _scalar(_mapping(item).get("source", (None, None))[1]) or ""
            if "docker.sock" in source:
                findings.append(_finding(Code.COMPOSE_DOCKER_SOCKET, Severity.high,
                                         f"Service '{label}' mounts the Docker socket",
                                         {"service": label, "mount": sanitize_text(source, max_len=200)},
                                         path, _line_of(item)))
        image = fields.get("image")
        image_ref = _scalar(image[1]) if image else None
        if image_ref and "build" not in fields and "@sha256:" not in image_ref.lower():
            findings.append(_finding(Code.DOCKERFILE_UNPINNED_BASE, Severity.low,
                                     f"Service '{label}' image '{image_ref}' is not pinned by digest",
                                     {"service": label, "image": sanitize_text(image_ref, max_len=200)},
                                     path, _line_of(image[0]),
                                     confidence=0.5 if _VARIABLE_RE.search(image_ref) else 0.95))
        environment = fields.get("environment")
        for key, value, node in _environment(environment[1] if environment else None):
            if value and looks_like_secret(key, value):
                findings.append(_finding(Code.DOCKERFILE_SECRET_IN_ENV, Severity.high,
                                         f"Service '{label}' sets {key} to a secret-like literal",
                                         {"service": label, "name": sanitize_text(key, max_len=100)},
                                         path, _line_of(node), confidence=0.9 if find_secrets(value) else 0.7))
    return findings


def _environment(node: Any) -> Iterable[tuple[str, str, Any]]:
    if isinstance(node, yaml.MappingNode):
        for key, (k, v) in _mapping(node).items():
            yield key, _scalar(v) or "", k
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            key, _, value = (_scalar(item) or "").partition("=")
            yield key, value, item


def lint_files(files: dict[str, str]) -> list[Finding]:
    """Lint every Dockerfile and Compose file in ``{path: text}``."""
    findings: list[Finding] = []
    for path in sorted(files):
        if is_dockerfile(path):
            findings.extend(lint_dockerfile(files[path], path))
        elif is_compose_file(path):
            findings.extend(lint_compose(files[path], path))
    return findings
