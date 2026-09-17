"""End-to-end regression: planted fake secrets never leave Warden in recoverable form.

A package containing planted credentials is analysed by the real orchestrator with every registered
analyzer plus the secrets analyzer, a faked gitleaks run and two deliberately failing analyzers whose
exception text contains the secrets. The verdict is then persisted through the real API scan flow.

The test asserts that neither the full value of any planted secret nor any 16-character window of it
(beyond a public four-character type prefix such as ``ghp_``) appears in:

* the ``AnalysisResult`` JSON and the verdict-cache payload;
* API responses (``POST /scans``, ``GET /scans/{id}``, listings, stats, events, audit);
* any database row (every table, including ``signals``, ``scans`` JSON columns, ``audit_events`` and
  ``security_events``) and the raw SQLite database file;
* captured structlog output, stdlib logging records and stdout/stderr;
* the Prometheus ``/metrics`` exposition.

Every planted value is generated at runtime from a seeded RNG and string concatenation, so no literal
credential exists in the repository; none of them is real. The gitleaks report written by the fake tool is
a labelled TEST FIXTURE shaped like gitleaks v8 JSON output — deliberately *unredacted* (raw values in
``Secret``/``Match``) to prove the adapter never reads those fields. Nothing in the package is executed.
"""

from __future__ import annotations

import json
import logging
import os
import random
import string
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pytest
import structlog

from app.analysis import analyzers as registry
from app.analysis import scoring, tools
from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, ScanOptions, SourceFile, ToolStatus
from app.analysis.analyzers.secrets import SecretsAnalyzer
from app.analysis.orchestrator import Orchestrator
from app.analysis.tools import ToolNotFoundError, ToolResult
from app.api.routers import scans as scans_router
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from tests.conftest import auth

# Split so repository secret scanners do not treat the synthetic fixtures as real credentials.
_SA_TYPE = "service" + "_account"

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
HEX = "0123456789abcdef"
B64 = ALNUM + "+/"
WINDOW = 16
_PRINT_LOGGER_METHODS = ("msg", "log", "debug", "info", "warn", "warning", "err", "error", "critical", "exception",
                         "fatal", "failure")


# --------------------------------------------------------------------------- planted package
@dataclass(frozen=True)
class Planted:
    name: str
    value: str
    public_prefix: int = 0  # leading characters that are a documented type marker (``ghp_``), not secret

    def fragments(self) -> list[str]:
        value = self.value
        out = [value]
        last = max(self.public_prefix, len(value) - WINDOW)
        out.extend(value[i:i + WINDOW] for i in range(self.public_prefix, last + 1, WINDOW // 2))
        out.append(value[last:last + WINDOW])
        return sorted({f for f in out if len(f) >= 12})


@dataclass
class PlantedPackage:
    secrets: list[Planted]
    files: dict[str, str]
    binaries: dict[str, bytes]
    crash_message: str
    raw: dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(cls, seed: int = 424242) -> PlantedPackage:
        rng = random.Random(seed)

        def rand(alphabet: str, n: int) -> str:
            return "".join(rng.choice(alphabet) for _ in range(n))

        def mixed(alphabet: str, n: int) -> str:
            while True:
                value = rand(alphabet, n)
                if any(c.isupper() for c in value) and any(c.islower() for c in value) and \
                        any(c.isdigit() for c in value):
                    return value

        raw = {
            "github_token": "gh" + "p_" + rand(ALNUM, 36),
            "aws_access_key_id": "AK" + "IA" + rand(UPPER_DIGITS, 16),
            "aws_secret_access_key": mixed(B64, 40),
            "db_password": rand(ALNUM, 12) + "-" + rand(ALNUM, 8),
            "generic_secret": mixed(ALNUM + "#!", 30),
            "slack_app_token": "xa" + "pp-1-" + rand(UPPER_DIGITS, 11) + "-" + rand(string.digits, 13) + "-"
                               + rand(HEX, 64),
            "sendgrid_api_key": "S" + "G." + rand(ALNUM + "_-", 22) + "." + rand(ALNUM + "_-", 43),
            "azure_account_key": rand(B64, 86) + "==",
            "stripe_secret_key": "sk" + "_live_" + rand(ALNUM, 24),
            "bearer_token": mixed(ALNUM, 40),
        }
        pem_lines = [rand(B64, 64) for _ in range(12)]
        armour = "PRIV" + "ATE KEY-----"
        pem = "-----BEGIN " + armour + "\n" + "\n".join(pem_lines) + "\n-----END " + armour + "\n"

        settings_py = (
            '"""Service settings for leaky-demo (test fixture with planted fake secrets)."""\n'
            "import os\n"
            f"GITHUB_TOKEN = '{raw['github_token']}'\n"
            f"AWS_ACCESS_KEY_ID = '{raw['aws_access_key_id']}'\n"
            f"AWS_SECRET_ACCESS_KEY = '{raw['aws_secret_access_key']}'\n"
            f"DATABASE_URL = 'postgresql://svc_app:{raw['db_password']}@db.prod.internal:5432/app'\n"
            f"API_SECRET = '{raw['generic_secret']}'\n"
            f"SLACK_APP_TOKEN = '{raw['slack_app_token']}'\n"
            "DEBUG = os.environ.get('DEBUG') == '1'\n"
        )
        client_py = (
            "import requests\n"
            "\n"
            f"HEADERS = {{'Authorization': 'Bearer {raw['bearer_token']}'}}\n"
            f"SENDGRID_API_KEY = '{raw['sendgrid_api_key']}'\n"
            "\n"
            "def notify(url, payload):\n"
            "    return requests.post(url, json=payload, headers=HEADERS, timeout=5)\n"
        )
        service_account = json.dumps({
            "type": _SA_TYPE, "project_id": "leaky-demo", "private_key_id": rand(HEX, 40),
            "private_key": pem, "client_email": "deploy@leaky-demo.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        }, indent=2)
        conn_cfg = ("DefaultEndpointsProtocol=https;AccountName=leakydemo;"
                    f"AccountKey={raw['azure_account_key']};EndpointSuffix=core.windows.net\n")
        files = {
            "setup.py": (
                "from setuptools import setup\n\n"
                "setup(name='leaky-demo', version='1.0.0', packages=['leaky'])\n"
            ),
            "leaky/__init__.py": "from leaky.client import notify\n",
            "leaky/settings.py": settings_py,
            "leaky/client.py": client_py,
            "leaky/conn.cfg": conn_cfg,
            "leaky/keys/service-account.json": service_account,
        }
        binary = (b"\x7fELF\x02\x01\x01" + b"\x00" * 57 + b"STRIPE_KEY=" + raw["stripe_secret_key"].encode()
                  + b"\x00" * 32)
        binaries = {"leaky/_speedups.cpython-312-x86_64-linux-gnu.so": binary}

        prefixed = {"github_token", "aws_access_key_id", "slack_app_token", "stripe_secret_key"}
        secrets = [Planted(name, value, 4 if name in prefixed else 0) for name, value in raw.items()]
        secrets.extend(Planted(f"private_key_line_{i}", line) for i, line in enumerate(pem_lines))
        crash_message = (
            f"could not parse leaky/settings.py: GITHUB_TOKEN={raw['github_token']} "
            f"API_SECRET={raw['generic_secret']} dsn=postgresql://svc_app:{raw['db_password']}@db.prod.internal"
        )
        return cls(secrets=secrets, files=files, binaries=binaries, crash_message=crash_message, raw=raw)

    def context(self, name: str, version: str) -> PackageContext:
        return PackageContext(
            ecosystem="pypi", name=name, version=version,
            files=[SourceFile(relpath=k, text=v, size=len(v)) for k, v in self.files.items()],
            binaries=dict(self.binaries),
        )

    def leaks(self, sinks: dict[str, str]) -> list[tuple[str, str]]:
        """``(secret name, sink)`` pairs where a planted value (or a window of it) was found.

        Returns names only: a failing assertion must not print the secret or the sink content.
        """
        found: list[tuple[str, str]] = []
        for sink, blob in sinks.items():
            for planted in self.secrets:
                if any(fragment in blob for fragment in planted.fragments()):
                    found.append((planted.name, sink))
        return found


# --------------------------------------------------------------------------- fakes
class PlantedFetcher:
    def __init__(self, package: PlantedPackage) -> None:
        self.package = package

    def build_context(self, name, version, options=None):
        return self.package.context(name, version or "1.0.0")


class LeakyCrash(BaseAnalyzer):
    """Raises an exception whose message contains planted secrets."""

    name = "leaky_crash"
    version = "0.0.1"

    def __init__(self, message: str) -> None:
        self._message = message

    def analyze(self, ctx):
        raise RuntimeError(self._message)


class LeakyAvailability(BaseAnalyzer):
    """Fails in ``availability()`` with planted secrets in the exception message."""

    name = "leaky_availability"
    version = "0.0.1"

    def __init__(self, message: str) -> None:
        self._message = message

    def availability(self):
        raise ValueError(self._message)

    def analyze(self, ctx):  # pragma: no cover - never reached
        return []


class NoModel:
    available = False
    metadata: dict = {}

    def predict(self, features):
        return 0, 0.0


class RecordingCache:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.sets = 0

    def get_json(self, key):
        raw = self.store.get(key)
        return json.loads(raw) if raw else None

    def set_json(self, key, value, ttl):
        self.store[key] = json.dumps(value, default=str)
        self.sets += 1


def _is_gitleaks(binary: str) -> bool:
    return Path(str(binary)).name.lower().startswith("gitleaks")


def arm_fake_gitleaks(monkeypatch, package: PlantedPackage) -> list[list[str]]:
    """gitleaks "available"; its run writes an unredacted report FIXTURE. Other tools stay unavailable."""
    calls: list[list[str]] = []
    monkeypatch.setattr(settings, "GITLEAKS_ENABLED", True)
    monkeypatch.setattr(tools, "find_tool", lambda binary, **kw: ToolStatus(
        name=Path(str(binary)).name, available=_is_gitleaks(binary), version="8.21.2" if _is_gitleaks(binary) else None,
        detail=None if _is_gitleaks(binary) else "not found on PATH"))

    def fake_run_tool(argv, *, timeout, cwd=None, extra_env=None, max_output_bytes=None):
        if not argv or not _is_gitleaks(argv[0]) or "--report-path" not in argv:
            raise ToolNotFoundError("executable not found")
        calls.append(list(argv))
        root = Path(cwd)
        raw = package.raw
        settings_path = root / "leaky" / "settings.py"
        # TEST FIXTURE shaped like a gitleaks v8 report, deliberately unredacted.
        report = [
            {"RuleID": "github-pat", "Description": "GitHub Personal Access Token", "StartLine": 3, "EndLine": 3,
             "StartColumn": 17, "EndColumn": 56, "Match": f"GITHUB_TOKEN = '{raw['github_token']}'",
             "Secret": raw["github_token"], "Line": f"GITHUB_TOKEN = '{raw['github_token']}'",
             "File": str(settings_path), "Entropy": 4.9, "Tags": [], "Commit": "",
             "Fingerprint": f"{settings_path}:github-pat:3"},
            {"RuleID": "adafruit-api-key", "Description": "Adafruit API Key", "StartLine": 1, "EndLine": 1,
             "Match": raw["azure_account_key"], "Secret": raw["azure_account_key"], "File": "./leaky/conn.cfg",
             "Entropy": 5.1, "Tags": []},
        ]
        Path(argv[argv.index("--report-path") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return ToolResult(0, "", "", False, 7, False)

    monkeypatch.setattr(tools, "run_tool", fake_run_tool)
    return calls


def selected_analyzers(crash_message: str | None) -> list:
    chosen = [a for a in registry.all_analyzers() if registry.normalize_analyzer_name(a.name) != "secrets"]
    chosen.append(SecretsAnalyzer())
    if crash_message is not None:
        chosen.extend([LeakyCrash(crash_message), LeakyAvailability(crash_message)])
    return chosen


@pytest.fixture()
def structlog_lines(monkeypatch) -> list[str]:
    """Every rendered structlog line, whichever (possibly cached) logger emitted it."""
    lines: list[str] = []
    for method in _PRINT_LOGGER_METHODS:
        original = getattr(structlog.PrintLogger, method, None)
        if original is None:
            continue

        def recorder(self, message="", *args, _original=original, **kwargs):
            lines.append(str(message))
            return _original(self, message, *args, **kwargs)

        monkeypatch.setattr(structlog.PrintLogger, method, recorder)
    return lines


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.setattr(scoring, "get_model_store", lambda: NoModel())
    monkeypatch.setattr(settings, "INTEL_OFFLINE", True)


def dump_database() -> str:
    chunks: list[str] = []
    with engine.connect() as conn:
        for table in Base.metadata.sorted_tables:
            for row in conn.execute(table.select()):
                chunks.append(table.name + " " + json.dumps(dict(row._mapping), default=str, ensure_ascii=False))
    return "\n".join(chunks)


def database_file_text() -> str:
    path = engine.url.database
    if engine.url.get_backend_name() != "sqlite" or not path or path == ":memory:":
        return ""
    parts = [Path(p).read_bytes().decode("latin-1") for p in (path, path + "-wal", path + "-journal")
             if os.path.exists(p)]
    return "\n".join(parts)


def assert_detection_happened(signals: list[dict]) -> None:
    """The planted secrets were really found, so the absence checks below are not vacuous."""
    secrets = [s for s in signals if s["code"] == "SECRET_DETECTED"]
    detectors = {s["evidence"]["detector"] for s in secrets}
    expected = {"github_token", "aws_access_key_id", "aws_secret_access_key", "database_url", "generic_secret",
                "slack_app_token", "sendgrid_api_key", "gcp_service_account", "azure_storage_key",
                "stripe_secret_key"}
    assert expected <= detectors, sorted(expected - detectors)
    assert detectors & {"authorization_header", "bearer_token", "auth_scheme_credentials"}
    assert any(s["evidence"].get("tool") == "gitleaks" for s in secrets)
    assert any(s["evidence"].get("corroborated_by") == ["gitleaks"] for s in secrets)
    for s in secrets:
        assert s["evidence"]["redacted"] and (s["evidence"].get("fingerprint") or s["evidence"].get("tool"))


# --------------------------------------------------------------------------- tests
def test_planted_secrets_never_leave_warden_through_the_api(client, admin_token, monkeypatch, caplog, capfd,
                                                             structlog_lines):
    package = PlantedPackage.build()
    gitleaks_calls = arm_fake_gitleaks(monkeypatch, package)
    cache = RecordingCache()
    orchestrator = Orchestrator(PlantedFetcher(package), analyzers=selected_analyzers(package.crash_message),
                                cache_backend=cache)
    monkeypatch.setattr(scans_router, "_orchestrator", orchestrator)
    caplog.set_level(logging.DEBUG)
    headers = auth(admin_token)
    name = "leaky-demo-" + uuid.uuid4().hex[:8]

    created = client.post("/api/v1/scans", headers=headers, json={"ecosystem": "pypi", "name": name,
                                                                  "version": "1.0.0"})
    assert created.status_code == 201
    body = created.json()
    assert gitleaks_calls, "the gitleaks adapter path must have run"
    assert_detection_happened(body["signals"])
    errors = {s["evidence"]["analyzer"]: s["evidence"] for s in body["signals"] if s["code"] == "ANALYZER_ERROR"}
    assert errors["leaky_crash"] == {"analyzer": "leaky_crash", "status": "error", "error_type": "RuntimeError"}
    assert errors["leaky_availability"] == {"analyzer": "leaky_availability", "status": "error",
                                            "error_type": "ValueError"}

    scan_id = body["id"]
    responses = {
        "POST /scans": created,
        "GET /scans/{id}": client.get(f"/api/v1/scans/{scan_id}", headers=headers),
        "GET /scans?q=": client.get("/api/v1/scans", headers=headers, params={"q": name}),
        "GET /scans/stats/overview": client.get("/api/v1/scans/stats/overview", headers=headers),
        "GET /events": client.get("/api/v1/events", headers=headers),
        "GET /audit": client.get("/api/v1/audit", headers=headers),
        "GET /metrics": client.get("/metrics"),
    }
    for label, response in responses.items():
        assert response.status_code == (201 if label == "POST /scans" else 200), label

    database = dump_database()
    assert body["signals"][0]["finding_id"] in database  # the dump really contains this scan's rows
    out, err = capfd.readouterr()
    structlog_text = "\n".join(structlog_lines)
    assert "scan_complete" in structlog_text + caplog.text + out + err  # log capture is live, not vacuous

    sinks = {label: response.text for label, response in responses.items()}
    sinks.update({
        "database rows": database,
        "database file": database_file_text(),
        "verdict cache": "\n".join(cache.store.values()),
        "structlog output": structlog_text,
        "stdlib logging": caplog.text,
        "stdout": out,
        "stderr": err,
    })
    leaks = package.leaks(sinks)
    assert not leaks, leaks


def test_analysis_result_and_verdict_cache_hold_no_planted_secret(monkeypatch, caplog, capfd, structlog_lines):
    package = PlantedPackage.build()
    arm_fake_gitleaks(monkeypatch, package)
    caplog.set_level(logging.DEBUG)
    cache = RecordingCache()
    orchestrator = Orchestrator(PlantedFetcher(package), analyzers=selected_analyzers(None), cache_backend=cache)

    result = orchestrator.analyze("pypi", "leaky-demo", "1.0.0", ScanOptions(offline=True))
    assert_detection_happened(result.signals)
    again = orchestrator.analyze("pypi", "leaky-demo", "1.0.0", ScanOptions(offline=True))

    serialised = json.dumps(asdict(result), default=str)
    cache_payloads = list(cache.store.values()) or [serialised]  # an incomplete verdict is (correctly) not cached
    out, err = capfd.readouterr()
    sinks = {
        "AnalysisResult JSON": serialised,
        "AnalysisResult repr": repr(result),
        "second AnalysisResult": json.dumps(asdict(again), default=str),
        "verdict cache": "\n".join(cache_payloads),
        "structlog output": "\n".join(structlog_lines),
        "stdlib logging": caplog.text,
        "stdout": out,
        "stderr": err,
    }
    leaks = package.leaks(sinks)
    assert not leaks, leaks


def test_crashing_analyzer_messages_are_never_persisted_or_logged(monkeypatch, caplog, capfd, structlog_lines):
    package = PlantedPackage.build(seed=99)
    caplog.set_level(logging.DEBUG)
    crashers = [LeakyCrash(package.crash_message), LeakyAvailability(package.crash_message)]
    result = Orchestrator(PlantedFetcher(package), analyzers=crashers, cache_backend=RecordingCache()).analyze(
        "pypi", "leaky-demo", "1.0.0", ScanOptions(offline=True))
    errors = [s for s in result.signals if s["code"] == "ANALYZER_ERROR"]
    assert sorted(e["evidence"]["error_type"] for e in errors) == ["RuntimeError", "ValueError"]
    assert all(set(e["evidence"]) == {"analyzer", "status", "error_type"} for e in errors)
    out, err = capfd.readouterr()
    crash_only = PlantedPackage(
        secrets=[p for p in package.secrets if p.name in {"github_token", "generic_secret", "db_password"}],
        files={}, binaries={}, crash_message="",
    )
    leaks = crash_only.leaks({
        "AnalysisResult JSON": json.dumps(asdict(result), default=str),
        "analyzer runs": json.dumps(result.analyzer_runs),
        "structlog output": "\n".join(structlog_lines),
        "stdlib logging": caplog.text,
        "stdout": out,
        "stderr": err,
    })
    assert not leaks, leaks


@pytest.mark.xfail(strict=False, reason=(
    "Known leak outside the secrets subsystem: ObfuscationAnalyzer copies the first 24 characters of every "
    "high-entropy string constant into evidence['blobs'] (app/analysis/analyzers/obfuscation.py). Reported as "
    "an integration request; remove this marker once that preview is redacted."))
def test_long_base64_key_constant_is_not_previewed_by_any_analyzer(monkeypatch):
    rng = random.Random(7)
    der = "".join(rng.choice(B64) for _ in range(160))
    source = f'"""Request signing (test fixture)."""\nSIGNING_KEY_DER = \'{der}\'\n'
    package = PlantedPackage(secrets=[Planted("signing_key_der", der)], files={"leaky/signing.py": source},
                             binaries={}, crash_message="")
    result = Orchestrator(PlantedFetcher(package), analyzers=selected_analyzers(None),
                          cache_backend=RecordingCache()).analyze("pypi", "leaky-demo", "1.0.0",
                                                                  ScanOptions(offline=True))
    assert any(s["code"] == "SECRET_DETECTED" for s in result.signals)
    leaks = package.leaks({"AnalysisResult JSON": json.dumps(asdict(result), default=str)})
    assert not leaks, leaks
