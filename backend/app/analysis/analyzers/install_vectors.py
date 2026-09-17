"""Install- and startup-time execution vectors beyond ``setup.py``.

``install_script`` covers ``setup.py``. This analyzer covers the other ways a package gets code to run
without anyone importing it:

* ``PTH_STARTUP_HOOK`` - ``.pth`` files whose lines start with ``import`` are executed by
  :mod:`site` on *every* interpreter start, and a shipped ``sitecustomize.py`` / ``usercustomize.py``
  is imported the same way. Editable-install finders and ``distutils-precedence.pth`` are ordinary,
  so a hook that only imports is medium / 0.6; a hook that also decodes, evaluates, spawns processes
  or touches the network is critical / 0.9.
* ``BUILD_BACKEND_HOOK`` - ``pyproject.toml`` build configuration that runs code from the archive
  (an in-tree backend via ``backend-path``: high / 0.8), a build requirement fetched from a direct
  URL (medium / 0.7), or a backend outside the list of widely used ones (low / 0.4 - informational).
* ``ENTRYPOINT_SHADOWING`` - console scripts named like common system or developer commands
  (``pip``, ``python``, ``git``, ``sudo`` ...), which can intercept those commands once installed.
  Scripts that match the package's own name are not reported.

Everything is read as text (``tomllib``, line parsing and a regular expression over ``setup.py``);
nothing is imported or executed.
"""

from __future__ import annotations

import configparser
import re
import tomllib

from app.analysis.analyzers.base import BaseAnalyzer, PackageContext, SourceFile
from app.analysis.findings import Finding, Location
from app.analysis.signals import Capability, Code, Severity
from app.core.redaction import sanitize_text

ANALYZER_VERSION = "1.0.0"
MAX_REPORTED = 20

KNOWN_BACKENDS = frozenset({
    "setuptools.build_meta", "setuptools.build_meta:__legacy__", "hatchling.build", "flit_core.buildapi",
    "flit.buildapi", "poetry.core.masonry.api", "poetry.masonry.api", "pdm.backend", "pdm.pep517.api",
    "maturin", "scikit_build_core.build", "mesonpy", "sipbuild.api", "whey", "enscons.api",
    "jupyter_packaging.build_api", "pbr.build", "trampolim", "uv_build", "hatchling.ouroboros",
    "setuptools_rust.build_meta", "cmake_build_extension.build_meta",
})

# Command names worth protecting; the most sensitive ones are graded higher.
CRITICAL_COMMANDS = frozenset({"pip", "pip3", "python", "python3", "sudo", "su", "ssh", "git", "gpg", "doas"})
COMMON_COMMANDS = CRITICAL_COMMANDS | frozenset({
    "ls", "cp", "mv", "rm", "cat", "cd", "ps", "curl", "wget", "bash", "sh", "zsh", "env", "which", "npm", "npx",
    "node", "docker", "kubectl", "helm", "terraform", "aws", "gcloud", "az", "make", "gcc", "cc", "apt", "apt-get",
    "yum", "dnf", "brew", "openssl", "scp", "rsync", "tar", "unzip", "chmod", "chown", "passwd", "ssh-keygen",
    "pip3.12", "python3.12", "pipx", "poetry", "uv", "conda", "twine",
})

_HOOK_DANGER_RE = re.compile(
    r"\b(?:exec|eval|compile|__import__|b64decode|b32decode|a85decode|unhexlify|decompress|marshal|pickle"
    r"|subprocess|popen|system|socket|urlopen|urllib|requests|httpx|http\.client|ctypes)\b"
)
_CONSOLE_SCRIPT_RE = re.compile(r"""['"]\s*([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})\s*=\s*[\w.]+\s*:\s*[\w.]+""")


def _finding(code: str, severity: Severity, weight: float, message: str, evidence: dict, *, file: str,
             line: int | None, confidence: float, capability: str | None) -> Finding:
    return Finding(code, severity, weight, sanitize_text(message, max_len=300), evidence, capability=capability,
                   confidence=confidence, location=Location(file=file, line=line))


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class InstallVectorsAnalyzer(BaseAnalyzer):
    name = "install_vectors"
    version = ANALYZER_VERSION

    def analyze(self, ctx: PackageContext) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._startup_hooks(ctx)
        findings += self._build_backend(ctx)
        findings += self._entry_points(ctx)
        return findings

    # ------------------------------------------------------------------ .pth / sitecustomize
    def _startup_hooks(self, ctx: PackageContext) -> list[Finding]:
        out: list[Finding] = []
        sources = [*ctx.files, *getattr(ctx, "wheel_files", [])]
        seen: set[str] = set()
        for source in sources:
            if source.relpath in seen:
                continue
            seen.add(source.relpath)
            name = source.relpath.rsplit("/", 1)[-1].lower()
            if name.endswith(".pth"):
                out += self._pth(source)
            elif name in ("sitecustomize.py", "usercustomize.py") and self._importable_top_level(source.relpath):
                out.append(_finding(
                    Code.PTH_STARTUP_HOOK, Severity.high, 9.0,
                    f"{name} is shipped where Python imports it on every interpreter start",
                    {"file": source.relpath, "kind": "startup_module"},
                    file=source.relpath, line=1, confidence=0.8, capability=Capability.PTH_HOOK,
                ))
            if len(out) >= MAX_REPORTED:
                break
        return out

    @staticmethod
    def _importable_top_level(relpath: str) -> bool:
        parts = relpath.strip("/").split("/")
        # "pkg-1.0/sitecustomize.py" (sdist root), "sitecustomize.py" (wheel root) or under src/.
        return len(parts) <= 2 or (len(parts) == 3 and parts[1] == "src")

    @staticmethod
    def _pth(source: SourceFile) -> list[Finding]:
        executable = []
        for number, line in enumerate(source.text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith(("import ", "import\t")):
                executable.append((number, stripped))
        if not executable:
            return []
        dangerous = [(n, text) for n, text in executable if _HOOK_DANGER_RE.search(text)]
        first_line = (dangerous or executable)[0][0]
        evidence = {"file": source.relpath, "executable_lines": len(executable),
                    "lines": [n for n, _ in executable[:10]]}
        if dangerous:
            found = {m.group(0) for _, text in dangerous for m in _HOOK_DANGER_RE.finditer(text)}
            evidence["indicators"] = sorted(found)[:10]
            return [_finding(Code.PTH_STARTUP_HOOK, Severity.critical, 12.0,
                             f"{source.relpath} runs code with {', '.join(evidence['indicators'][:3])} on every "
                             "interpreter start",
                             evidence, file=source.relpath, line=first_line, confidence=0.9,
                             capability=Capability.PTH_HOOK)]
        return [_finding(Code.PTH_STARTUP_HOOK, Severity.medium, 4.0,
                         f"{source.relpath} executes an import on every interpreter start",
                         evidence, file=source.relpath, line=first_line, confidence=0.6,
                         capability=Capability.PTH_HOOK)]

    # ------------------------------------------------------------------ pyproject build system
    def _build_backend(self, ctx: PackageContext) -> list[Finding]:
        out: list[Finding] = []
        for source in ctx.find("pyproject.toml"):
            if source.relpath.count("/") > 1:
                continue  # only the archive root's pyproject.toml drives the build (nested ones are examples)
            try:
                data = tomllib.loads(source.text)
            except (tomllib.TOMLDecodeError, UnicodeError):
                continue
            build = data.get("build-system")
            if not isinstance(build, dict):
                continue
            backend = build.get("build-backend")
            backend_path = build.get("backend-path")
            line = _line_of(source.text, "build-backend") or _line_of(source.text, "[build-system]")
            if backend_path:
                out.append(_finding(
                    Code.BUILD_BACKEND_HOOK, Severity.high, 8.0,
                    f"pyproject.toml uses an in-tree build backend ({backend})",
                    {"file": source.relpath, "backend": sanitize_text(backend, max_len=100),
                     "backend_path": [sanitize_text(p, max_len=100) for p in backend_path][:5]
                     if isinstance(backend_path, list) else sanitize_text(backend_path, max_len=100)},
                    file=source.relpath, line=_line_of(source.text, "backend-path") or line,
                    confidence=0.8, capability=Capability.BUILD_HOOK,
                ))
            elif isinstance(backend, str) and backend.strip() not in KNOWN_BACKENDS:
                out.append(_finding(
                    Code.BUILD_BACKEND_HOOK, Severity.low, 1.5,
                    f"pyproject.toml uses an uncommon build backend ({backend})",
                    {"file": source.relpath, "backend": sanitize_text(backend, max_len=100)},
                    file=source.relpath, line=line, confidence=0.4, capability=Capability.BUILD_HOOK,
                ))
            requires = build.get("requires") if isinstance(build.get("requires"), list) else []
            direct = [r for r in requires if isinstance(r, str) and "@" in r and "://" in r]
            if direct:
                out.append(_finding(
                    Code.BUILD_BACKEND_HOOK, Severity.medium, 5.0,
                    "Build requirements are fetched from direct URLs, outside the package index",
                    {"file": source.relpath, "requirements": [sanitize_text(r, max_len=200) for r in direct[:5]]},
                    file=source.relpath, line=_line_of(source.text, "requires") or line,
                    confidence=0.7, capability=Capability.BUILD_HOOK,
                ))
        return out

    # ------------------------------------------------------------------ console scripts
    def _entry_points(self, ctx: PackageContext) -> list[Finding]:
        own = {_normalize(ctx.name)}
        scripts: dict[str, tuple[str, int | None]] = {}
        for source in [*ctx.files, *getattr(ctx, "wheel_files", [])]:
            name = source.relpath.rsplit("/", 1)[-1]
            if name == "entry_points.txt":
                for script, line in _entry_points_txt(source.text):
                    scripts.setdefault(script, (source.relpath, line))
            elif name == "pyproject.toml":
                for script in _pyproject_scripts(source.text):
                    scripts.setdefault(script, (source.relpath, _line_of(source.text, script)))
            elif name == "setup.py" and "console_scripts" in source.text:
                for match in _CONSOLE_SCRIPT_RE.finditer(source.text):
                    line = source.text.count("\n", 0, match.start()) + 1
                    scripts.setdefault(match.group(1), (source.relpath, line))
        out = []
        for script in sorted(scripts):
            lowered = script.lower()
            if lowered not in COMMON_COMMANDS or _normalize(script) in own:
                continue
            file, line = scripts[script]
            critical = lowered in CRITICAL_COMMANDS
            out.append(_finding(
                Code.ENTRYPOINT_SHADOWING, Severity.high if critical else Severity.medium, 7.0 if critical else 4.0,
                f"Console script '{script}' shadows the '{lowered}' command",
                {"script": sanitize_text(script, max_len=64), "file": file},
                file=file, line=line, confidence=0.75 if critical else 0.65, capability=Capability.INSTALL_EXEC,
            ))
        return out[:MAX_REPORTED]


def _line_of(text: str, needle: str) -> int | None:
    index = text.find(needle)
    return None if index < 0 else text.count("\n", 0, index) + 1


def _entry_points_txt(text: str) -> list[tuple[str, int | None]]:
    parser = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=False)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    out = []
    for section in ("console_scripts", "gui_scripts"):
        if parser.has_section(section):
            out += [(key.strip(), _line_of(text, key)) for key in parser.options(section)]
    return out


def _pyproject_scripts(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, UnicodeError):
        return []
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    names: list[str] = []
    for key in ("scripts", "gui-scripts"):
        table = project.get(key)
        if isinstance(table, dict):
            names += [str(k) for k in table]
    poetry = ((data.get("tool") or {}).get("poetry") or {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict) and isinstance(poetry.get("scripts"), dict):
        names += [str(k) for k in poetry["scripts"]]
    return names
