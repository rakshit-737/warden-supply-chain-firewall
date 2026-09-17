"""warden - command-line gate for CI and developer machines.

API-backed commands (need a running Warden API and a token)::

  warden scan requests==2.32.3 --api http://localhost:8000 --token $WARDEN_TOKEN
  warden gate -r requirements.txt --fail-on block

Local commands (run the engines in-process; need the ``[server]`` extras)::

  warden project scan .              # dependency hygiene, dependency confusion, graph summary
  warden sbom generate . --format cyclonedx --output sbom.json
  warden policy validate policies/production.yaml

``--api`` and ``--token`` default to the ``WARDEN_API`` and ``WARDEN_TOKEN`` environment variables.

Exit codes: 0 = passed, 2 = something was blocked / a check failed, 3 = usage or transport error.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass

import httpx

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*))?")
_COLORS = {"allow": "\033[92m", "warn": "\033[93m", "block": "\033[91m", "reset": "\033[0m"}
# Values echoed from the API originate in package metadata and archives, i.e. attacker input.
# Escape control and bidirectional characters so nothing can drive the user's terminal.
_UNSAFE_TERMINAL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


def terminal_safe(value: object, max_len: int = 200) -> str:
    text = _UNSAFE_TERMINAL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", str(value)).replace("\n", "\\n")
    return text if len(text) <= max_len else text[: max_len - 1] + "..."


@dataclass
class Dep:
    name: str
    version: str | None


def parse_requirements(path: str) -> list[Dep]:
    deps: list[Dep] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            m = _REQ_LINE.match(line)
            if m:
                deps.append(Dep(m.group(1), m.group(2)))
    return deps


def scan_one(client: httpx.Client, api: str, token: str, dep: Dep) -> dict:
    resp = client.post(
        f"{api.rstrip('/')}/api/v1/scans",
        headers={"Authorization": f"Bearer {token}"},
        json={"ecosystem": "pypi", "name": dep.name, "version": dep.version},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def _fmt(verdict: dict, no_color: bool) -> str:
    d = str(verdict.get("decision", "?"))
    color = "" if no_color else _COLORS.get(d, "")
    reset = "" if no_color else _COLORS["reset"]
    top = "; ".join(terminal_safe(s.get("code", ""), 40) for s in verdict.get("signals", [])[:3]) or "-"
    name = terminal_safe(verdict.get("package_name", "?"), 80)
    version = terminal_safe(verdict.get("version", "?"), 40)
    return f"{color}{d.upper():6}{reset} risk={verdict.get('risk_score', '?'):>3} {name}=={version:<12} [{top}]"


def cmd_scan(args) -> int:
    deps = [_dep_from_spec(args.spec)]
    return _run(deps, args)


def cmd_gate(args) -> int:
    if not args.requirements:
        print("error: gate requires -r/--requirements", file=sys.stderr)
        return 3
    deps = parse_requirements(args.requirements)
    if not deps:
        print("No pinned dependencies found to scan.")
        return 0
    return _run(deps, args)


def _dep_from_spec(spec: str) -> Dep:
    m = _REQ_LINE.match(spec)
    if not m:
        raise SystemExit(f"Invalid package spec: {spec}")
    return Dep(m.group(1), m.group(2))


def _run(deps: list[Dep], args) -> int:
    order = {"allow": 0, "warn": 1, "block": 2}
    threshold = order[args.fail_on]
    worst = 0
    blocked: list[str] = []
    with httpx.Client() as client:
        for dep in deps:
            try:
                verdict = scan_one(client, args.api, args.token, dep)
            except httpx.HTTPStatusError as exc:
                print(f"error scanning {dep.name}: HTTP {exc.response.status_code}", file=sys.stderr)
                return 3
            except httpx.HTTPError as exc:
                print(f"transport error scanning {dep.name}: {exc}", file=sys.stderr)
                return 3
            print(_fmt(verdict, args.no_color))
            worst = max(worst, order[verdict["decision"]])
            if order[verdict["decision"]] >= threshold and verdict["decision"] != "allow":
                blocked.append(f"{terminal_safe(verdict['package_name'], 80)}=={terminal_safe(verdict['version'], 40)}")

    if worst >= threshold and threshold <= order["block"] and blocked:
        print(f"\nGate FAILED (fail-on={args.fail_on}): {', '.join(blocked)}", file=sys.stderr)
        return 2
    print("\nGate passed.")
    return 0


API_COMMANDS = frozenset({"scan", "gate"})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="warden", description="Warden X supply-chain security CLI")
    p.add_argument("--api", default=os.environ.get("WARDEN_API", "http://localhost:8000"),
                   help="Warden API base URL (default: $WARDEN_API)")
    p.add_argument("--token", default=os.environ.get("WARDEN_TOKEN", ""),
                   help="Bearer access token (default: $WARDEN_TOKEN)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--fail-on", choices=["warn", "block"], default="block")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="Scan a single package spec through the API")
    sp.add_argument("spec", help="e.g. requests==2.32.3")
    sp.set_defaults(func=cmd_scan)

    gp = sub.add_parser("gate", help="Scan a requirements file through the API and gate CI")
    gp.add_argument("-r", "--requirements", help="Path to requirements.txt")
    gp.set_defaults(func=cmd_gate)

    from cli import local

    project = sub.add_parser("project", help="Local project analysis").add_subparsers(dest="action", required=True)
    ps = project.add_parser("scan", help="Dependency hygiene, dependency confusion and graph summary")
    ps.add_argument("path", nargs="?", default=".")
    ps.add_argument("--project-name")
    ps.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    ps.add_argument("--output", "-o", help="write the report to a file (e.g. warden.sarif)")
    ps.add_argument("--fail-on", dest="fail_on", choices=["low", "medium", "high", "critical"], default="high",
                    help="minimum finding severity that fails the check (default: high)")
    ps.set_defaults(func=local.cmd_project_scan)

    sbom = sub.add_parser("sbom", help="Software bill of materials").add_subparsers(dest="action", required=True)
    sg = sbom.add_parser("generate", help="Generate a CycloneDX 1.6 or SPDX 2.3 SBOM from project manifests")
    sg.add_argument("path", nargs="?", default=".")
    sg.add_argument("--format", choices=["cyclonedx", "spdx"], default="cyclonedx")
    sg.add_argument("--output", "-o")
    sg.add_argument("--project-name")
    sg.set_defaults(func=local.cmd_sbom_generate)

    dp = sub.add_parser("diff", help="Compare the behaviour of two releases of a package (fetches both)")
    dp.add_argument("package")
    dp.add_argument("from_version")
    dp.add_argument("to_version")
    dp.add_argument("--format", choices=["table", "json"], default="table")
    dp.add_argument("--fail-on-drift", action="store_true", help="exit 2 when the newer release escalated")
    dp.set_defaults(func=local.cmd_diff)

    image = sub.add_parser("image", help="Container images").add_subparsers(dest="action", required=True)
    isc = image.add_parser("scan", help="Analyse a docker-save / OCI image archive offline")
    isc.add_argument("archive", help="path to the output of `docker save` (or an OCI layout tarball)")
    isc.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    isc.add_argument("--output", "-o")
    isc.add_argument("--sbom-output", help="also write a CycloneDX SBOM of the image packages")
    isc.add_argument("--no-vulnerabilities", action="store_true", help="skip the Trivy vulnerability scan")
    isc.add_argument("--offline", action="store_true", help="do not let Trivy update its database")
    isc.add_argument("--fail-on", dest="fail_on", choices=["low", "medium", "high", "critical"], default="high")
    isc.set_defaults(func=local.cmd_image_scan)

    rp = sub.add_parser("report", help="Render a saved JSON result as Markdown, HTML or SARIF")
    rp.add_argument("input", help="JSON from project scan, image scan, diff or the scans API ('-' for stdin)")
    rp.add_argument("--format", choices=["markdown", "html", "sarif"], default="markdown")
    rp.add_argument("--output", "-o")
    rp.set_defaults(func=local.cmd_report)

    policy = sub.add_parser("policy", help="Policy-as-code").add_subparsers(dest="action", required=True)
    pv = policy.add_parser("validate", help="Validate a policy document (YAML or JSON)")
    pv.add_argument("file")
    pv.add_argument("--format", choices=["text", "json"], default="text")
    pv.set_defaults(func=local.cmd_policy_validate)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in API_COMMANDS and not args.token:
        print("error: --token (or WARDEN_TOKEN) is required for API commands", file=sys.stderr)
        return 3
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
