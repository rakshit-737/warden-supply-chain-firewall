"""warden — command-line gate for CI and developer machines.

Reads a requirements file (or a single ``name==version``), asks a running Warden API to
scan each dependency, prints an explainable verdict table, and exits non-zero if any
package is BLOCKED — turning Warden into a CI gate with a single step.

Usage:
  warden scan requests==2.32.3 --api http://localhost:8000 --token $WARDEN_TOKEN
  warden gate -r requirements.txt --api $WARDEN_API --token $WARDEN_TOKEN --fail-on block

Exit codes: 0 = all allowed/warned, 2 = at least one blocked, 3 = usage/transport error.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass

import httpx

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*))?")
_COLORS = {"allow": "\033[92m", "warn": "\033[93m", "block": "\033[91m", "reset": "\033[0m"}


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
    d = verdict["decision"]
    color = "" if no_color else _COLORS.get(d, "")
    reset = "" if no_color else _COLORS["reset"]
    top = "; ".join(s["code"] for s in verdict.get("signals", [])[:3]) or "-"
    return (f"{color}{d.upper():6}{reset} risk={verdict['risk_score']:>3} "
            f"{verdict['package_name']}=={verdict['version']:<12} [{top}]")


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
                blocked.append(f"{verdict['package_name']}=={verdict['version']}")

    if worst >= threshold and threshold <= order["block"] and blocked:
        print(f"\nGate FAILED (fail-on={args.fail_on}): {', '.join(blocked)}", file=sys.stderr)
        return 2
    print("\nGate passed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="warden", description="Warden supply-chain firewall CLI")
    p.add_argument("--api", default="http://localhost:8000", help="Warden API base URL")
    p.add_argument("--token", default="", help="Bearer access token")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--fail-on", choices=["warn", "block"], default="block")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="Scan a single package spec")
    sp.add_argument("spec", help="e.g. requests==2.32.3")
    sp.set_defaults(func=cmd_scan)

    gp = sub.add_parser("gate", help="Scan a requirements file and gate CI")
    gp.add_argument("-r", "--requirements", help="Path to requirements.txt")
    gp.set_defaults(func=cmd_gate)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.token:
        print("error: --token (or WARDEN_TOKEN) is required", file=sys.stderr)
        return 3
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
