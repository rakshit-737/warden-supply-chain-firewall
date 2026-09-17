# Warden

**Decide whether a dependency is safe to install — from what its code does, where it came from, and
what is known about it.**

Warden analyses PyPI packages, project manifests and container images **without running them**. It
reports what a package does (install hooks, network and process behaviour, obfuscation, credential
access), where it came from (provenance, maintainers, dependency confusion) and what is known about
it (OSV, CISA KEV, FIRST EPSS), and turns that into an `allow` / `warn` / `block` decision under a
versioned policy.

![Scan detail: a blocked package with its risk scores, policy reasons and the correlated attack chain](images/scan-detail.png)

## What you can do with it

| | |
|---|---|
| **Gate dependencies in CI** | `warden gate -r requirements.txt` fails the build on blocked packages; the [GitHub Action](cli.md#github-action) uploads SARIF to code scanning. |
| **Scan a project** | Manifests become findings, a dependency graph with blast radius, and CycloneDX / SPDX SBOMs. Dockerfiles and Compose files are linted too. |
| **Compare releases** | See what changed in behaviour between two versions of a package before you upgrade. |
| **Check container images** | Analyse a `docker save` archive offline: user, secrets, installed packages, set-uid binaries, and known vulnerabilities through Trivy. |
| **Watch packages** | The monitoring worker checks new releases and raises events on drift or maintainer changes. |
| **Investigate** | The security console shows findings with file and line, ATT&CK and CWE mappings, attack chains, the audit trail and security events. |

## Honest limits

Static analysis reduces risk; it does not certify safety. The [detection benchmark](BENCHMARK.md) is
a small synthetic regression baseline, not a real-world detection rate, and the ML model's influence
is deliberately bounded ([ML model](ML_MODEL.md)).

Next: [Getting started](getting-started.md).
