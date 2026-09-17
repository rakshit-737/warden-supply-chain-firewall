# Changelog

## 2.0.0 — Warden X

Warden grows from a package firewall into a supply-chain security platform. Package code is still
never executed.

### Analysis
- Unified `Finding` model: severity and confidence, file and line, CWE and MITRE ATT&CK mappings,
  remediation, provenance; evidence sanitised and secrets redacted on construction.
- Fourteen analyzers, including new secrets, dependency-confusion, provenance (PEP 740), YARA,
  Semgrep, vulnerability (OSV, CISA KEV, FIRST EPSS, optional NVD) and install-vector analyzers
  (`.pth` start-up hooks, in-tree build backends, console scripts that shadow commands).
- Static analysis detects serialised environment dumps, import aliases, socket egress,
  reconstructed `exec` names and reverse shells.
- Attack-chain correlation and Risk Engine 2.0 with separate behavioural and vulnerability risk;
  the ML model can no longer escalate on its own past the medium band.
- Release-to-release behavioural diffs.

### Projects, containers and monitoring
- Project scans from manifests: dependency hygiene, dependency confusion, Dockerfile and Compose
  linting, dependency graph with blast radius, CycloneDX 1.6 and SPDX 2.3 SBOMs.
- Offline container image analysis (`docker save` / OCI) with an optional Trivy pass.
- Continuous monitoring worker for new releases, drift and maintainer changes.

### Platform
- API: packages, projects, diffs, containers, monitoring and vulnerabilities routes; policy-as-code
  with environments and approved exceptions; five-role RBAC; hash-chained audit log; security
  events; Prometheus metrics.
- Console: projects, diffs, containers, monitoring and package views; React 19, React Router 8,
  Vite 8 and Tailwind CSS 4.
- CLI: `project scan`, `sbom generate`, `policy validate`, `diff`, `image scan`, `report`; SARIF
  2.1.0 output.
- GitHub Action (`action.yml`) for project scans with SARIF upload.
- Synthetic detection benchmark with a CI regression gate (`docs/BENCHMARK.md`).

### Security
- Secret redaction can no longer be bypassed with terminal escape sequences or bidi characters.
- Hardened proxy limits, digest-pinned images with applied OS updates, Trivy and CodeQL clean.
- The dynamic sandbox is designed but not built; enabling it is refused (`docs/SANDBOX.md`).

## 1.0.0

Initial release: behavioural package firewall for PyPI with rule and ML scoring, policy engine,
API, console and CI gate.
