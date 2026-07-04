# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately (e.g. via a GitHub security advisory)
rather than opening a public issue. Include reproduction steps and impact. You can expect
an acknowledgement within a few days.

## Security posture of this project

Warden intentionally processes **hostile input** (attacker-authored package archives), so
its own hardening is part of the product. Key controls:

- Package code is **fetched and statically parsed, never executed**.
- Archive extraction guards against path traversal (Zip-Slip), zip/tar bombs (size, file
  count, and per-file caps), and symlink escapes.
- Authentication uses argon2id password hashing and short-lived JWTs with rotating refresh
  tokens stored only as hashes.
- Authorisation is role-based and enforced on every mutating endpoint.
- All input is validated with pydantic before it reaches the analysis pipeline; package
  names are constrained to the ecosystem grammar before they can influence a URL or path.
- Rate limiting, security headers, structured audit logging, and a fail-closed config
  validator are enabled by default.
- The container runs as a non-root user with a read-only root filesystem and
  `no-new-privileges`.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full STRIDE analysis and the
residual risks we acknowledge.
