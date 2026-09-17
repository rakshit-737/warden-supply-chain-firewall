# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through a
[GitHub security advisory](https://github.com/rakshit-737/warden-supply-chain-firewall/security/advisories/new)
rather than a public issue. Include reproduction steps and the impact you expect. You should receive
an acknowledgement within a few days.

If the issue involves a malicious package sample, do not attach it: describe how to obtain it or
share a hash.

## Security posture

Warden processes attacker-authored archives and untrusted registry and advisory data, so its own
hardening is part of the product.

- **No execution of analysed code.** Packages are downloaded and parsed, never imported, built,
  unpickled or unmarshalled.
- **Hostile-archive extraction.** Content-based format detection; path, link, device, depth, length,
  count and size limits; a cap on the declared size of skipped members that defeats decompression
  bombs; artifact digests verified against the registry.
- **Outbound requests.** HTTPS only, host allowlist checked on every redirect hop, size caps, bounded
  retries, client-side rate limits.
- **Secrets.** Secrets found in packages are reported only as a redacted preview and a keyed
  fingerprint. Log output, error bodies and metrics pass through redaction; a regression test plants
  secrets and checks every sink.
- **Authentication.** argon2id password hashing, short-lived JWTs, rotating refresh tokens with reuse
  detection, timing-equalised login, audited failures.
- **Authorisation.** Five roles with permissions enforced on every route; exceptions need an approver
  other than the requester.
- **Audit.** A sha256 hash chain with a verification endpoint; on PostgreSQL a trigger rejects
  updates and deletes on audit rows.
- **API hardening.** Validated request ids, streamed body limits, proxy-aware rate limiting, strict
  security headers, sanitised errors, fail-closed production configuration.
- **Warden's own supply chain.** GitHub Actions pinned by commit SHA, least-privilege tokens,
  `pip-audit --strict` and `npm audit` able to fail the build, bandit, CodeQL, gitleaks and Trivy,
  digest-pinned base images, non-root read-only containers, signed build provenance on release.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full analysis and the residual risks we
acknowledge.
