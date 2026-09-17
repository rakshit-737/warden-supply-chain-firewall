# API Reference

Base path `/api/v1`. The live schema is served at `/openapi.json`, with Swagger UI at `/docs` and
ReDoc at `/redoc` outside production. This page lists the routes that exist today, generated from
that schema and kept in step with it.

## Conventions

- **Authentication** — `Authorization: Bearer <access token>`. Access tokens are short-lived JWTs;
  the refresh token is an opaque value in an httpOnly cookie and rotates on every use. Presenting a
  refresh token that was already used revokes the whole family: that is theft detection, not a bug.
- **Authorisation** — every route requires a permission (see the table below), enforced server-side.
- **Errors** — `{"error": {"code": "...", "message": "...", "request_id": "..."}}`. Validation errors
  never echo the submitted value back.
- **Pagination** — `limit` and `offset` query parameters; responses are
  `{"items": [...], "total": n, "limit": n, "offset": n}`.
- **Rate limiting** — per client and per authenticated user, stricter on authentication routes.
  A limited response carries `Retry-After`.
- **Request ids** — a client `X-Request-ID` is accepted only if it matches `^[A-Za-z0-9._-]{8,64}$`;
  otherwise the server generates one. It is returned on every response and recorded in the audit log.

## Roles and permissions

| Permission | admin | security_analyst | developer | auditor | read_only |
|---|:--:|:--:|:--:|:--:|:--:|
| `scan:create`, `project:write`, `container:scan`, `diff:create` | ✓ | ✓ | ✓ | | |
| `scan:read`, `policy:read`, `event:read`, `monitor:read`, `ml:read`, `report:read`, `vuln:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `exception:request` | ✓ | ✓ | ✓ | | |
| `exception:approve`, `event:ack`, `monitor:write` | ✓ | ✓ | | | |
| `audit:read`, `system:read` | ✓ | | | ✓ | |
| `policy:write`, `user:manage`, `system:write` | ✓ | | | | |

## Authentication

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/auth/login` | public | Returns an access token, sets the refresh cookie. Failed attempts are audited; timing is equalised so a missing account cannot be distinguished. |
| POST | `/auth/refresh` | refresh cookie | Rotates the refresh token. Reuse of a revoked token revokes every token for that user. |
| POST | `/auth/logout` | refresh cookie | Revokes the presented refresh token. |
| GET | `/auth/me` | authenticated | The caller's own profile. |
| POST | `/auth/register` | `user:manage` | Creates a user; passwords must be at least 12 characters. |

## Scans

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/scans` | `scan:create` | Body `{ecosystem, name, version?, environment?}`. Runs the pipeline and returns the verdict with findings, risk dimensions, attack chains, analyzer runs, provenance, vulnerabilities and the policy reasons that decided it. A version that does not exist is a 404 — never a verdict for a different release. |
| GET | `/scans` | `scan:read` | History with `decision`, `severity`, `q` and pagination. |
| GET | `/scans/{scan_id}` | `scan:read` | One verdict with its findings. |
| GET | `/scans/stats/overview` | `scan:read` | Totals by decision and severity, blocked in the last 30 days, average risk, most frequent finding codes. |

## Policies and exceptions

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/policies` | `policy:read` | All policies with their document and hash. |
| POST | `/policies` | `policy:write` | Creates a policy, optionally from a policy-as-code document. |
| PUT | `/policies/{policy_id}` | `policy:write` | Updates a policy. |
| POST | `/policies/{policy_id}/activate` | `policy:write` | Activates it for its environment (one active policy per environment). |
| GET | `/policies/active` | `policy:read` | The active policy, optionally for a named environment. |
| POST | `/policies/validate` | `policy:read` | Validates a document (object or YAML text) without storing it; returns errors with locations and the policy hash. |
| GET | `/policies/exceptions` | `policy:read` | Exceptions with their status, including expiry. |
| POST | `/policies/exceptions` | `exception:request` | Requests a time-boxed exception: package, optional version range, scope, justification, expiry. |
| POST | `/policies/exceptions/{id}/approve` | `exception:approve` | The requester may not approve their own request. |
| POST | `/policies/exceptions/{id}/reject` | `exception:approve` | |
| POST | `/policies/exceptions/{id}/revoke` | `exception:approve` | |

## Events and audit

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/events` | `event:read` | Security events filtered by type, severity, package, project, time and acknowledgement. |
| POST | `/events/{event_id}/ack` | `event:ack` | Idempotent; the first acknowledger is kept. |
| GET | `/audit` | `audit:read` | Append-only audit log, filterable by action. |
| GET | `/audit/verify` | `audit:read` | Recomputes the hash chain and reports `ok`, or the first sequence number where it breaks. Tamper-evident, not tamper-proof: anyone who can rewrite the whole table can rebuild the chain, so record the head hash externally. |

## Users and system

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/users` | `user:manage` | Filter by role, active flag, email substring. |
| PATCH | `/users/{user_id}` | `user:manage` | Change role or active flag; removing the last active admin is refused (409). Deactivating revokes refresh tokens. |
| GET | `/system/info` | `system:read` | Version, environment, feature switches, enforced limits. Never secrets or connection strings. |
| GET | `/system/tools` | `system:read` | Availability of the optional tools (YARA, Semgrep, gitleaks). |

## Machine learning

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/ml/model` | `ml:read` | Model metadata: availability (and why not), version, feature-set identity, dataset provenance, and metrics with their scope label. Never pickled objects or file paths. |
| GET | `/ml/drift` | `ml:read` | Population stability index of recent scan inputs against the training reference; `insufficient_data` below 50 usable rows. |

## Operations

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/health/live` | public | Liveness. |
| GET | `/health/ready` | public | Database and cache checks; the model is optional, so a missing model is degraded, not unready. |
| GET | `/metrics` | optional bearer | Prometheus exposition; requires `METRICS_TOKEN` when configured. Labels are bounded and never contain package names. |

## Not implemented yet

`/packages`, `/projects`, `/diffs`, `/containers`, `/monitoring` and `/vulnerabilities` are
registered but carry no routes yet. Their engines exist as libraries (SBOM, dependency graph,
intelligence); the HTTP surface is the next phase, and the console links to them as placeholders.
