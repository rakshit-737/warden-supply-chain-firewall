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

## Packages and vulnerabilities

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/packages/{ecosystem}/{name}` | `scan:read` | Everything stored about one package (PEP 503 name matching): verdicts per version and environment, advisories found in them, monitoring state and release diffs. Database only; 404 when Warden has no data. |
| GET | `/vulnerabilities` | `vuln:read` | Advisories found in stored verdicts, aggregated by id with the affected package versions. Filters `kev`, `min_severity`. |
| GET | `/vulnerabilities/lookup` | `vuln:read` | Live lookup for `name` + `version` (OSV, CISA KEV, FIRST EPSS, optional NVD). The response always carries `status`; `unavailable` or `partial` means "not known", never "no vulnerabilities". Results are cached. |
| GET | `/vulnerabilities/{vuln_id}` | `vuln:read` | One advisory from the local cache (populated by lookups). |

## Projects

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/projects` | `project:write` | `{name, description?}`; names are unique (409). |
| GET | `/projects` | `project:read` | Paginated list. |
| GET | `/projects/{project_id}` | `project:read` | One project. |
| POST | `/projects/{project_id}/scans` | `project:write` | `{files: {path: text}, environment?}` — at most 50 files, 1 MB each, 5 MB in total. Manifests are parsed (requirements, `pyproject.toml`, lock files) and Dockerfiles / Compose files are linted; nothing is fetched or run. Produces hygiene, dependency-confusion and container-configuration findings, a dependency graph, a CycloneDX SBOM, and components enriched with the newest stored verdict for the same name, version and environment. |
| GET | `/projects/{project_id}/scans` | `project:read` | Scan history. |
| GET | `/projects/{project_id}/scans/{scan_id}` | `project:read` | Decision, risk, manifests, findings, parser warnings. |
| GET | `/projects/{project_id}/scans/{scan_id}/components` | `project:read` | Paginated components; `direct` filter. |
| GET | `/projects/{project_id}/scans/{scan_id}/graph` | `project:read` | Nodes, edges and metrics (depth, blast radius, single points of failure). |
| GET | `/projects/{project_id}/scans/{scan_id}/sbom` | `project:read` | `format=cyclonedx` (stored) or `spdx` (rebuilt from the stored components). Publishes `sbom_generated`. |

A project scan's decision is `block` for a high or critical finding, `warn` for a medium one,
otherwise `allow`, raised to the worst stored component decision.

## Release diffs

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/diffs` | `diff:create` | `{name, from_version, to_version}`. Analyses both releases and compares risk, dimensions, capabilities, findings (by code and file), the file inventory (added, removed, changed, new executables, install-time files) and declared maintainers. An `escalated` result publishes `behavior_drift_detected`; new maintainers publish `maintainer_changed`. One stored row per package, version pair and analyzer version. |
| GET | `/diffs` | `scan:read` | Paginated; filters `package`, `drift_only`. |
| GET | `/diffs/{diff_id}` | `scan:read` | Summary and the findings that are new in the newer release. |

## Containers

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/containers/scans` | `container:scan` | Raw `application/octet-stream` body: a `docker save` or OCI layout tarball, at most `MAX_IMAGE_UPLOAD_BYTES` (256 MiB) — the only route with a larger body limit. Query `image_ref` (label), `vulnerabilities` (run Trivy when installed). Authorisation is checked before the body is read; scans run one at a time. The image is analysed in memory and never run: configured user, environment secrets, installed Debian / Alpine / Python packages after whiteouts, credential formats in files, set-uid executables. An archive that cannot be read completely is stored as `incomplete` and never looks clean; vulnerabilities that were not assessed make the decision at least `warn`. |
| GET | `/containers/scans` | `scan:read` | Paginated list. |
| GET | `/containers/scans/{scan_id}` | `scan:read` | Summary, tool status and findings. |
| GET | `/containers/scans/{scan_id}/sbom` | `scan:read` | CycloneDX document of the image packages. |

## Monitoring

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/monitoring/packages` | `monitor:write` | `{name, approved_version?, poll_interval_seconds? (300–604800), project_id?}`; 409 for a duplicate. |
| GET | `/monitoring/packages` | `monitor:read` | Paginated; `failing` filter. |
| GET | `/monitoring/packages/{package_id}` | `monitor:read` | One watched package with its snapshot. |
| PATCH | `/monitoring/packages/{package_id}` | `monitor:write` | `enabled`, `approved_version`, `poll_interval_seconds`. |
| DELETE | `/monitoring/packages/{package_id}` | `monitor:write` | Stops watching. |
| POST | `/monitoring/packages/{package_id}/check` | `monitor:write` | Runs one check now: `baseline`, `unchanged`, `new_release` (with `diff_id`) or `error`. |

Checks normally run in the monitoring worker (`python -m app.workers.monitor`, Compose profile
`worker`). A new release is compared with the approved version, or the last one seen, and publishes
`new_release_detected` plus drift, risk and maintainer events. Failed checks back off exponentially
and publish `monitor_error` on the first failure and every fifth.

All write actions above are recorded in the audit chain.
