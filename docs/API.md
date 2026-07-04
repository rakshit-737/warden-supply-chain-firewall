# API Reference

Base path: `/api/v1`. Interactive OpenAPI docs are served at `/docs` (Swagger) and
`/redoc` when `ENV != production`. All timestamps are ISO-8601 UTC. All errors use a
consistent problem shape:

```json
{ "error": { "code": "string", "message": "human readable", "request_id": "uuid" } }
```

## Authentication

Bearer JWT access tokens (short-lived). Refresh tokens are delivered/rotated via an
httpOnly cookie. Send `Authorization: Bearer <access_token>` on protected routes.

| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | admin | Create a user (first-run bootstrap creates the initial admin via seed) |
| POST | `/auth/login` | public | Exchange credentials for an access token (+ refresh cookie) |
| POST | `/auth/refresh` | public (cookie) | Rotate the refresh token, issue a new access token |
| POST | `/auth/logout` | any | Revoke the current refresh token |
| GET  | `/auth/me` | any | Current user profile |

## Scans

| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/scans` | analyst+ | Analyse `{ecosystem, name, version}`; returns full verdict |
| GET  | `/scans` | viewer+ | Paginated verdict history with filters (`decision`, `severity`, `q`) |
| GET  | `/scans/{id}` | viewer+ | One verdict with all signals + feature vector |
| GET  | `/scans/stats/overview` | viewer+ | Aggregates for the dashboard (counts by decision/severity, trend) |

Example verdict (`POST /scans`):

```json
{
  "id": "1f9c...",
  "ecosystem": "pypi",
  "package_name": "reqeusts",
  "version": "1.0.0",
  "risk_score": 88,
  "rule_score": 82,
  "ml_score": 88,
  "severity": "critical",
  "decision": "block",
  "duration_ms": 640,
  "signals": [
    {"code": "TYPOSQUAT", "severity": "high", "weight": 8.0,
     "message": "Name is edit-distance 1 from popular package 'requests'",
     "evidence": {"target": "requests", "distance": 1}},
    {"code": "INSTALL_HOOK_EXEC", "severity": "critical", "weight": 10.0,
     "message": "setup.py executes code at install time", "evidence": {"file": "setup.py"}}
  ],
  "matched_policy_rules": ["block_threshold", "blocked_capability:install_hook_exec"]
}
```

## Policies

| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET  | `/policies` | viewer+ | List policies |
| GET  | `/policies/active` | viewer+ | The currently active policy |
| POST | `/policies` | admin | Create a policy |
| PUT  | `/policies/{id}` | admin | Update a policy |
| POST | `/policies/{id}/activate` | admin | Make a policy the active one |

## Audit

| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/audit` | admin | Paginated append-only audit events with filters |

## Health

| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/health/live` | public | Liveness |
| GET | `/health/ready` | public | Readiness (checks DB + Redis + model) |

## Rate limiting

Sliding-window limits are enforced per identity and per IP (configurable). Exceeding a
limit returns `429` with a `Retry-After` header and error code `RATE_LIMITED`.
