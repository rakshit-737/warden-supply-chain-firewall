# Data Model

PostgreSQL. Managed via SQLAlchemy 2.0 (typed, declarative) and Alembic migrations.
JSONB is used where a column stores a variable-shape but query-secondary payload (signal
evidence, feature vectors, policy rules).

```mermaid
erDiagram
    USERS ||--o{ SCANS : requests
    USERS ||--o{ AUDIT_EVENTS : actor
    USERS ||--o{ REFRESH_TOKENS : owns
    POLICIES ||--o{ SCANS : evaluated_by
    SCANS ||--o{ SIGNALS : produces

    USERS {
        uuid id PK
        string email UK
        string password_hash
        enum role  "admin|analyst|viewer"
        bool is_active
        timestamptz created_at
    }
    REFRESH_TOKENS {
        uuid id PK
        uuid user_id FK
        string token_hash UK
        timestamptz expires_at
        bool revoked
    }
    POLICIES {
        uuid id PK
        string name
        bool is_active
        int warn_threshold
        int block_threshold
        int min_package_age_days
        jsonb blocked_capabilities
        jsonb allowlist
        jsonb denylist
        timestamptz updated_at
    }
    SCANS {
        uuid id PK
        uuid requested_by FK
        uuid policy_id FK
        string ecosystem
        string package_name
        string version
        int rule_score
        int ml_score
        int risk_score
        enum severity  "info|low|medium|high|critical"
        enum decision  "allow|warn|block"
        jsonb feature_vector
        string analyzer_version
        int duration_ms
        timestamptz created_at
    }
    SIGNALS {
        uuid id PK
        uuid scan_id FK
        string code
        enum severity
        float weight
        string message
        jsonb evidence
    }
    AUDIT_EVENTS {
        uuid id PK
        uuid actor_id FK
        string action
        string target_type
        string target_id
        jsonb metadata
        string request_id
        timestamptz created_at
    }
```

## Notes & rationale

- **UUID primary keys** avoid enumerable ids in the API surface.
- **`SCANS.feature_vector` (JSONB)** stores the exact numeric features fed to the model,
  which makes verdicts reproducible and lets the dashboard show feature contributions.
- **`SIGNALS`** is a child table rather than a JSON blob on the scan so signals are
  independently queryable (e.g. "how many packages this month tripped `INSTALL_NETWORK`").
- **`REFRESH_TOKENS.token_hash`** stores only a hash — a database leak does not yield
  usable refresh tokens.
- **`AUDIT_EVENTS`** is append-only by convention (no update/delete routes) and carries
  the `request_id` so a verdict can be traced to the exact HTTP request.
- **`analyzer_version`** is part of the cache key and stored on every scan so historical
  verdicts remain interpretable after analyzer logic changes.
