# Warden deployment

Hardened Docker Compose stack: `web` (nginx: dashboard + API reverse proxy) → `api` (FastAPI) →
`db` (PostgreSQL 16) and `cache` (Redis 7). A one-shot `migrate` job applies database migrations
before any api container starts. Two optional profiles add Prometheus + Grafana (`observability`)
and the continuous-monitoring worker (`worker`).

> **Status.** These files were checked without a Docker engine: `docker compose config` (Compose
> v5.5.1: model, required variables, all profiles), the compose-spec JSON schema,
> `promtool check config` and `promtool check rules` (every dashboard query), and YAML/JSON parsing.
> `frontend/nginx.conf` was tested with nginx 1.30.4: `nginx -t` and response tests. Those tests
> included runtime re-resolution of `api` against a stand-in DNS server: a start while `api` does not
> resolve, and an api that moves to a new address. Later changes (the image-upload and long-running
> routes) are covered by `nginx -t` inside the built web image in CI, not by the response tests. The images and the stack have **not** been
> built or run, so treat the first `docker compose up --build` as a test run.

## Quick start

```bash
cp .env.example .env           # fill in every REQUIRED value; generation commands are in the file
docker compose up -d --build
docker compose ps              # migrate "exited (0)"; api and web "healthy"
```

Open <http://127.0.0.1:8080> and sign in with `FIRST_ADMIN_EMAIL` / `FIRST_ADMIN_PASSWORD`. The API is
served on the same origin, so the CLI uses `--api http://127.0.0.1:8080`.

| Profile | Adds | Start |
|---|---|---|
| `observability` | Prometheus and Grafana with the provisioned **Warden SOC** dashboard on 127.0.0.1:3000 | create the metrics token file (below), then `docker compose --profile observability up -d` |
| `worker` | `monitor` (`python -m app.workers.monitor`) | `docker compose --profile worker up -d` |

Compose checks required variables across the whole file, so `GRAFANA_ADMIN_PASSWORD` must be set even
if the observability profile is never enabled.

### Metrics token file (observability profile)

The api reads `METRICS_TOKEN` from `.env`. Prometheus has a read-only root filesystem, so it reads the
same token from a Compose file secret, `deploy/secrets/metrics_token`, which Compose bind-mounts at
`/run/secrets/metrics_token`. Compose cannot place `environment:` secrets into read-only containers. The
directory is ignored by git. Create the file from `.env` (the value must be unquoted there, as generated):

```bash
mkdir -p deploy/secrets && chmod 700 deploy/secrets
sed -n 's/^METRICS_TOKEN=//p' .env | tr -d '\r\n' > deploy/secrets/metrics_token
chmod 444 deploy/secrets/metrics_token
```

Prometheus runs as UID 65534 (`nobody`) and the bind mount keeps the host file's owner and mode, so the
file itself must be world-readable. With rootful Docker, the 700 directory still keeps other host users
away from it, and the container's mount does not depend on host directory permissions. Docker Desktop
applies its own file-sharing permissions.

To rotate the token: change `METRICS_TOKEN` in `.env`, rerun the three commands above, then
`docker compose --profile observability up -d --force-recreate api prometheus`. If you scaled out,
add `--scale api=N` again. Until both sides match, every scrape gets HTTP 401 and the dashboard's
**API metrics scrape** panel shows Down.

## Networks

| Network | Internal | Members | Why |
|---|---|---|---|
| `edge` | no | web, api | reverse proxy; web's host port; the api's outbound HTTPS (PyPI, OSV, CISA KEV, FIRST EPSS) |
| `data` | yes | api, migrate, monitor, db, cache | datastores: no host ports, no outbound route |
| `metrics` | yes | api, prometheus, grafana | scraping and dashboard queries |
| `ops` | no | grafana | Grafana's host port |
| `worker_egress` | no | monitor | the worker's outbound HTTPS |

`web` has a fixed address on `edge` (`WARDEN_WEB_IPV4`). The api honours `X-Forwarded-For` /
`X-Forwarded-Proto` only from that address (`TRUSTED_PROXY_IPS` for rate limiting,
`FORWARDED_ALLOW_IPS` for uvicorn).

## What is hardened

- **Secrets:** no defaults (`${VAR:?}`). Redis requires a password. `/metrics` requires a bearer token,
  which Prometheus reads from a file secret.
- **Containers:** `no-new-privileges`, `cap_drop: [ALL]` (db adds back `CHOWN`, `DAC_OVERRIDE`, `FOWNER`,
  `SETGID` and `SETUID` for its root entrypoint step), read-only root filesystem with `noexec`,
  size-capped tmpfs, CPU/memory/pids limits, rotated logs. Long-running services also have
  healthchecks and `restart: unless-stopped`.
- **Migrations:** `migrate` runs `alembic upgrade head` once per `docker compose up`, with only the
  settings migrations need and only the `data` network. api and monitor start after it exited
  successfully; the api image itself no longer migrates on start. When running the image outside
  Compose, run it once with the command `alembic upgrade head` first.
- **Images:** base images pinned by digest. The API runs as UID 10001 with no compilers, and its code is
  owned by root. The model is trained during the build. nginx runs as UID 101 with root-owned config.
- **Edge (frontend/nginx.conf):**
  - Security headers go on every response, errors included. The CSP header matches the `<meta>` policy
    built into `index.html`, plus `frame-ancestors`.
  - `/metrics` and every `/api/v1/health*` path are answered with 404 and never proxied. The container
    healthchecks call the probes inside the api container, the API exempts them from rate limiting,
    and `/ready` queries the database on each call.
  - Request bodies are capped at 5 MiB, except `POST /api/v1/containers/scans` (256 MiB, streamed to
    the API). API read timeouts follow the synchronous work behind each route: 330 s for package
    scans, 660 s for release diffs and on-demand monitoring checks (two analyses), 960 s for image
    scans. Raise `MAX_IMAGE_UPLOAD_BYTES` and the nginx limit together if you need larger images.
    API responses are never gzip-compressed or cached.
  - nginx resolves `api` through Docker's DNS at runtime. A recreated api container is reached at its
    new address without restarting `web`, and `web` starts even while api is down; API requests
    get 502 until it is back.

## Scaling out

```bash
docker compose up -d --scale api=3
```

- Keep `UVICORN_WORKERS=1`: metrics registries are per process.
- Every api container becomes a separate Prometheus target (DNS service discovery in
  `deploy/prometheus/prometheus.yml`) and a separate nginx upstream peer.
- Migrations still run once, in `migrate`.
- The bootstrap admin is created by the api process when it starts. Whether several api containers
  starting together against an empty database do that without conflicts has not been verified, so
  start the stack once with a single api container before scaling out.

## TLS and public exposure

TLS is not included. To serve beyond this host, terminate TLS in front of `127.0.0.1:8080` and set
`WARDEN_PUBLIC_ORIGIN=https://…`. With Grafana, also set `GRAFANA_ROOT_URL` and
`GRAFANA_COOKIE_SECURE=true`. If that proxy is not on the same host, enable nginx's `realip` module in
`frontend/nginx.conf` for its address. Otherwise every client shares the proxy's rate-limit bucket and
the API sees `X-Forwarded-Proto: http`. Docker's userland proxy can have the same effect, making clients
appear as the bridge gateway address. An external load balancer can use `web`'s `/healthz`; the API's
own probes are deliberately not reachable through `web`.

## Observability

- Prometheus discovers every api container through Docker DNS and scrapes each on port 8000 every
  15 s, keeping 15 days / 2 GB of data. It publishes no host port.
- Grafana provisions the `warden-prometheus` datasource and a read-only **Warden SOC** dashboard (folder
  "Warden"). To change the dashboard, edit `deploy/grafana/dashboards/warden-soc.json`; it reloads
  within 60 s.
- **API metrics scrape** (first panel) shows Down when any api container cannot be scraped or none is
  discovered. **Packages scanned** and **Blocked packages** then show "no data" instead of 0.
- The image is `grafana/grafana`, which is the OSS edition. `grafana/grafana-oss` is no longer updated
  (Grafana's Docker installation docs).
- `monitored_packages` is computed by the API from the database on every scrape. `queue_depth` has
  no producer yet, and the worker itself exposes no metrics endpoint.

## Upgrading

- From the v1 compose file: the API no longer publishes host port 8000; use the dashboard origin (also
  for the CLI). The web container listens on 8080, and the host port binds to 127.0.0.1 by default.
- An existing `pgdata` volume keeps the password it was created with; `POSTGRES_PASSWORD` only applies
  to a new volume. To set the new value on an existing volume:

  ```bash
  docker compose up -d db
  docker compose exec db psql -U warden -d warden -c '\password warden'   # enter POSTGRES_PASSWORD
  ```

- Redis now requires `REDIS_PASSWORD` and still persists nothing.
- The observability profile needs `deploy/secrets/metrics_token` (see above).

## Updating pinned images

Pins live in `backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml` and the service
containers in `.github/workflows/ci.yml`, as `image:tag@sha256:…`. Dependabot proposes updates for the
Dockerfiles and `docker-compose.yml` (`.github/dependabot.yml`); keep the ci.yml service images equal to
the `db` and `cache` images by hand. The `trivy-compose-images` job in `.github/workflows/security.yml`
reports known vulnerabilities of the pinned Compose images to code scanning. To resolve a tag's
current multi-arch index digest from the registry (official images use `library/`):

```bash
repo=library/postgres tag=16.15-alpine3.24
token=$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
  | python -c "import json,sys; print(json.load(sys.stdin)['token'])")
curl -fsSI -H "Authorization: Bearer ${token}" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
  "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" | grep -i '^docker-content-digest'
```

## Known limitations

- Images and stack not yet built or run (see Status).
- `backend/requirements.txt` pins versions but not hashes.
- Secrets reach the api and db containers as environment variables, so anyone with Docker API access can
  read them (`docker inspect`). `METRICS_TOKEN` exists twice (in `.env` and in the secret file), and the
  two must be kept equal by hand.
- Labelled counters (`scans_total`, `policy_decisions_total`, `security_events_total`,
  `analyzer_runs_total`) get a series only on their first increment, and `increase()` / `rate()` cannot
  count that first step. A decision, ecosystem or event type seen for the first time after an api start
  is undercounted by one, and a single rare event can be missing from the dashboard entirely. Fixing
  this needs the backend to pre-initialise the known label combinations; the dashboard cannot.
- `app.workers.monitor` and its heartbeat file (`/tmp/warden-monitor.heartbeat`, used by the worker
  healthcheck) are still being implemented by the backend team.
- Grafana on a read-only root filesystem has not been exercised. If it fails to start, add a tmpfs for
  the path it reports.
- No TLS, backups or alerting rules are provided.
