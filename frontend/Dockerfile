# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# Warden X dashboard image: Vite production build served by unprivileged nginx on port 8080.
#
# Base images are pinned by multi-arch index digest (tag kept for readability), resolved from
# registry-1.docker.io on 2026-09-15 (see deploy/README.md):
# * node:24-alpine3.24 - Node 24 LTS; its image config reports NODE_VERSION=24.21.0. The
#   24.21.0-alpine3.24 tag pointed at a different index digest on that date, so the pin keeps the
#   tag that was verified to match this digest.
# * nginxinc/nginx-unprivileged:1.30.4-alpine3.24 - the same index as stable-alpine on that date.

# ---- Stage 1: build the static bundle --------------------------------------------------------
FROM node:24-alpine3.24@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS builder

WORKDIR /app
COPY package.json package-lock.json ./
# `npm ci` installs exactly the versions and integrity hashes recorded in package-lock.json and fails
# if package.json and the lockfile disagree. --ignore-scripts stops dependency lifecycle scripts from
# running during the build; in the current lockfile only esbuild (binary check/optimisation) and
# fsevents (macOS only) declare install scripts, and neither is needed for `vite build` on Linux.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . .
RUN npm run build

# ---- Stage 2: serve with unprivileged nginx --------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.30.4-alpine3.24@sha256:adf5042a17f4ecdd200c595fa9ffd1be37efb18f89a830bd1a00e4ab4d59d42c AS runtime

LABEL org.opencontainers.image.title="warden-x-web" \
      org.opencontainers.image.description="Warden X security dashboard (static SPA and API reverse proxy)" \
      org.opencontainers.image.source="https://github.com/rakshit-737/warden-supply-chain-firewall" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/nginxinc/nginx-unprivileged:1.30.4-alpine3.24" \
      org.opencontainers.image.base.digest="sha256:adf5042a17f4ecdd200c595fa9ffd1be37efb18f89a830bd1a00e4ab4d59d42c"

# Root only for the filesystem lock-down below; the final USER is the image's unprivileged nginx (101).
USER root

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

# * The upstream image leaves /etc/nginx writable by the nginx user for its entrypoint helpers. Here
#   config and content are owned by root and read-only for nginx (the listen-on-ipv6 helper only edits
#   default.conf when it is writable, so it skips itself).
# * worker_processes is fixed at 2: "auto" starts one worker per host CPU, ignoring the container's
#   CPU and pids limits. The grep fails the build if the upstream file format changes.
RUN sed -i 's/^worker_processes .*;/worker_processes 2;/' /etc/nginx/nginx.conf \
    && grep -q '^worker_processes 2;$' /etc/nginx/nginx.conf \
    && chown -R root:root /etc/nginx /usr/share/nginx/html \
    && chmod -R go-w /etc/nginx /usr/share/nginx/html

USER 101
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
