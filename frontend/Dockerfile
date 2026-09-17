# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# Warden dashboard image: Vite production build served by unprivileged nginx on port 8080.
#
# Base images are pinned by multi-arch index digest (tag kept for readability); Dependabot moves the
# tag and the digest together (see deploy/README.md):
# * node:26-alpine3.24 - build stage only; nothing from it reaches the runtime image.
# * nginxinc/nginx-unprivileged:1.30.x-alpine3.24 - the nginx stable line. Odd minor versions are
#   nginx mainline and are held for manual review in .github/dependabot.yml.

# ---- Stage 1: build the static bundle --------------------------------------------------------
FROM node:26-alpine3.24@sha256:ef24c5053d50fdc3e4e56eb4e7ddb7861874ab0fdc797046ba897581deb8e868 AS builder

WORKDIR /app
COPY package.json package-lock.json ./
# `npm ci` installs exactly the versions and integrity hashes recorded in package-lock.json and fails
# if package.json and the lockfile disagree. --ignore-scripts stops dependency lifecycle scripts from
# running during the build; in the current lockfile only fsevents (macOS only) declares an install
# script, and it is not needed for `vite build` on Linux.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . .
RUN npm run build

# ---- Stage 2: serve with unprivileged nginx --------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.30.5-alpine3.24@sha256:daa17b944bac2b578e962da4c61ad72a59233b3c63abea17113acaf4e6b9aea4 AS runtime

LABEL org.opencontainers.image.title="warden-web" \
      org.opencontainers.image.description="Warden security dashboard (static SPA and API reverse proxy)" \
      org.opencontainers.image.source="https://github.com/rakshit-737/warden-supply-chain-security" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/nginxinc/nginx-unprivileged:1.30.5-alpine3.24" \
      org.opencontainers.image.base.digest="sha256:daa17b944bac2b578e962da4c61ad72a59233b3c63abea17113acaf4e6b9aea4"

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
