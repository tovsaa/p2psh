# syntax=docker/dockerfile:1.7
#
# All-in-one P2PSH server image.
#
# Bundles:
#   - nym-client (Linux native binary, pinned release)
#   - Node.js server compiled to JS by tsx-loader at runtime
#
# Runs both processes under a tiny bash supervisor so `docker run` is enough:
#   docker run -d --name p2psh -v p2psh-data:/data ghcr.io/tovsaa/p2psh:latest
#
# The volume preserves: the server's ML-KEM/Ed25519 identity, the nym-client's
# gateway registration + surb store, and resume session map (in-memory today;
# kept here for future persistence).

# ---------- Stage 1: Node dependencies ----------
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
# node-pty needs build tools to compile from source on arches without prebuilt
# binaries. Slim base lacks them — install briefly, then this stage is discarded.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 make g++ \
    && rm -rf /var/lib/apt/lists/* \
    && npm ci --omit=optional --ignore-scripts=false

# ---------- Stage 2: nym-client binary ----------
FROM debian:bookworm-slim AS nym
ARG NYM_VERSION=nym-binaries-v2026.9-venaco
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
# Upstream nymtech/nym publishes only an amd64 ELF; the bare `nym-client`
# asset name carries no arch suffix but `file` reports `x86-64`. There's no
# official arm64 / armhf binary. For ARM hosts: build nym-client from source
# (cargo build --release -p nym-client; see README "Building for arm64") and
# either:
#   a) build this image on an ARM host with a pre-fetched binary at
#      ./nym-client (replace the wget below with `COPY nym-client ...`), or
#   b) use a multi-stage rust:slim builder to compile inside the image.
# We refuse to silently package an amd64 binary into an arm64 image — that
# would produce a container that "starts" but crashes the moment Linux
# tries to ld-linux-x86-64.so.2 it.
RUN case "$TARGETARCH" in \
        amd64) \
            wget -q "https://github.com/nymtech/nym/releases/download/${NYM_VERSION}/nym-client" -O /usr/local/bin/nym-client \
            && chmod +x /usr/local/bin/nym-client \
            ;; \
        arm64|armhf|*) \
            echo "ERROR: TARGETARCH=$TARGETARCH is not supported by the published Dockerfile." >&2; \
            echo "Upstream nymtech/nym publishes amd64 only. See README 'Building for arm64'." >&2; \
            exit 1 \
            ;; \
    esac

# ---------- Stage 3: runtime ----------
FROM node:22-slim

# `node:22-slim` ships yarn at /opt/yarn-* (~7 MB) which we don't use — pure
# npm. Drop it together with the apt install in a single RUN so the cleanup
# stays in the same layer, plus add /data with the right ownership while
# we're at it (avoids a 200+ MB `chown -R` layer over /app later).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && mkdir -p /data /app \
    && chown node:node /data /app

WORKDIR /app

# `node:22-slim` already ships a non-root `node` user (UID 1000). Reuse it so
# the image works on hosts that bind-mount paths owned by 1000.
# Use --chown on every COPY so the file ownership is set in-place (single
# layer per copy) rather than walking the tree afterwards. The old
# `chown -R node:node /app` rewrote permission bits on the ~190 MB
# node_modules tree, which made it a second copy in a new layer.
COPY --from=nym  /usr/local/bin/nym-client /usr/local/bin/nym-client
COPY --chown=node:node --from=deps /app/node_modules ./node_modules
COPY --chown=node:node package.json tsconfig.json ./
COPY --chown=node:node src ./src
COPY docker/entrypoint.sh /usr/local/bin/p2psh-entrypoint
RUN chmod +x /usr/local/bin/p2psh-entrypoint

ENV P2PSH_IDENTITY=/data/server-identity.json \
    P2PSH_NYM_URL=ws://127.0.0.1:1977 \
    P2PSH_SHELL=bash \
    P2PSH_SHELL_ARGS="" \
    NYM_CLIENT_ID=p2psh \
    HOME=/data/home

USER node
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/p2psh-entrypoint"]
