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
# Upstream publishes only the host arch from their CI runner. amd64 is always
# present; arm64 builds are sporadic. For arm64 hosts you may need to rebuild
# nym-client from source — see README for the build instructions.
RUN case "$TARGETARCH" in \
        amd64) suffix="" ;; \
        arm64) suffix="" ;; \
        *) echo "unsupported arch: $TARGETARCH"; exit 1 ;; \
    esac \
    && wget -q "https://github.com/nymtech/nym/releases/download/${NYM_VERSION}/nym-client${suffix}" -O /usr/local/bin/nym-client \
    && chmod +x /usr/local/bin/nym-client

# ---------- Stage 3: runtime ----------
FROM node:22-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# `node:22-slim` already ships a non-root `node` user (UID 1000). Reuse it so
# the image works on hosts that bind-mount paths owned by 1000.
COPY --from=nym  /usr/local/bin/nym-client /usr/local/bin/nym-client
COPY --from=deps /app/node_modules ./node_modules
COPY package.json tsconfig.json ./
COPY src ./src

# Identity + nym-client state live here; mount a volume to persist across runs.
RUN mkdir -p /data && chown -R node:node /data /app
ENV P2PSH_IDENTITY=/data/server-identity.json \
    P2PSH_NYM_URL=ws://127.0.0.1:1977 \
    P2PSH_SHELL=bash \
    P2PSH_SHELL_ARGS="" \
    NYM_CLIENT_ID=p2psh \
    HOME=/data/home

COPY docker/entrypoint.sh /usr/local/bin/p2psh-entrypoint
RUN chmod +x /usr/local/bin/p2psh-entrypoint

USER node
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/p2psh-entrypoint"]
