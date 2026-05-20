# Changelog

All notable changes go here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [v0.1.1] — 2026-05-20

### Changed
- Runtime Docker image trimmed from 846 MB to 604 MB (-29%). Removed the
  `chown -R` layer that was doubling `node_modules` in storage, and dropped
  the unused `yarn` binary the base ships at `/opt/yarn-*`.

### Fixed
- `deploy/docker-compose.yml` pinned image tag `v0.1.0` which doesn't exist —
  `docker/metadata-action` strips the `v` prefix per docker convention. Fixed
  to `0.1.0`.
- `deploy/p2psh.service` used `ProtectHome=tristate` (not a valid value;
  systemd accepts only `true|false|read-only|tmpfs`) plus an inline trailing
  comment on the same line that broke the parser. Switched to
  `ProtectHome=read-only`; the existing `ReadWritePaths=/home/p2psh`
  re-opens the service's own home for writes.

## [v0.1.0] — 2026-05-20

First tagged release.

### Added
- **Client-chosen data plane**: WebRTC peer-to-peer (low latency) or Nym
  mixnet tunnel (full IP anonymity). The client decides per session and
  advertises the choice in `ClientHello`; the server enforces a
  `P2PSH_TRANSPORT` allowlist (`any`|`webrtc`|`nym`|comma-list) and rejects
  mismatches with an explicit `{t:"error", code:"transport-not-allowed"}`
  frame.
- **STUN-based NAT probe** in the web client (3 s on page load against
  Google + Cloudflare STUN). Classifies the local NAT as `ok` / `symmetric`
  / `blocked`; the last two disable the WebRTC radio and force Nym.
- **`Channel` interface + `NymChannel`** abstraction unifying the WebRTC and
  Nym data paths; `ssh-bridge` and the browser terminal speak one surface.
- **werift adapter**: bridges werift's `dc.onMessage.subscribe` stream into
  the `EventTarget`-shaped surface the browser exposes, fixing a
  pre-existing latent bug where `addEventListener("message")` on the
  server-side data channel never fired.
- **Shell hardening**: PTY env curated to `PATH/HOME/USER/LANG/TERM/…`,
  dropping `AWS_*`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, etc. Optional
  `P2PSH_RESTRICT=1` swaps `bash` for `rbash` on POSIX. Optional
  `P2PSH_AUDIT_LOG` appends per-peer keystroke lines.
- **ML-KEM pin**: `@noble/post-quantum@0.4.1` (exact, not `^`) with
  `tests/ml-kem-kat.ts` regression-guarding the byte-stable output.
- **Regression suite**: `tests/aead.ts` (16 checks — replay window,
  direction-tag separation, wrong-key rejection, sliding-window floor),
  `tests/handshake.ts` (9 checks — full roundtrip, MITM rejection, ack
  cross-binding, resume with wrong saved key).
- **CI**: `test.yml` workflow (typecheck + tests + `npm audit
  --audit-level=critical`); `container.yml` gains Trivy SARIF scan
  (HIGH/CRITICAL, ignore-unfixed) uploaded to the Security tab.
- **`SECURITY.md`** with threat model, what's protected vs. not, and known
  limitations (browser localStorage XSS exposure, werift transitive `ip`
  CVE, STUN IP exposure in WebRTC mode, partial PFS via resume chains).
- **`deploy/`** directory: `docker-compose.yml` for self-hosting,
  `p2psh.service` + `nym-client.service` for bare-metal/VM with full
  systemd-level sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome=read-only`, `PrivateTmp`, `RestrictNamespaces`, …).
- **Bundle code-split**: initial chunk dropped from ~7.1 MB to ~413 KB —
  the Nym SDK (~6.7 MB, includes WASM) lazy-loads on Connect click.
- **xterm fit deferred to `requestAnimationFrame`** so the renderer
  measures the container after CSS layout, preventing the 1-column
  terminal we saw in headless tests.
- **CRLF protection**: `.gitattributes` forces LF on `*.sh` files so a
  Windows checkout can't break the Docker entrypoint shebang again.
- **`SPDX-License-Identifier: Apache-2.0`** headers on every source file.

[v0.1.1]: https://github.com/tovsaa/p2psh/releases/tag/v0.1.1
[v0.1.0]: https://github.com/tovsaa/p2psh/releases/tag/v0.1.0
