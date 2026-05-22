# Changelog

All notable changes go here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [v0.3.0] — 2026-05-22

### Changed — **wire-breaking**
- **Hybrid ML-KEM-768 + X25519 key exchange.** Every full handshake now
  runs both halves; their 32-byte shared secrets are concatenated and fed
  through HKDF-SHA256 to derive the AEAD key. Wire format bumps to v1
  (TRANSCRIPT_LABEL and HKDF info strings carry `p2psh/v1/...`). v0 peers
  cannot talk to v1 peers: signature verification fails at the transcript
  binding, so the connection drops without silent downgrade. Upgrade
  server and clients together; resume state from v0 is auto-discarded
  because the server's in-memory map is lost on restart anyway. ML-KEM
  byte-level encoding is unchanged, KAT vectors still pass.
  `ClientHello` gains `x25519Pk`; `ServerAck` gains `x25519Pk`.

### Added
- **Resume PFS policy.** Client caps chain length at 24h / 64 resumes
  (overridable via `P2PSH_RESUME_MAX_AGE_MS` / `P2PSH_RESUME_MAX_COUNT`);
  past the cap, the next connect runs a fresh hybrid handshake to break
  forward dependence on the old chain key.
- **`NymTransport.drain()`** for deterministic exit flush from the CLI
  client; replaces the prior fixed 50 ms `setTimeout` flake under load.
- **`.env.example`** documenting prod-hardening flags (`P2PSH_RESTRICT=1`,
  `P2PSH_EPHEMERAL_HOME=1`, conservative DoS caps).
- **Downgrade-attack test scenarios** in `tests/handshake.ts` (forged
  resume-nack, downgrade-then-MITM, post-downgrade key independence).
- **Hybrid-specific tests**: X25519 pk presence on both wire messages,
  tampered X25519 pk breaks signature verification, distinct ephemerals
  across runs.

### Changed
- **Client default `P2PSH_TRANSPORT=nym`** (was `webrtc`). Security-by-
  default against STUN-driven peer IP exposure; opt into WebRTC explicitly
  when low latency matters more than IP privacy. Web client radio button
  defaults match.
- **Dependency bumps.** `@noble/{ciphers,curves,hashes}` 1.x → ^2.2.0;
  `@noble/post-quantum` 0.4.1 → 0.6.1 (exact pin retained, KAT verifies
  byte-level compatibility); TypeScript 5.7 → ^6.0.3; tsx and Vite patch
  bumps. Adapted to noble 2.x: `.js` subpath suffixes, `ed25519.keygen()`
  in place of `ed25519.utils.randomPrivateKey()`.
- **`NymTransport.close()`** now awaits the WS `close` event instead of
  fire-and-forget. `onFrame` validates types instead of using `any`.

### Fixed
- **Web client: Nym signaling listener leak in `runWebRTC`.** Listener
  is now detached on DataChannel open / error / close, and the
  `RTCPeerConnection` is closed when the channel closes. Each reconnect
  no longer accumulates one extra Nym subscriber.
- **Web client: Connect button stuck disabled after a FATAL.** Now
  re-enables in the catch handler so the user can retry without reload.
- **Web client: `window.__p2psh` debug hook exposed in production
  bundles.** Now gated behind `import.meta.env.DEV` — production XSS
  payload can't grab the live `channel.send` reference.

## [v0.2.0] — 2026-05-20

### Added
- **Interactive CLI client** (`npm run client`): raw stdin/stdout
  passthrough to the remote PTY, SIGWINCH-driven resize frames, clean
  exit on remote disconnect or stdin EOF. Pipe mode supported for
  one-shot remote command execution (`echo "ls" | npm run client`).
- **Browser auto-reconnect** with exponential backoff (2 s / 5 s / 15 s,
  then give up). The xterm instance and the WASM Nym SDK survive across
  reconnects; only the AEAD session + data channel are rebuilt. Status
  surfaces in the terminal with ANSI colors.
- **`P2PSH_EPHEMERAL_HOME=1`**: each spawned shell lands in a fresh
  `mkdtemp` `$HOME` (e.g. `/tmp/p2psh-<peer>-XXXXXX`) that's wiped on
  disconnect. Stops a peer from reading the server user's `~/.bashrc`,
  `~/.bash_history`, `~/.ssh/known_hosts`, etc.
- **`tests/protocol.ts`** (30 checks) + **`tests/connect-string.ts`**
  (14 checks): nonce layout, b64u URL-safety, DIR_C2S/DIR_S2C
  distinctness, connect string roundtrip + malformed input rejection.
- **Project hygiene**: CHANGELOG, CONTRIBUTING, .editorconfig,
  `.github/ISSUE_TEMPLATE/*`, PR template, Dependabot config (weekly
  npm with grouped Noble updates; @noble/post-quantum patches ignored
  because KAT bytes need regenerating per bump).

### Changed
- **Web initial bundle: 412 KB → 71 KB** (-83%). Lazy-load xterm.js +
  addon-fit on Connect, so the NAT probe + initial paint don't wait on
  them. The total payload is unchanged; it's just split.
- **Docker arm64 build now fails fast** with a clear error pointing to
  the README "Building for arm64" section. Previously it silently
  packaged the upstream amd64 ELF into an arm64 image, producing a
  container that would crash on Linux start.

### Documented
- README "Building for arm64" — manual `cargo build -p nym-client` path,
  local-COPY hot-patch in the Dockerfile, and a note that the workflow
  flips back to multi-arch once nymtech/nym ships arm64 binaries.

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

[v0.2.0]: https://github.com/tovsaa/p2psh/releases/tag/v0.2.0
[v0.1.1]: https://github.com/tovsaa/p2psh/releases/tag/v0.1.1
[v0.1.0]: https://github.com/tovsaa/p2psh/releases/tag/v0.1.0
