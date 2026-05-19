# P2PSH

[![container](https://github.com/tovsaa/p2psh/actions/workflows/container.yml/badge.svg)](https://github.com/tovsaa/p2psh/actions/workflows/container.yml)
[![pages](https://github.com/tovsaa/p2psh/actions/workflows/pages.yml/badge.svg)](https://github.com/tovsaa/p2psh/actions/workflows/pages.yml)
[![ghcr image](https://img.shields.io/badge/ghcr.io-tovsaa%2Fp2psh-blue?logo=github)](https://github.com/tovsaa/p2psh/pkgs/container/p2psh)
[![web client](https://img.shields.io/badge/web%20client-tovsaa.github.io%2Fp2psh-success)](https://tovsaa.github.io/p2psh/)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**An SSH-like shell into your Linux box, with the server addressable only as a
mixnet identity.** No public IP, no port forwarding, no domain or TLS
certificate. The browser is the client; the server can sit behind NAT, CGNAT,
or a corporate firewall.

The wire goes:

```
  Browser                         Nym mixnet                       Linux server
  ┌───────────────────┐           (signaling only;                 ┌───────────────────┐
  │  xterm.js         │            sees ciphertext)                │  PTY shell        │
  │  ML-KEM-768       │       ┌──────────────┐                     │  node-pty         │
  │  Ed25519 verify   │  ◄──► │ SDP + ICE +  │ ◄────────────────►  │  ML-KEM-768       │
  │  ChaCha20-Poly1305│       │ resume frames│                     │  Ed25519 sign     │
  │  @nymproject/sdk  │       │ inside AEAD  │                     │  nym-client       │
  └────────┬──────────┘       └──────────────┘                     └──────────┬────────┘
           │                                                                  │
           └────────────────── WebRTC DataChannel ──────────────────────────  ┘
                              (UDP P2P, post-handshake)
```

- **Key exchange:** ML-KEM-768 (post-quantum, `@noble/post-quantum`, version-pinned with a [KAT regression test](tests/ml-kem-kat.ts)) → HKDF-SHA256 → ChaCha20-Poly1305. Threat model and known limitations: see [`SECURITY.md`](SECURITY.md).
- **Server authentication:** Ed25519 signature over the transcript, client pins the public key.
- **Signaling:** every SDP / ICE / resume frame travels through Nym, AEAD-sealed; the gateway sees only encrypted bytes.
- **Data plane:** browser-native `RTCPeerConnection` ↔ `werift` on Node.js. After WebRTC is up, Nym is idle.
- **Session resume:** an HKDF-rotated key persists in the browser's `localStorage`; subsequent connects skip the full ML-KEM round-trip.

## Quick start

You need: Docker on the server box, a modern browser anywhere.

```bash
docker run -d --name p2psh --restart=unless-stopped \
  -v p2psh-data:/data \
  -e P2PSH_WEB_URL=https://tovsaa.github.io/p2psh \
  ghcr.io/tovsaa/p2psh:latest

docker logs p2psh
```

Copy the `p2psh1://…` line or the direct-link from the log, open it in a
browser, click Connect. After a few seconds a live shell on the server appears.

The `p2psh-data` volume holds the server's identity and `nym-client`
gateway registration; keep it across restarts to preserve session resume.

## Web client

Hosted at <https://tovsaa.github.io/p2psh/> via the `pages` workflow in this
repo. The bundle is pure static — drop it on any HTTPS host and it will work,
the WASM Nym SDK is bundled inline.

## Configuration

Server-side env vars (set with `-e` on `docker run`):

| Var                  | Default                            | Purpose                                              |
|----------------------|------------------------------------|------------------------------------------------------|
| `P2PSH_IDENTITY`     | `/data/server-identity.json`       | ML-KEM + Ed25519 keypair file; auto-generated        |
| `P2PSH_NYM_URL`      | `ws://127.0.0.1:1977`              | local `nym-client` native WS endpoint                |
| `P2PSH_SHELL`        | `bash`                             | shell to spawn for each connection                   |
| `P2PSH_SHELL_ARGS`   | (empty)                            | space-separated args, e.g. `-l` for a login shell    |
| `P2PSH_RESTRICT`     | (unset)                            | set to `1` to swap `bash` for `rbash` on POSIX       |
| `P2PSH_AUDIT_LOG`    | (unset)                            | path to append per-peer keystroke audit lines        |
| `P2PSH_TRANSPORT`    | `any`                              | allowlist of data-plane transports the server accepts: `any`, `webrtc`, `nym`, or comma list |
| `P2PSH_WEB_URL`      | (unset)                            | public web-client URL; if set, the server also prints a ready-to-share deep link |
| `NYM_CLIENT_ID`      | `p2psh`                            | nym-client config id (under `$HOME/.nym/clients/`)   |

CLI client env vars (when running `npm run client` directly):

| Var                  | Default                            | Purpose                                              |
|----------------------|------------------------------------|------------------------------------------------------|
| `P2PSH_CONNECT`      | —                                  | the `p2psh1://…` string from the server              |
| `P2PSH_TRANSPORT`    | `webrtc`                           | the transport this client requests; server rejects if not in its allowlist |

### Transport modes

The data plane is **client-chosen**, because the privacy/latency tradeoff
sits with the client: a peer behind symmetric NAT or wanting full mixnet
anonymity may opt out of WebRTC even when the server would happily speak it.
The server only declares which transports it accepts (`P2PSH_TRANSPORT`
allowlist); the client must pick one per session and send it in `hello`/`resume`
(the field is required — there is no implicit default on the wire). A
mismatched request gets an explicit `{t:"error", code:"transport-not-allowed"}`
frame back; a missing/invalid field gets `code:"bad-request"`. Either way the
client sees a fatal reject instead of a silent hang.

- **`webrtc` (client default).** After the ML-KEM handshake the peers swap
  SDP/ICE over Nym, then move all traffic to a P2P WebRTC DataChannel. Lowest
  latency, but each side learns the other's public IP via STUN
  (`stun.l.google.com`, `stun.cloudflare.com`) — Nym anonymity covers the
  handshake only.
- **`nym`.** Every shell frame is AEAD-sealed and routed through the mixnet,
  WebRTC is skipped entirely. Neither side ever learns the other's IP. Latency
  is noticeably higher (typical mixnet RTT is hundreds of ms).

The web client runs a 3s STUN probe on load against two independent STUN
servers (Google and Cloudflare). It classifies the local NAT as:
**`ok`** (srflx consistent — direct P2P should work), **`symmetric`** (the
two STUN servers see different reflexive ports for the same local port —
hole-punch is impossible without a TURN relay, which we don't ship), or
**`blocked`** (no srflx at all — UDP egress blocked or captive portal). The
last two disable the WebRTC radio and force the Nym tunnel.

### Browser session resume — threat model

The web client persists the post-handshake symmetric key in `localStorage`
keyed by the server's Ed25519 identity. This lets repeated connects skip the
ML-KEM round-trip. Caveats:

- **XSS reads it.** Any script that runs in this origin (a compromised bundle,
  an injected dev tool, a malicious browser extension) can read both the key
  and the session id, then resume your session from another box. There is no
  pure technical fix that keeps both convenience and XSS-resistance without a
  user passphrase, so we keep the convenience and document it instead.
- **Mitigations.** Clear it manually any time:
  ```js
  for (const k of Object.keys(localStorage)) if (k.startsWith("p2psh-resume:")) localStorage.removeItem(k);
  ```
  For higher-security setups, use the CLI client (`npm run client`) — its
  resume state lives in `./data/client-state-*.json` and is filesystem-scoped,
  not exposed to any page.
- **What a stolen key buys.** Only the live session's symmetric key. The
  server's Ed25519 identity stays private; without it nobody can impersonate
  the server. The stolen key cannot decrypt past traffic captured before the
  most recent resume (each resume rotates via HKDF), but it CAN read and inject
  traffic on the current session until the server tears it down (full
  handshake from a different client) or restarts.

### Shell hardening

By default the spawned shell gets a curated env (PATH, HOME, LANG, TERM, …);
host credentials like `AWS_*`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK` are dropped
before `spawn`. Set `P2PSH_RESTRICT=1` to switch to `rbash` on POSIX. Set
`P2PSH_AUDIT_LOG=/var/log/p2psh-audit.log` to record every keystroke line
with an ISO timestamp and a short peer label.

## Development

Requires Node.js 22+, npm, and (on Windows) WSL for the server-side shell.

```bash
git clone https://github.com/tovsaa/p2psh && cd p2psh
npm install
```

Run server, web, and (optionally) a Node CLI client in three terminals:

```bash
npm run server          # server, advertises a p2psh1:// connect string
npm run web             # Vite dev server at http://127.0.0.1:5173
P2PSH_CONNECT=p2psh1://… npm run client   # CLI smoke test
```

The server needs a `nym-client` reachable on `P2PSH_NYM_URL`. Inside the Docker
image one is supervised for you; locally, install [`nym-client`](https://github.com/nymtech/nym/releases)
and run `nym-client init --id p2psh && nym-client run --id p2psh`.

`npm run typecheck` runs `tsc --noEmit`.

## Deployment

### Server image (GHCR)

`.github/workflows/container.yml` builds and pushes to
`ghcr.io/tovsaa/p2psh` on every push to `main` and every `v*` tag. The image
bundles a pinned `nym-client` and supervises both processes under `tini`.

amd64 only for now: upstream Nym publishes only x86_64 binaries. For arm64,
clone `nymtech/nym`, run `cargo build --release -p nym-client`, and bind-mount
the resulting binary into the container at `/usr/local/bin/nym-client`.

### Web client (GitHub Pages)

`.github/workflows/pages.yml` builds with Vite and deploys via the official
Pages action on every push to `main`. One-time repo setup:
**Settings → Pages → Source: GitHub Actions**. The bundle base path is
derived from the repo name, so forks just work.

### Where the server can live

The server has no inbound network requirement — only outbound HTTPS/WS to Nym
gateways and UDP for WebRTC. Anything that can run a long-lived Docker
container with a small persistent volume works: home PC behind NAT,
Raspberry Pi, any €4 VPS (Hetzner, DO, Vultr…), Oracle Always Free, Fly.io
with a `[mounts]` block. Serverless / edge platforms (Vercel, Cloudflare
Workers, Deno Deploy) do **not** work — they lack persistent processes,
`spawn`, and long-lived sockets.

## Protocol details

The wire format and crypto choices are in [`src/shared/protocol.ts`](src/shared/protocol.ts)
and [`src/shared/handshake.ts`](src/shared/handshake.ts). High-level summary:

**Initial handshake.** Client picks an ephemeral ML-KEM-768 secret, encapsulates
against the server's pinned KEM public key, sends `{t:"hello", kemCt, replyTo}`
through Nym. Server decapsulates, derives the AEAD key via HKDF-SHA256,
signs `H("p2psh/v0/transcript" || kemPk || kemCt)` with its Ed25519 identity
key, replies with `{t:"ack", enc, sig}` where `enc = AEAD("ok")`. Client
verifies the signature, then the AEAD decrypt, in that order — so a wrong
identity can't poison the receive counter.

**Session resume.** A 16-byte `sessionId = HKDF(sharedSecret, "session-id")` is
derived on both sides at handshake time. The browser keeps `{sessionId, key}`
in `localStorage`; the server keeps it in memory. On the next connect the
client sends `{t:"resume", sessionId, salt}`; server rotates the key via
`HKDF(oldKey, salt, "resume")`, resets seq counters, and replies with an
AEAD-sealed `RESUMED` token under the new key — verifying decrypt is the
proof of possession. If the sessionId is unknown (server restart) the server
returns `{t:"resume-nack"}` in cleartext and the client transparently falls
back to a full ML-KEM handshake.

**Anti-replay.** Each direction has its own ChaCha20-Poly1305 nonce constructed
as `dirTag || be64(seq)`. The receiver tracks a sliding-window of seen seqs
(IPsec ESP style) instead of strict ordering, because Nym reorders.

**WebRTC bring-up.** Once the AEAD channel is up, both sides exchange SDP and
ICE candidates wrapped in `AppData` frames. The mixnet sees only ciphertext —
crucially, it does not see the public IPs in ICE candidates. After the
DataChannel opens, application traffic flows peer-to-peer over WebRTC; Nym is
no longer in the path.

**Server-side PTY.** A single PTY is spawned per active session, wired to the
DataChannel with a JSON envelope: `{t:"o", d:string}` for output,
`{t:"i", d:string}` for input, `{t:"r", c:cols, r:rows}` for resize.

## Known quirks

- `node-pty` prints `AttachConsole failed` to stderr on Windows when running
  headless (no console attached to the parent). The PTY itself works — this
  is a warning from an internal bookkeeping helper. Does not appear on Linux.
- Late-arriving frames from the previous session after a resume are dropped
  silently (the wire seqs overlap the new session's anti-replay window).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
