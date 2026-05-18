# P2PSH — VPN/tunnel replacement via P2P + Nym signaling + ML-KEM

**Status:** end-to-end working through real Nym mixnet, from a real browser
terminal into a real shell on the server: ML-KEM-768 key exchange, Ed25519
server identity pinning, ChaCha20-Poly1305 session, WebRTC DataChannel
brought up with all SDP/ICE wrapped inside the AEAD session, PTY shell on
the server piped to an xterm.js terminal in the browser.

## Architecture (target)

```
  Browser (GitHub Pages)                          Linux server
  ┌─────────────────────────┐                  ┌─────────────────────────┐
  │  web UI                 │                  │  SSH-bridge script      │
  │  ML-KEM-768 client      │                  │  ML-KEM-768 server      │
  │  WebRTC DataChannel ◄───┼─── P2P (E2E) ────┼──► werift DataChannel   │
  │  Nym SDK (WASM)         │   signaling      │  nym-client binary      │
  └─────────────────────────┘   via mixnet     └─────────────────────────┘
```

## Layout

- `src/shared/protocol.ts`     — wire format + cross-platform base64url
- `src/shared/handshake.ts`    — ML-KEM-768 + Ed25519 transcript signature +
                                 HKDF-SHA256 + ChaCha20-Poly1305 with
                                 sliding-window anti-replay (Nym reorders)
- `src/shared/signaling.ts`    — SDP / ICE / app envelope types
- `src/shared/nym-transport.ts` — Node side: talks to local `nym-client` WS
- `src/shared/webrtc-peer.ts`   — Node side: werift PeerConnection bring-up
- `src/server/main.ts`         — Node server entry, in-memory session resume map
- `src/server/ssh-bridge.ts`   — spawns a PTY on DataChannel open and bridges
                                 stdin/stdout/resize over a tiny JSON envelope
- `src/client/cli.ts`          — Node CLI client (handy for testing, echo loop)
- `web/index.html`             — minimal browser UI
- `web/src/main.ts`            — browser entry: same handshake + native WebRTC
- `web/src/nym-browser.ts`     — browser side: `@nymproject/sdk-full-fat` WASM

## Prerequisites

Two **separate** `nym-client` identities are needed (one for the server side,
one for the client CLI). On Windows, run them inside **WSL** — Nym does not
ship a Windows build.

```bash
# In WSL (Ubuntu):
# 1. Download nym-client binary from https://github.com/nymtech/nym/releases
#    Put it on PATH or in this folder.

# 2. Initialize two separate clients (different IDs => different mix addresses)
./nym-client init --id p2psh-server
./nym-client init --id p2psh-clientcli

# 3. Run them on different ports (default :1977 for the first, override for the second)
./nym-client run --id p2psh-server                                # ws://127.0.0.1:1977
./nym-client run --id p2psh-clientcli --port 1978                 # ws://127.0.0.1:1978
```

## Run the MVP

From Windows PowerShell, two terminals:

```powershell
# Terminal 1 — server
npm install
$env:P2PSH_NYM_URL = "ws://127.0.0.1:1977"
npm run server
# Note down the printed P2PSH_SERVER_ADDR and P2PSH_SERVER_PK
```

```powershell
# Terminal 2 — client
$env:P2PSH_NYM_URL     = "ws://127.0.0.1:1978"
$env:P2PSH_SERVER_ADDR = "<mix address from terminal 1>"
$env:P2PSH_SERVER_PK   = "<ML-KEM-768 public key from terminal 1>"
$env:P2PSH_SERVER_IDPK = "<Ed25519 identity key from terminal 1>"
npm run client
```

Expected output:

```
[client] my mix address: ABc...
[client] sending ClientHello to XyZ...
[client] handshake verified — Ed25519 signature OK, session key agreed.
[client] decrypted from server: echo: hello from client

[server] handshake complete with ABc...
[server] decrypted from client: hello from client
```

A successful round-trip proves: (a) the server is the holder of the Ed25519
identity key the client pinned, (b) ML-KEM agreed on a shared secret bound to
that identity (the signature covers the KEM ciphertext + server KEM pk), (c)
both sides derived the same AEAD key, (d) the entire conversation went through
the Nym mixnet — the local `nym-client` never saw the plaintext.

## Connect string

The server prints a single `p2psh1://…` URI bundling its mix address, ML-KEM
public key, and Ed25519 identity key. Paste it into the browser's one field,
or share a direct link that auto-fills:

```
https://<your-pages-host>/#c=<url-encoded-p2psh1-uri>
```

Set `P2PSH_WEB_URL=https://<your-pages-host>` on the server and it will print
the ready-to-share link too. The CLI accepts `P2PSH_CONNECT=p2psh1://…` as a
single env var (legacy `P2PSH_SERVER_*` still work).

## Browser client (Vite, dev mode)

The server still runs in WSL/Linux against a local `nym-client`. The browser
talks to the mixnet directly using `@nymproject/sdk-full-fat` (WASM) — **no
second `nym-client` instance is needed for the browser side**.

```powershell
npm run web        # starts Vite at http://127.0.0.1:5173
# Open the page, paste the three values the server printed, click Connect.
# After ~3 s the WASM client connects to a Nym gateway, then ClientHello
# crosses the mixnet (typically 1-3 min today), then the WebRTC DataChannel
# opens and "echo: hello from browser via DataChannel" prints.
```

## Deploy: server (Docker / GHCR)

A ready-to-pull image is built by `.github/workflows/container.yml` and pushed
to `ghcr.io/tovsaa/p2psh` on every push to `main` and every `v*` tag.

```bash
docker run -d --name p2psh \
  -v p2psh-data:/data \
  -e P2PSH_WEB_URL=https://tovsaa.github.io/P2PSH \
  ghcr.io/tovsaa/p2psh:latest

docker logs p2psh    # copy the p2psh1:// connect string from here
```

The image bundles a pinned `nym-client` and supervises both processes under
`tini`. The `p2psh-data` volume preserves the ML-KEM/Ed25519 identity and
nym-client gateway registration across restarts — without it the server's
identity (and any saved resume sessions on clients) would rotate every boot.

amd64 only for now; arm64 needs a hand-built `nym-client` because upstream
publishes only x86_64 binaries. Build with: clone nymtech/nym, then
`cargo build --release -p nym-client`, and bind-mount the binary in.

## Deploy: web (GitHub Pages)

`.github/workflows/pages.yml` builds with Vite and publishes on every push to
`main`. One-time repo setup: **Settings → Pages → Source: GitHub Actions**.

The bundle's base path is derived from the repo name automatically. After the
first deploy the site lives at `https://tovsaa.github.io/P2PSH/`.

## Session resume

After the first ML-KEM handshake completes, both sides derive a 16-byte
`sessionId` from the shared secret and remember the AEAD key. On the next
connect:

- Client (browser → `localStorage`, CLI → `./data/client-state-<hash>.json`)
  sends `{ t: "resume", sessionId, salt }` *first* with a fresh 16-byte salt.
- Server looks up the saved key, derives `newKey = HKDF(oldKey, salt, "resume")`,
  resets seq counters to 0, and sends back an AEAD-sealed `RESUMED` token
  under `newKey`. Verifying decrypt is the proof of possession.
- Client verifies, both sides save the rotated key, WebRTC proceeds.
- If server doesn't recognize `sessionId` (server restart, key forgotten) it
  sends `{ t: "resume-nack" }` in cleartext and the client transparently
  falls back to a full ML-KEM handshake.

Server-side resume state is in-memory only. Persisting it across restarts
would let a snapshot of the disk replace a long-term identity key with a
short-term forward secret; deliberate omission for now.

## Known quirks

- `node-pty` prints an `AttachConsole failed` line on stderr at startup on
  Windows when run from a headless process (no console attached to the
  parent). The PTY itself works fine — the warning comes from a separate
  bookkeeping helper inside node-pty. Does not appear on Linux servers.
- Late-arriving frames from the previous session after a resume are silently
  dropped (they hit the new anti-replay window with wire seqs that overlap
  the new session's). Visible only with debug logging enabled.

## Next steps

- Pin the shell to a non-interactive `ssh fixed-user@localhost` instead of a
  raw PTY for stricter session policy on multi-tenant servers
- Optional: drop the WSL dependency on Linux servers (the production case is
  Linux native, only the Windows dev setup needs WSL)

## Configuration

| env var               | default                 | meaning                                |
|-----------------------|-------------------------|----------------------------------------|
| `P2PSH_NYM_URL`       | `ws://127.0.0.1:1977`   | local nym-client native WS endpoint    |
| `P2PSH_IDENTITY`      | `./data/server-identity.json` | server's ML-KEM keypair store    |
| `P2PSH_SERVER_ADDR`   | —                       | (client only) server's mix address     |
| `P2PSH_SERVER_PK`     | —                       | (client only) server's ML-KEM-768 pk   |
| `P2PSH_SERVER_IDPK`   | —                       | (client only) server's Ed25519 identity pk (pinned) |
| `P2PSH_SHELL`         | `wsl.exe` (Windows) / `bash` | shell to spawn for the bridged PTY     |
| `P2PSH_SHELL_ARGS`    | (empty)                 | space-separated args, e.g. `-d Ubuntu` to pick a WSL distro |
