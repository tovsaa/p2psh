# Security

## Reporting

Open a GitHub issue with the `security` label for low/medium-severity bugs.
For high-severity issues that would benefit from a fix landing before public
disclosure, email the maintainer (see `git log --format=%ae | sort -u`) — there
is no separate security inbox yet.

## Threat model

P2PSH gives an authenticated peer an interactive shell on the host. The wire
is protected by:

- **ML-KEM-768** (`@noble/post-quantum`, version-pinned, KAT-tested) for
  post-quantum key encapsulation.
- **Ed25519** for server identity. Clients pin the server's `idPublicKey` out
  of band (it ships inside the `p2psh1://` connect string).
- **ChaCha20-Poly1305** AEAD over a per-direction nonce (`c2s` / `s2c`) and a
  64-bit sequence counter. Receiver enforces a 1024-frame sliding anti-replay
  window — Nym reorders frames, so out-of-order is normal but old frames are
  rejected.
- **Session resume** via HKDF-rotated keys, with the rotated AEAD-sealed
  "RESUMED" payload acting as the server's proof of possession.

Out of scope:

- **The host itself.** A peer with shell access has whatever the spawned shell
  has. We curate the env (drop `AWS_*`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, ...)
  and offer `P2PSH_RESTRICT=1` for `rbash`, but neither is a real sandbox.
  Run inside a container (the published image does) and don't bind-mount
  credentials.
- **The browser bundle.** If the bundle the user loads is tampered with — by
  a compromised CDN, a rogue extension, or an attacker who has write access
  to the GitHub Pages deployment — they can exfiltrate session keys. We do
  not currently SRI-pin sub-resources or sign the bundle.

## Known limitations

| Item | Severity | Note |
|---|---|---|
| Browser `localStorage` resume key | medium | XSS on this origin reads the symmetric key. Mitigation: clear `p2psh-resume:*` keys, or use the CLI client (filesystem-scoped state). See README "Browser session resume — threat model". |
| `werift` transitive `ip@*` SSRF (GHSA-2p57-rm9w-gvfp) | medium | We do not call `ip.isPublic()`. CI's `npm audit` gates on CRITICAL only, with `HIGH` documented as an exception. Revisit when `werift` adopts `@isaacs/ip-fork` or when we migrate WebRTC libraries. |
| WebRTC mode exposes peer IP via STUN | inherent | A direct P2P UDP path requires reflexive-address discovery. The web client falls back to the Nym tunnel automatically when STUN fails or the NAT looks symmetric; users wanting full anonymity for bulk traffic should pick Nym manually. We do not ship a TURN relay. |
| Forward secrecy through resume is partial | low | Resume rotates the AEAD key via HKDF of the previous key plus a fresh client salt. Compromise of a current resume key reveals all future resume keys derived from it (until a full ML-KEM handshake). Past AEAD ciphertext recorded before the most recent resume is NOT recoverable. A new ML-KEM exchange on every resume would give perfect FS at the cost of a Kyber round-trip — deferred. |
| `@noble/post-quantum` is the only ML-KEM impl | low | Audited by Cure53 (Feb 2024), version-pinned to `0.4.1`. Regression-guarded by `tests/ml-kem-kat.ts` with hardcoded known-answer vectors so a future bump can't silently change KEM behavior. |
| No application-layer crypto over WebRTC DTLS | accepted | In WebRTC mode shell frames travel as plaintext JSON inside DTLS. The peer authenticates via the ML-KEM/Ed25519 layer before the channel opens; once open, DTLS is the only layer. In Nym mode every frame is AEAD-sealed end-to-end. |

## What's protected vs. what's not

- An on-path observer on the Nym mixnet sees only ciphertext frames between
  the server and clients. The signaling layer (SDP / ICE / resume) is always
  AEAD-sealed.
- An on-path observer on the WebRTC data plane sees DTLS-encrypted SCTP. They
  learn the *existence* of a session and the peer's reflexive IP, but no
  contents.
- An on-path observer on the Nym tunnel (`P2PSH_TRANSPORT=nym`) sees the same
  ciphertext as on signaling; the peer's reflexive IP is never exposed.
- A passive observer who later compromises the server's ML-KEM secret key
  cannot decrypt past traffic — the KEM gives forward secrecy at handshake
  time. Resume chains have the caveat documented above.
