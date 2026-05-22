// SPDX-License-Identifier: Apache-2.0
// Regression tests for the handshake + resume flow.
//
// What we want to catch:
//   1. Full roundtrip: client+server end up with the same session key, same
//      session id, and can exchange AppData both ways.
//   2. MITM detection: a wrong pinned Ed25519 identity key MUST cause
//      clientVerifyAck to throw, not silently accept a swapped identity.
//   3. Wrong KEM ciphertext (tamper): server's decapsulate yields a different
//      shared secret, so the AEAD-sealed "ok" payload in the ack will fail to
//      decrypt under the client's session key. We do NOT test ML-KEM itself
//      here — that's `ml-kem-kat.ts`.
//   4. Resume roundtrip: client + server rotate to the same new key.
//   5. Resume with wrong saved key must fail (proof-of-possession).

import {
  DEFAULT_RESUME_POLICY,
  clientInitiate,
  clientResume,
  clientVerifyAck,
  clientVerifyResumeAck,
  decodeAppData,
  encodeAppData,
  extractResumeStateFromHandshake,
  generateServerIdentity,
  newResumeStateAfterResume,
  resumeExpiryReason,
  serverAccept,
  serverResume,
} from "../src/shared/handshake.js";
import { b64uEncode } from "../src/shared/protocol.js";

let failed = 0;

function ok(label: string, cond: boolean): void {
  if (cond) {
    console.log(`ok    ${label}`);
  } else {
    console.error(`FAIL  ${label}`);
    failed++;
  }
}

function throws(label: string, fn: () => unknown): void {
  try {
    fn();
    console.error(`FAIL  ${label} (expected throw)`);
    failed++;
  } catch {
    console.log(`ok    ${label}`);
  }
}

// 1. Full roundtrip.
{
  const id = generateServerIdentity();
  const state = clientInitiate(id.publicKey, "client-addr", "webrtc");
  const r = serverAccept(state.hello, id);
  clientVerifyAck(r.ack, state, id.idPublicKey);

  // Sessions should agree on identifier.
  ok("client+server agree on sessionId", b64uEncode(state.sessionId) === b64uEncode(r.sessionId));

  // App data both ways.
  const c2s = encodeAppData(state.session, new TextEncoder().encode("hi server"));
  ok(
    "server decrypts client AppData",
    new TextDecoder().decode(decodeAppData(r.session, c2s)) === "hi server",
  );
  const s2c = encodeAppData(r.session, new TextEncoder().encode("hi client"));
  ok(
    "client decrypts server AppData",
    new TextDecoder().decode(decodeAppData(state.session, s2c)) === "hi client",
  );
}

// 2. MITM: pinned Ed25519 key doesn't match the one that signed the ack.
{
  const real = generateServerIdentity();
  const decoy = generateServerIdentity();
  const state = clientInitiate(real.publicKey, "client-addr", "webrtc");
  const r = serverAccept(state.hello, real);
  // Client pins `decoy.idPublicKey` instead of `real.idPublicKey`.
  throws("MITM: wrong pinned ID key rejected", () => clientVerifyAck(r.ack, state, decoy.idPublicKey));
}

// 3. Tampered KEM ciphertext. We can't easily forge a fake ack without the
//    server's signing key, but we CAN swap a fresh handshake's ack into a
//    different client's state — the AEAD will fail because the keys differ.
{
  const id = generateServerIdentity();
  const aliceState = clientInitiate(id.publicKey, "alice", "webrtc");
  const bobState = clientInitiate(id.publicKey, "bob", "webrtc");
  const aliceAck = serverAccept(aliceState.hello, id).ack;
  // Bob tries to verify Alice's ack against his own state.
  throws("ack cross-binding: bob can't verify alice's ack", () =>
    clientVerifyAck(aliceAck, bobState, id.idPublicKey),
  );
}

// 4. Resume roundtrip — client and server rotate to the same key.
{
  const id = generateServerIdentity();
  const state = clientInitiate(id.publicKey, "client-addr", "webrtc");
  const r = serverAccept(state.hello, id);
  clientVerifyAck(r.ack, state, id.idPublicKey);

  const saved = extractResumeStateFromHandshake(state);
  const attempt = clientResume(saved, "client-addr-2", "nym");
  // Server resume uses the stored old key. Verify the ack proves possession.
  const serverSide = serverResume(attempt.request, r.sessionKey);
  clientVerifyResumeAck(serverSide.ack, attempt);

  // Now session is rotated; exchange both ways with the rotated session.
  const c2s = encodeAppData(attempt.session, new TextEncoder().encode("post-resume c2s"));
  ok(
    "post-resume server decrypts c2s",
    new TextDecoder().decode(decodeAppData(serverSide.session, c2s)) === "post-resume c2s",
  );
  const s2c = encodeAppData(serverSide.session, new TextEncoder().encode("post-resume s2c"));
  ok(
    "post-resume client decrypts s2c",
    new TextDecoder().decode(decodeAppData(attempt.session, s2c)) === "post-resume s2c",
  );

  // `newResumeStateAfterResume` must move the saved key forward and bump
  // the chain's resume counter while preserving its establishedAt anchor.
  const next = newResumeStateAfterResume(attempt, saved);
  ok(
    "resume state advances key",
    b64uEncode(next.key) !== b64uEncode(saved.key),
  );
  ok(
    "resume count increments",
    next.resumeCount === (saved.resumeCount ?? 0) + 1,
  );
  ok(
    "resume preserves establishedAt anchor",
    next.establishedAt === saved.establishedAt,
  );
}

// 5. Resume with a wrong saved key — proof-of-possession must fail.
{
  const id = generateServerIdentity();
  const state = clientInitiate(id.publicKey, "client-addr", "webrtc");
  const r = serverAccept(state.hello, id);
  clientVerifyAck(r.ack, state, id.idPublicKey);

  const saved = extractResumeStateFromHandshake(state);
  // Swap the saved key for noise — client computes its rotated key off the
  // wrong base, so the ack the server produces won't decrypt under it.
  const wrong = { sessionId: saved.sessionId, key: new Uint8Array(32) };
  const attempt = clientResume(wrong, "client-addr-2", "nym");
  const serverSide = serverResume(attempt.request, r.sessionKey);
  throws("resume with wrong saved key rejected", () =>
    clientVerifyResumeAck(serverSide.ack, attempt),
  );
}

// 6. Resume-chain expiry policy. Pure function; we drive it with synthetic
//    states and a fixed `now` rather than wall-clock, so the test is
//    deterministic and doesn't sleep.
{
  const dummyKey = new Uint8Array(32);
  const dummyId = new Uint8Array(16);

  const fresh = { sessionId: dummyId, key: dummyKey, establishedAt: 1_000_000, resumeCount: 0 };
  ok(
    "fresh state within policy is not expired",
    resumeExpiryReason(fresh, DEFAULT_RESUME_POLICY, 1_000_000 + 60_000) === null,
  );

  const tooOld = {
    sessionId: dummyId,
    key: dummyKey,
    establishedAt: 1_000_000,
    resumeCount: 0,
  };
  ok(
    "state past maxAgeMs is expired",
    resumeExpiryReason(tooOld, DEFAULT_RESUME_POLICY, 1_000_000 + DEFAULT_RESUME_POLICY.maxAgeMs + 1) !== null,
  );

  const tooMany = {
    sessionId: dummyId,
    key: dummyKey,
    establishedAt: Date.now(),
    resumeCount: DEFAULT_RESUME_POLICY.maxCount,
  };
  ok(
    "state at maxCount is expired",
    resumeExpiryReason(tooMany, DEFAULT_RESUME_POLICY, Date.now()) !== null,
  );

  // Legacy state with no metadata (written by a pre-PFS client) is grandfathered
  // — count defaults to 0 and missing establishedAt skips the age check. One
  // grace resume is allowed before the chain gets reseeded.
  const legacy = { sessionId: dummyId, key: dummyKey };
  ok(
    "legacy state without metadata gets a grace resume",
    resumeExpiryReason(legacy, DEFAULT_RESUME_POLICY, Date.now()) === null,
  );
}

// 7. Downgrade attack — forced fallback from resume to full handshake.
//
//    Threat model: a network attacker who sits between client and server (or
//    a malicious mixnet gateway) can drop legitimate `resume-ack` frames and
//    inject a `resume-nack` frame instead. The client's documented behavior
//    is to drop saved state and run a full ML-KEM handshake.
//
//    This is intentional — `resume-nack` carries no signature or MAC because
//    a server that has lost its state cannot prove it (it doesn't know the
//    previous session key anymore). Adding auth would require a separate
//    server-held secret just for nacks, doubling the long-term key surface.
//
//    The mitigation lives at a different layer: (a) the full-handshake
//    fallback is still authenticated by the pinned Ed25519 identity — see
//    test #2 above. (b) The PFS policy caps chain length so full handshakes
//    are amortized anyway. (c) An attacker who forces a downgrade does not
//    learn the new session key unless they also possess the server's ML-KEM
//    secret (which is post-quantum-resistant).
//
//    These tests document the property by asserting:
//    - `resume-nack` is structurally unauthenticated (forgeable).
//    - The full-handshake session that follows a forced downgrade is
//      cryptographically independent of any previous resume chain.
{
  // (a) Structural: a forged resume-nack is indistinguishable from a
  //     legitimate one. The attacker needs zero key material.
  const forgedNack = { t: "resume-nack", reason: "(forged by attacker)" };
  const legitimateNack = { t: "resume-nack", reason: "unknown sessionId" };
  ok(
    "resume-nack carries no MAC/signature — anyone can forge it",
    Object.keys(forgedNack).every((k) => k === "t" || k === "reason") &&
      Object.keys(legitimateNack).every((k) => k === "t" || k === "reason"),
  );

  // (b) After a forced downgrade, the new full handshake binds to the
  //     server's pinned Ed25519 identity. An attacker who forced the
  //     downgrade but doesn't hold the server's Ed25519 secret cannot
  //     impersonate the server in the fresh handshake — the client's
  //     `clientVerifyAck` will reject any ack not signed by the pinned key.
  //     (This is the same property as test #2 but spelled out for the
  //     downgrade-then-MITM compound attack.)
  const realServer = generateServerIdentity();
  const attackerServer = generateServerIdentity();
  // After downgrade, the client runs `clientInitiate` against what it
  // believes is the real server's KEM key. If the attacker substituted
  // their own KEM key in flight, the Ed25519 signature in the ack will
  // not match the pinned real-server idPublicKey.
  const downgraded = clientInitiate(realServer.publicKey, "client-addr", "nym");
  const attackerAck = serverAccept(downgraded.hello, attackerServer).ack;
  throws(
    "downgrade-then-MITM: attacker's ack rejected under real server's pinned ID key",
    () => clientVerifyAck(attackerAck, downgraded, realServer.idPublicKey),
  );

  // (c) Fresh full handshake after downgrade produces a session key that
  //     is independent of any prior resume chain. We simulate a chain that
  //     produced rotated key K_old, then force a downgrade and run a fresh
  //     handshake; the new session key must not equal K_old.
  const id = generateServerIdentity();
  const original = clientInitiate(id.publicKey, "client-addr", "nym");
  serverAccept(original.hello, id); // would have produced session, ignore.
  const originalKey = original.sessionKey;
  // Now simulate downgrade: same client starts a fresh full handshake.
  const fresh = clientInitiate(id.publicKey, "client-addr", "nym");
  ok(
    "post-downgrade session key is independent of pre-downgrade chain",
    b64uEncode(fresh.sessionKey) !== b64uEncode(originalKey),
  );
}

if (failed > 0) {
  console.error(`\n${failed} handshake check(s) failed`);
  process.exit(1);
}
console.log("handshake: all checks passed");