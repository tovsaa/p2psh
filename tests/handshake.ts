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
  clientInitiate,
  clientResume,
  clientVerifyAck,
  clientVerifyResumeAck,
  decodeAppData,
  encodeAppData,
  extractResumeStateFromHandshake,
  generateServerIdentity,
  newResumeStateAfterResume,
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

  // `newResumeStateAfterResume` must move the saved key forward.
  const next = newResumeStateAfterResume(attempt);
  ok(
    "resume state advances key",
    b64uEncode(next.key) !== b64uEncode(saved.key),
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

if (failed > 0) {
  console.error(`\n${failed} handshake check(s) failed`);
  process.exit(1);
}
console.log("handshake: all checks passed");