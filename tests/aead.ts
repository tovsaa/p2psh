// SPDX-License-Identifier: Apache-2.0
// Regression tests for SessionCipher (the AEAD layer used over Nym + WebRTC
// signaling, and end-to-end in the Nym tunnel transport).
//
// We are not retesting ChaCha20-Poly1305 itself — `@noble/ciphers` has its own
// vectors. The bugs we want to catch here are in our framing on top of it:
//   1. Direction tags (c2s vs s2c) must be different — using the same key
//      with both directions would make crosswire replay trivial.
//   2. Sequence numbers must increment, must not collide, and a replay of a
//      previously-seen seq must be rejected even after AEAD verification.
//   3. The replay window must accept out-of-order seqs within `windowSize`
//      (Nym reorders messages) but reject everything older.
//   4. A wrong key (eg. resume key vs. fresh handshake key) must fail open(),
//      not silently produce garbage.

import { SessionCipher } from "../src/shared/handshake.js";
import { DIR_C2S, DIR_S2C } from "../src/shared/protocol.js";

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

const key = new Uint8Array(32);
for (let i = 0; i < 32; i++) key[i] = i;

// 1. Basic roundtrip across matched send/recv pair.
{
  const send = new SessionCipher(key, DIR_C2S);
  const recv = new SessionCipher(key, DIR_C2S);
  const msg = new TextEncoder().encode("hello world");
  const { seq, ct } = send.seal(msg);
  const pt = recv.open(seq, ct);
  ok("roundtrip plaintext matches", new TextDecoder().decode(pt) === "hello world");
  ok("first seq is 0", seq === 0);
}

// 2. Direction tags differ — encrypting with DIR_C2S and trying to decrypt
//    with DIR_S2C must fail (mismatched nonces => AEAD tag check fails).
{
  const c2sSender = new SessionCipher(key, DIR_C2S);
  const s2cReader = new SessionCipher(key, DIR_S2C);
  const { seq, ct } = c2sSender.seal(new TextEncoder().encode("x"));
  throws("c2s ciphertext rejected by s2c reader", () => s2cReader.open(seq, ct));
}

// 3. Replay rejection — same seq+ct twice is detected.
{
  const send = new SessionCipher(key, DIR_C2S);
  const recv = new SessionCipher(key, DIR_C2S);
  const { seq, ct } = send.seal(new Uint8Array([1, 2, 3]));
  recv.open(seq, ct);
  throws("replay of seq=0 rejected", () => recv.open(seq, ct));
}

// 4. Out-of-order acceptance within the sliding window. Nym reorders frames,
//    so the receiver MUST tolerate this.
{
  const send = new SessionCipher(key, DIR_C2S);
  const recv = new SessionCipher(key, DIR_C2S);
  const sealed: { seq: number; ct: Uint8Array }[] = [];
  for (let i = 0; i < 10; i++) {
    sealed.push(send.seal(new Uint8Array([i])));
  }
  // Open in reverse order.
  for (let i = sealed.length - 1; i >= 0; i--) {
    const { seq, ct } = sealed[i];
    const pt = recv.open(seq, ct);
    ok(`out-of-order open seq=${seq}`, pt[0] === i);
  }
}

// 5. Window-floor rejection — a frame older than windowSize below maxSeen
//    must be rejected even if its AEAD tag is valid. We construct two senders
//    with the same key but different starting positions to forge an "old" seq.
{
  const recv = new SessionCipher(key, DIR_C2S);
  const senderFar = new SessionCipher(key, DIR_C2S);
  // Burn 1500 seqs on senderFar (replay window is 1024).
  let lastFrame: { seq: number; ct: Uint8Array } | null = null;
  for (let i = 0; i < 1500; i++) {
    lastFrame = senderFar.seal(new Uint8Array([0]));
  }
  recv.open(lastFrame!.seq, lastFrame!.ct);

  // Now try to inject a seq=0 frame (well below the window floor).
  const senderOld = new SessionCipher(key, DIR_C2S);
  const old = senderOld.seal(new Uint8Array([0xff]));
  throws("seq below replay window floor rejected", () => recv.open(old.seq, old.ct));
}

// 6. Wrong key — receiver with a different key must not decrypt.
{
  const sender = new SessionCipher(key, DIR_C2S);
  const wrong = new Uint8Array(32);
  for (let i = 0; i < 32; i++) wrong[i] = 0xab;
  const recv = new SessionCipher(wrong, DIR_C2S);
  const { seq, ct } = sender.seal(new TextEncoder().encode("secret"));
  throws("wrong key rejects ciphertext", () => recv.open(seq, ct));
}

if (failed > 0) {
  console.error(`\n${failed} AEAD check(s) failed`);
  process.exit(1);
}
console.log("aead: all checks passed");