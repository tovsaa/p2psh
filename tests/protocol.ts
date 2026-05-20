// SPDX-License-Identifier: Apache-2.0
// Regression tests for the low-level protocol primitives in src/shared/protocol.ts:
//
//   - nonceFor(dir, seq): builds the 12-byte AEAD nonce. If this drifts even
//     one byte, every existing session's transcript becomes unverifiable, so
//     pinning the layout in a test is worth the few lines.
//   - b64uEncode / b64uDecode: the URL-safe base64 we use everywhere on the
//     wire (no padding, `+` -> `-`, `/` -> `_`). Browser-compatible
//     (atob/btoa, not Buffer).
//   - DIR_C2S / DIR_S2C: literal byte arrays. Tested for distinctness so a
//     refactor can't silently make c2s == s2c (which would let any frame be
//     decrypted under the wrong direction's cipher).

import { DIR_C2S, DIR_S2C, b64uDecode, b64uEncode, nonceFor } from "../src/shared/protocol.js";

let failed = 0;

function ok(label: string, cond: boolean): void {
  if (cond) console.log(`ok    ${label}`);
  else {
    console.error(`FAIL  ${label}`);
    failed++;
  }
}

function hex(u: Uint8Array): string {
  return Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
}

// 1. nonceFor produces a stable 12-byte layout: [dir(4)][seq big-endian(8)].
{
  ok("nonce length is 12 for c2s/0", nonceFor(DIR_C2S, 0).length === 12);
  ok("nonce length is 12 for s2c/0", nonceFor(DIR_S2C, 0).length === 12);

  // Direction tags occupy bytes 0..3. "c2s\0" = 0x63 0x32 0x73 0x00.
  ok(
    "c2s nonce starts with 'c2s\\0'",
    hex(nonceFor(DIR_C2S, 0)).startsWith("63327300"),
  );
  // "s2c\0" = 0x73 0x32 0x63 0x00.
  ok(
    "s2c nonce starts with 's2c\\0'",
    hex(nonceFor(DIR_S2C, 0)).startsWith("73326300"),
  );

  // Seq encoded big-endian in bytes 4..11.
  ok("seq=0 packs to 8 zero bytes", hex(nonceFor(DIR_C2S, 0)).slice(8) === "0000000000000000");
  ok("seq=1 packs to ...00000001", hex(nonceFor(DIR_C2S, 1)).slice(8) === "0000000000000001");
  ok("seq=255 packs to ...000000ff", hex(nonceFor(DIR_C2S, 255)).slice(8) === "00000000000000ff");
  ok("seq=256 packs to ...00000100", hex(nonceFor(DIR_C2S, 256)).slice(8) === "0000000000000100");

  // 2^32 — first byte of the upper half. Catches a "writeUInt32" instead of
  // "writeBigUInt64" mistake.
  ok(
    "seq=2^32 packs into high half (...0100000000)",
    hex(nonceFor(DIR_C2S, 2 ** 32)).slice(8) === "0000000100000000",
  );

  // Nonce of the same seq under different dirs must differ (only first 4
  // bytes change). This is what prevents cross-direction replay even with
  // the same key.
  const c2s0 = nonceFor(DIR_C2S, 0);
  const s2c0 = nonceFor(DIR_S2C, 0);
  ok("c2s/0 != s2c/0", hex(c2s0) !== hex(s2c0));
  ok(
    "different nonces differ only in the dir prefix",
    hex(c2s0).slice(8) === hex(s2c0).slice(8),
  );
}

// 2. DIR_C2S and DIR_S2C are 4-byte literals, distinct, ASCII for the labels.
{
  ok("DIR_C2S is 4 bytes", DIR_C2S.length === 4);
  ok("DIR_S2C is 4 bytes", DIR_S2C.length === 4);
  ok("DIR_C2S != DIR_S2C", hex(DIR_C2S) !== hex(DIR_S2C));
  ok("DIR_C2S spells 'c2s\\0'", DIR_C2S[0] === 0x63 && DIR_C2S[1] === 0x32 && DIR_C2S[2] === 0x73 && DIR_C2S[3] === 0x00);
  ok("DIR_S2C spells 's2c\\0'", DIR_S2C[0] === 0x73 && DIR_S2C[1] === 0x32 && DIR_S2C[2] === 0x63 && DIR_S2C[3] === 0x00);
}

// 3. b64u roundtrip: random + empty + special-byte vectors.
{
  const cases: Uint8Array[] = [
    new Uint8Array([]),
    new Uint8Array([0]),
    new Uint8Array([0xff]),
    new Uint8Array([0, 1, 2, 3, 4]),
    new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]),
    // Bytes that would land on `+` and `/` in standard base64; check we use
    // `-` and `_` (URL-safe).
    new Uint8Array([0xfb, 0xff, 0xbf]),
    // 32-byte payload (typical AEAD key length).
    new Uint8Array(Array.from({ length: 32 }, (_, i) => (i * 37) & 0xff)),
  ];
  for (const original of cases) {
    const enc = b64uEncode(original);
    // No standard-base64 chars allowed:
    ok(
      `b64u(${original.length}B) avoids + / =`,
      !/[+/=]/.test(enc),
    );
    const decoded = b64uDecode(enc);
    ok(
      `b64u roundtrip preserves ${original.length}B`,
      decoded.length === original.length && decoded.every((v, i) => v === original[i]),
    );
  }
}

// 4. b64uDecode tolerates input that was already padding-stripped (which is
//    what the encoder produces). The standard base64 alphabet's `+` and `/`
//    are remapped on the way in.
{
  // "Hello" = 0x48 0x65 0x6c 0x6c 0x6f. base64 = "SGVsbG8=" → URL-safe
  // stripped = "SGVsbG8".
  const decoded = b64uDecode("SGVsbG8");
  ok("b64uDecode handles padding-stripped 'SGVsbG8'", new TextDecoder().decode(decoded) === "Hello");

  // URL-unsafe input should still decode (the function remaps before atob).
  // base64 of 0xFB 0xFF 0xBF = "+/+/", URL-safe = "-_-_".
  const url = b64uDecode("-_-_");
  ok(
    "b64uDecode handles URL-safe '-_-_'",
    url.length === 3 && url[0] === 0xfb && url[1] === 0xff && url[2] === 0xbf,
  );
}

if (failed > 0) {
  console.error(`\n${failed} protocol check(s) failed`);
  process.exit(1);
}
console.log("protocol: all checks passed");
