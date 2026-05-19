// SPDX-License-Identifier: Apache-2.0
// Known-Answer Test for the ML-KEM-768 implementation we ship.
//
// The point of this test is regression protection, not crypto validation:
//   1. Deterministic round-trip — encapsulate + decapsulate agree on the
//      shared secret. Catches any future packaging accident that wires up
//      the wrong KEM (e.g. accidental swap to ml-kem-512/1024).
//   2. Byte-stable output for a fixed (seed, msg). Catches an ABI change in
//      `@noble/post-quantum` between releases — without this we'd have no
//      signal if a bump silently re-defined the encoding.
//
// The hardcoded `EXPECTED_*` bytes below were produced by running this same
// computation against @noble/post-quantum@0.4.1. If they ever stop matching,
// either the library changed underneath us (investigate before bumping) or
// we deliberately upgraded — in which case recompute and re-paste.
//
// Run: `npm test`.

import { ml_kem768 } from "@noble/post-quantum/ml-kem";

function hex(u: Uint8Array): string {
  return Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
}

function assertEq(label: string, got: unknown, want: unknown): void {
  if (got !== want) {
    console.error(`FAIL ${label}\n  got:  ${got}\n  want: ${want}`);
    process.exit(1);
  }
  console.log(`ok    ${label}`);
}

// Fixed input material — d||z seed and encapsulation msg `m`. Picked as
// trivially predictable bytes so anyone can regenerate the expected outputs.
const seed = Uint8Array.from({ length: 64 }, (_, i) => i);
const msg = Uint8Array.from({ length: 32 }, (_, i) => 128 + i);

// Expected outputs from @noble/post-quantum@0.4.1. Recompute via
// `node tests/_compute-kat.mjs` (kept around as a tiny generator) after any
// intentional library bump.
const EXPECTED_PK_LEN = 1184;
const EXPECTED_SK_LEN = 2400;
const EXPECTED_CT_LEN = 1088;
const EXPECTED_PK_PREFIX = "298aa10d423c8dda069d02bc59e6cdf0";
const EXPECTED_SK_PREFIX = "27d2a77f33756f61208ef113abe82595";
const EXPECTED_CT_PREFIX = "04c1e43bd82139e4600aa87fddc0793f";
const EXPECTED_SS = "ef91db44b6cd5b2c50f483481a3d6e2a08cc149764fcb8dc568851332da45ed9";

const { publicKey, secretKey } = ml_kem768.keygen(seed);
const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, msg);
const recovered = ml_kem768.decapsulate(cipherText, secretKey);

assertEq("publicKey length", publicKey.length, EXPECTED_PK_LEN);
assertEq("secretKey length", secretKey.length, EXPECTED_SK_LEN);
assertEq("cipherText length", cipherText.length, EXPECTED_CT_LEN);
assertEq("publicKey prefix", hex(publicKey).slice(0, 32), EXPECTED_PK_PREFIX);
assertEq("secretKey prefix", hex(secretKey).slice(0, 32), EXPECTED_SK_PREFIX);
assertEq("cipherText prefix", hex(cipherText).slice(0, 32), EXPECTED_CT_PREFIX);
assertEq("shared secret (encapsulator)", hex(sharedSecret), EXPECTED_SS);
assertEq("shared secret (decapsulator)", hex(recovered), EXPECTED_SS);

console.log("ml-kem-768 KAT: all checks passed");