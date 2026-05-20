// SPDX-License-Identifier: Apache-2.0
// Regression tests for src/shared/connect-string.ts.
//
// The connect string is the single piece of trust material the user copies
// from the server console (or that ends up in a `#c=...` URL hash). If we
// break decode, every existing connect string ever issued stops working;
// pinning the wire format catches that early.

import { encodeConnectString, decodeConnectString } from "../src/shared/connect-string.js";

let failed = 0;

function ok(label: string, cond: boolean): void {
  if (cond) console.log(`ok    ${label}`);
  else {
    console.error(`FAIL  ${label}`);
    failed++;
  }
}

function throws(label: string, fn: () => unknown, expectedSubstr?: string): void {
  try {
    fn();
    console.error(`FAIL  ${label} (expected throw)`);
    failed++;
  } catch (e) {
    if (expectedSubstr && !String((e as Error).message).includes(expectedSubstr)) {
      console.error(`FAIL  ${label} (threw, but message "${(e as Error).message}" lacks "${expectedSubstr}")`);
      failed++;
      return;
    }
    console.log(`ok    ${label}`);
  }
}

// 1. Roundtrip with realistic field shapes.
{
  const p = {
    addr: "AbCd123.XyZ987@gateway01.nymtech.net",
    kemPk: "r7sNsYiB7-SGWOO4FCad3vtInFEpsOYTBzU83wiSawo",
    idPk: "Yf0scMjhXxLFgocDHJql1hz148KnCaXzI-hWiTHpzU8",
  };
  const s = encodeConnectString(p);
  ok("output starts with p2psh1://", s.startsWith("p2psh1://"));
  ok("no whitespace in encoded string", !/\s/.test(s));
  const back = decodeConnectString(s);
  ok("roundtrip preserves addr", back.addr === p.addr);
  ok("roundtrip preserves kemPk", back.kemPk === p.kemPk);
  ok("roundtrip preserves idPk", back.idPk === p.idPk);
}

// 2. Roundtrip is whitespace-tolerant on decode (users frequently paste
//    strings with leading/trailing newlines from terminals).
{
  const p = { addr: "a", kemPk: "p", idPk: "i" };
  const s = encodeConnectString(p);
  const back = decodeConnectString("  \n " + s + "\t\n ");
  ok("decode trims surrounding whitespace", back.addr === "a" && back.kemPk === "p" && back.idPk === "i");
}

// 3. Real-world short payload — empty fields are accepted by the wire format
//    (validation of contents is up to handshake, not the connect-string layer).
{
  const back = decodeConnectString(encodeConnectString({ addr: "", kemPk: "", idPk: "" }));
  ok("empty fields roundtrip", back.addr === "" && back.kemPk === "" && back.idPk === "");
}

// 4. Reject anything that isn't the expected scheme.
{
  throws("missing prefix rejected", () => decodeConnectString("not-a-connect-string"), "p2psh1");
  throws("wrong scheme rejected", () => decodeConnectString("p2psh2://abc"), "p2psh1");
  throws("HTTP URL rejected", () => decodeConnectString("https://example.com/"), "p2psh1");
}

// 5. Reject malformed payloads.
{
  // Valid prefix but the base64 decodes to non-JSON.
  throws("non-JSON payload rejected", () => decodeConnectString("p2psh1://aGVsbG8")); // "hello"
  // Valid JSON but missing required fields.
  // JSON: {"x":1} → base64url = "eyJ4IjoxfQ"
  throws("JSON missing fields rejected", () => decodeConnectString("p2psh1://eyJ4IjoxfQ"), "missing required");
  // JSON with wrong field types.
  // {"a":1,"p":2,"i":3} → base64url = "eyJhIjoxLCJwIjoyLCJpIjozfQ"
  throws("JSON with non-string fields rejected", () => decodeConnectString("p2psh1://eyJhIjoxLCJwIjoyLCJpIjozfQ"), "missing required");
}

// 6. Output is URL-safe (no `+` `/` `=` `%`) — so the connect string can be
//    dropped into a `#c=` hash without further percent-encoding.
{
  const longish = encodeConnectString({
    addr: "VeryLongAddressString.AnotherSegment@gateway-host-with-dashes.example.net",
    kemPk: "X".repeat(1184 / 6 * 8 + 4),   // approximate b64 length of ML-KEM-768 pk
    idPk: "Y".repeat(43),                  // typical Ed25519 pk b64
  });
  ok(
    "encoded string is URL-fragment safe",
    !/[+/=%\s]/.test(longish.slice("p2psh1://".length)),
  );
}

if (failed > 0) {
  console.error(`\n${failed} connect-string check(s) failed`);
  process.exit(1);
}
console.log("connect-string: all checks passed");
