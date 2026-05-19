// SPDX-License-Identifier: Apache-2.0
import { b64uDecode, b64uEncode } from "./protocol.js";

// One self-contained string the user copies from the server console and pastes
// into the browser (or that gets baked into a URL via the `#c=` hash). Includes
// every piece of trust material the client needs to connect.
//
// Format: "p2psh1://" + base64url( JSON({a: addr, p: kemPk, i: idPk}) )
//
// All values are passed through as base64url where they are already base64url;
// the addr field is the Nym mix-address string literal (already URL-safe).

const PREFIX = "p2psh1://";

export interface ConnectParams {
  addr: string;        // Nym mix address
  kemPk: string;       // base64url ML-KEM-768 public key
  idPk: string;        // base64url Ed25519 identity public key
}

export function encodeConnectString(p: ConnectParams): string {
  const json = JSON.stringify({ a: p.addr, p: p.kemPk, i: p.idPk });
  return PREFIX + b64uEncode(new TextEncoder().encode(json));
}

export function decodeConnectString(s: string): ConnectParams {
  const trimmed = s.trim();
  if (!trimmed.startsWith(PREFIX)) {
    throw new Error(`not a p2psh1:// connect string`);
  }
  const json = new TextDecoder().decode(b64uDecode(trimmed.slice(PREFIX.length)));
  const obj = JSON.parse(json);
  if (typeof obj.a !== "string" || typeof obj.p !== "string" || typeof obj.i !== "string") {
    throw new Error("connect string missing required fields");
  }
  return { addr: obj.a, kemPk: obj.p, idPk: obj.i };
}