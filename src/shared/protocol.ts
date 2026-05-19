// SPDX-License-Identifier: Apache-2.0
// Wire format for the P2PSH signaling/handshake protocol.
//
// All messages are JSON objects sent as text frames over the Nym mixnet.
// Binary fields (keys, ciphertexts, AEAD payloads) are base64url-encoded.
//
// Flow:
//   1. Client -> Server : ClientHello   { kemCt }
//      The server publishes its ML-KEM-768 public key out of band
//      (printed on startup, copied into client config). The client
//      runs ml_kem768.encapsulate(serverPk) and ships the ciphertext.
//
//   2. Server -> Client : ServerAck     { enc: AEAD("ok", k, nonce=0) }
//      Proves to the client that the server successfully decapsulated
//      and derived the same session key.
//
//   3. Either direction  : AppData      { seq, enc }
//      Application payload encrypted with ChaCha20-Poly1305.
//      `seq` is a monotonically increasing per-direction counter that
//      doubles as the AEAD nonce (12 bytes: 4 bytes direction tag || 8 bytes BE seq).

export type Msg =
  | ClientHello
  | ServerAck
  | AppData
  | ResumeRequest
  | ResumeAck
  | ResumeNack
  | ServerError;

// Wire-level transport choice. The client picks (subject to server allowlist)
// because the privacy/latency tradeoff lives on the client side: a client
// behind symmetric NAT or wanting full anonymity may opt for "nym" even when
// the server would happily speak WebRTC.
export type TransportChoice = "webrtc" | "nym";

export interface ClientHello {
  t: "hello";
  kemCt: string; // base64url, 1088 bytes
  replyTo: string; // client's Nym mix address; server uses this to route ack + further frames
  transport: TransportChoice;
}

export interface ServerAck {
  t: "ack";
  enc: string; // base64url, AEAD(plaintext="ok") with seq=0, dir="s2c"
  sig: string; // base64url Ed25519 signature over sha256(TRANSCRIPT_LABEL || serverKemPk || kemCt)
}

export interface AppData {
  t: "data";
  seq: number;
  enc: string; // base64url AEAD ciphertext
}

// --- Session resumption ------------------------------------------------------
//
// Flow:
//   client -> server : { t: "resume", sessionId, salt, replyTo }
//      Client picks a fresh 16-byte salt. Server looks up sessionId; if found,
//      both sides derive a new key via HKDF(oldKey, salt, "p2psh/v0/resume") and
//      reset send/recv counters to 0.
//   server -> client : { t: "resume-ack", enc }
//      AEAD("RESUMED") under the rotated key with seq=0, dir=s2c. Verifying
//      decrypt is the server's proof that it had the old key.
//   server -> client : { t: "resume-nack" }
//      Sent in plaintext if sessionId is unknown (server restarted or never
//      saw this client). Client falls back to a full ML-KEM handshake.

export interface ResumeRequest {
  t: "resume";
  sessionId: string; // base64url, 16 bytes
  salt: string;      // base64url, 16 bytes, fresh per resume
  replyTo: string;   // client's Nym mix address
  transport: TransportChoice; // see ClientHello.transport
}

export interface ResumeAck {
  t: "resume-ack";
  enc: string; // base64url AEAD("RESUMED") with rotated key, seq=0, dir=s2c
}

export interface ResumeNack {
  t: "resume-nack";
  reason?: string;
}

// Plaintext fatal error from server during/after handshake (e.g. requested
// transport not allowed by P2PSH_TRANSPORT allowlist). Distinct from
// resume-nack because hello can fail this way too, and the client should
// surface it instead of silently falling back.
export interface ServerError {
  t: "error";
  code: "transport-not-allowed" | "bad-request";
  reason?: string;
}

export const TRANSCRIPT_LABEL = new TextEncoder().encode("p2psh/v0/transcript");

export const DIR_C2S = new Uint8Array([0x63, 0x32, 0x73, 0x00]); // "c2s\0"
export const DIR_S2C = new Uint8Array([0x73, 0x32, 0x63, 0x00]); // "s2c\0"

export function nonceFor(dir: Uint8Array, seq: number): Uint8Array {
  const n = new Uint8Array(12);
  n.set(dir, 0);
  const view = new DataView(n.buffer);
  // JS numbers are safe for integers up to 2^53; that is enough for a session counter.
  view.setBigUint64(4, BigInt(seq), false);
  return n;
}

// Cross-platform base64url. Works in browsers (btoa/atob globals) and Node 16+.
// Avoids Node's Buffer so this file can be bundled for the browser unchanged.
export function b64uEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}