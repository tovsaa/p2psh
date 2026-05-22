// SPDX-License-Identifier: Apache-2.0
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  AppData,
  ClientHello,
  ResumeAck,
  ResumeRequest,
  ServerAck,
  TransportChoice,
  DIR_C2S,
  DIR_S2C,
  TRANSCRIPT_LABEL,
  b64uDecode,
  b64uEncode,
  nonceFor,
} from "./protocol.js";
import { randomBytes } from "@noble/hashes/utils.js";

const HKDF_INFO_SESSION_KEY = new TextEncoder().encode("p2psh/v1/session-key");
const HKDF_INFO_SESSION_ID = new TextEncoder().encode("p2psh/v1/session-id");
const HKDF_INFO_RESUME = new TextEncoder().encode("p2psh/v1/resume");

/**
 * Hybrid KEM combiner: concatenate the ML-KEM-768 shared secret with the
 * X25519 ECDH shared secret and feed the 64-byte concatenation through
 * HKDF-SHA256. Standard construction used by CECPQ2, TLS X25519MLKEM768,
 * and matching NIST SP 800-227 (draft) guidance for "concatenate-then-KDF"
 * hybrids. Security degrades to the strictly stronger of:
 *   - X25519 (well-tested classical) — protects if ML-KEM is broken
 *   - ML-KEM-768 (post-quantum)      — protects against future quantum
 * If both are broken, we have bigger problems.
 */
function combineSharedSecrets(mlKemSS: Uint8Array, x25519SS: Uint8Array): Uint8Array {
  const combined = new Uint8Array(mlKemSS.length + x25519SS.length);
  combined.set(mlKemSS, 0);
  combined.set(x25519SS, mlKemSS.length);
  return combined;
}

function deriveSessionKey(combinedSecret: Uint8Array): Uint8Array {
  // Salt left empty: the inputs are already uniformly random 32-byte values.
  // HKDF here is for domain separation and to bind the hybrid label v1.
  return hkdf(sha256, combinedSecret, new Uint8Array(0), HKDF_INFO_SESSION_KEY, 32);
}

/**
 * Stable 16-byte session identifier derived from the combined shared secret.
 * Used by both sides to look up saved state on resume. Not secret: the only
 * thing this identifier can be used for is checking whether the server still
 * has the matching key; a resume still requires AEAD proof of possession.
 */
function deriveSessionId(combinedSecret: Uint8Array): Uint8Array {
  return hkdf(sha256, combinedSecret, new Uint8Array(0), HKDF_INFO_SESSION_ID, 16);
}

/**
 * Rotate the session key on every resume. The new key is HKDF of the previous
 * key salted with a client-fresh value. Counters reset to 0 with the new key,
 * which simplifies replay handling and gives a step of post-compromise
 * security between resumes.
 */
function rotateKey(oldKey: Uint8Array, salt: Uint8Array): Uint8Array {
  return hkdf(sha256, oldKey, salt, HKDF_INFO_RESUME, 32);
}

/**
 * Bind the signature to (this server identity, this session ciphertext, both
 * X25519 ephemerals). Including kemPk prevents replaying a signature against
 * a different server with the same Ed25519 key; including both X25519 pks
 * binds the ECDH half so an attacker can't swap one factor of the hybrid.
 */
function transcriptHash(
  serverKemPk: Uint8Array,
  kemCt: Uint8Array,
  clientX25519Pk: Uint8Array,
  serverX25519Pk: Uint8Array,
): Uint8Array {
  const totalLen =
    TRANSCRIPT_LABEL.length +
    serverKemPk.length +
    kemCt.length +
    clientX25519Pk.length +
    serverX25519Pk.length;
  const buf = new Uint8Array(totalLen);
  let off = 0;
  buf.set(TRANSCRIPT_LABEL, off); off += TRANSCRIPT_LABEL.length;
  buf.set(serverKemPk, off); off += serverKemPk.length;
  buf.set(kemCt, off); off += kemCt.length;
  buf.set(clientX25519Pk, off); off += clientX25519Pk.length;
  buf.set(serverX25519Pk, off);
  return sha256(buf);
}

export interface ServerIdentity {
  // ML-KEM-768 — used for the actual key exchange.
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  // Ed25519 — long-term identity. Clients pin this out of band.
  idPublicKey: Uint8Array;
  idSecretKey: Uint8Array;
}

export function generateServerIdentity(): ServerIdentity {
  const kem = ml_kem768.keygen();
  const id = ed25519.keygen();
  return {
    publicKey: kem.publicKey,
    secretKey: kem.secretKey,
    idPublicKey: id.publicKey,
    idSecretKey: id.secretKey,
  };
}

/**
 * One half of an encrypted session. Each side keeps two of these:
 *  - a sender with its own direction tag and outgoing sequence
 *  - a receiver tracking the peer's direction tag and replay state
 *
 * Nym does NOT preserve message order: SURB-based delivery and mixnet routing
 * can reorder freely. We therefore accept any seq we haven't seen before,
 * within a sliding anti-replay window (similar to IPsec ESP). Anything older
 * than `windowSize` below the highest seen seq is rejected.
 */
export class SessionCipher {
  private seq = 0; // sender side
  private maxSeen = -1; // receiver side
  private readonly seen = new Set<number>(); // receiver side, sliding window
  private static readonly windowSize = 1024;

  constructor(
    private readonly key: Uint8Array,
    private readonly dir: Uint8Array,
  ) {}

  seal(plaintext: Uint8Array): { seq: number; ct: Uint8Array } {
    const seq = this.seq++;
    const nonce = nonceFor(this.dir, seq);
    const ct = chacha20poly1305(this.key, nonce).encrypt(plaintext);
    return { seq, ct };
  }

  open(seq: number, ct: Uint8Array): Uint8Array {
    if (seq < 0) throw new Error("negative seq");
    if (seq + SessionCipher.windowSize < this.maxSeen) {
      throw new Error(`seq ${seq} is below replay window (max=${this.maxSeen})`);
    }
    if (this.seen.has(seq)) throw new Error(`replay of seq ${seq}`);
    const nonce = nonceFor(this.dir, seq);
    const pt = chacha20poly1305(this.key, nonce).decrypt(ct);
    // Only mark as seen after successful AEAD verification.
    this.seen.add(seq);
    if (seq > this.maxSeen) this.maxSeen = seq;
    // Evict entries that fell out of the window to bound memory.
    const cutoff = this.maxSeen - SessionCipher.windowSize;
    if (cutoff > 0 && this.seen.size > SessionCipher.windowSize * 2) {
      for (const s of this.seen) if (s < cutoff) this.seen.delete(s);
    }
    return pt;
  }
}

export interface Session {
  send: SessionCipher;
  recv: SessionCipher;
}

function makeSession(key: Uint8Array, sendDir: Uint8Array, recvDir: Uint8Array): Session {
  return {
    send: new SessionCipher(key, sendDir),
    recv: new SessionCipher(key, recvDir),
  };
}

// --- Client side --------------------------------------------------------------

export interface ClientHandshakeState {
  hello: ClientHello;
  // Filled in after we receive ServerAck (we can't derive the key yet because
  // the X25519 ECDH needs the server's ephemeral public).
  session?: Session;
  // Saved so we can recompute the transcript and verify the server's signature.
  kemCt: Uint8Array;
  serverKemPk: Uint8Array;
  mlKemSharedSecret: Uint8Array; // kept until ack arrives so we can combine with X25519 SS
  clientX25519Sk: Uint8Array;
  clientX25519Pk: Uint8Array;
  // Filled in after verification.
  sessionId?: Uint8Array;
  sessionKey?: Uint8Array;
}

export function clientInitiate(
  serverPk: Uint8Array,
  replyTo: string,
  transport: TransportChoice,
): ClientHandshakeState {
  const { cipherText, sharedSecret: mlKemSS } = ml_kem768.encapsulate(serverPk);
  const x25519Kp = x25519.keygen();
  const hello: ClientHello = {
    t: "hello",
    kemCt: b64uEncode(cipherText),
    x25519Pk: b64uEncode(x25519Kp.publicKey),
    replyTo,
    transport,
  };
  return {
    hello,
    kemCt: cipherText,
    serverKemPk: serverPk,
    mlKemSharedSecret: mlKemSS,
    clientX25519Sk: x25519Kp.secretKey,
    clientX25519Pk: x25519Kp.publicKey,
  };
}

// --- Resumption (client) -----------------------------------------------------

/**
 * Persistent state a client needs to attempt a resume. The two cryptographic
 * fields (sessionId, key) are produced by `extractResumeState` once a handshake
 * (or previous resume) completes. The two policy fields (`establishedAt`,
 * `resumeCount`) let the client cap chain length: each HKDF rotation gives
 * only one-step post-compromise security, so a chain of arbitrarily many
 * resumes against a long-lived key is bounded PFS at best. Tearing down the
 * chain on a schedule (max-age) or count (max-count) forces a fresh ML-KEM
 * exchange and a fully independent new key.
 *
 * Both policy fields are optional for wire/disk backward-compat with state
 * files written before PFS rotation existed; missing values are treated as
 * "established now, count 0" so legacy state gets a single grace resume
 * before policy decisions kick in.
 */
export interface ResumeState {
  sessionId: Uint8Array; // 16 bytes
  key: Uint8Array;       // 32 bytes — current rotated key
  establishedAt?: number; // ms epoch when the current chain's full handshake completed
  resumeCount?: number;   // number of resumes performed on this chain (0 = fresh)
}

/**
 * Policy for forcing periodic full re-handshakes. Both limits are upper bounds
 * on a single resume chain: hitting either causes the client to drop the saved
 * state and run a full ML-KEM handshake instead, breaking forward dependence on
 * any past key.
 */
export interface ResumePolicy {
  maxAgeMs: number;  // chain expires this long after the full handshake
  maxCount: number;  // chain expires after this many resumes
}

export const DEFAULT_RESUME_POLICY: ResumePolicy = {
  maxAgeMs: 24 * 60 * 60 * 1000, // 24h
  maxCount: 64,
};

/**
 * Returns a non-null reason string if the chain should be torn down. The
 * `nowMs` parameter is taken explicitly to keep this pure and testable; the
 * caller passes `Date.now()` in production code.
 */
export function resumeExpiryReason(
  state: ResumeState,
  policy: ResumePolicy,
  nowMs: number,
): string | null {
  const count = state.resumeCount ?? 0;
  if (count >= policy.maxCount) return `resume count ${count} reached limit ${policy.maxCount}`;
  const established = state.establishedAt;
  if (established !== undefined) {
    const age = nowMs - established;
    if (age >= policy.maxAgeMs) return `resume chain age ${age}ms exceeded ${policy.maxAgeMs}ms`;
  }
  return null;
}

export function extractResumeStateFromHandshake(
  state: ClientHandshakeState,
): ResumeState {
  if (!state.sessionId || !state.sessionKey) {
    throw new Error("handshake not yet verified — call clientVerifyAck first");
  }
  return {
    sessionId: state.sessionId,
    key: state.sessionKey,
    establishedAt: Date.now(),
    resumeCount: 0,
  };
}

export interface ClientResumeAttempt {
  request: ResumeRequest;
  sessionId: Uint8Array;
  rotatedKey: Uint8Array;
  session: Session; // already armed with rotated key
}

export function clientResume(
  saved: ResumeState,
  replyTo: string,
  transport: TransportChoice,
): ClientResumeAttempt {
  const salt = randomBytes(16);
  const rotatedKey = rotateKey(saved.key, salt);
  const session = makeSession(rotatedKey, DIR_C2S, DIR_S2C);
  const request: ResumeRequest = {
    t: "resume",
    sessionId: b64uEncode(saved.sessionId),
    salt: b64uEncode(salt),
    replyTo,
    transport,
  };
  return {
    request,
    sessionId: saved.sessionId,
    rotatedKey,
    session,
  };
}

export function clientVerifyResumeAck(ack: ResumeAck, attempt: ClientResumeAttempt): void {
  // Decrypt the proof under the rotated key; if it parses as "RESUMED" the
  // server held the previous key, so the resume is authenticated.
  const pt = attempt.session.recv.open(0, b64uDecode(ack.enc));
  if (new TextDecoder().decode(pt) !== "RESUMED") {
    throw new Error("bad resume ack payload");
  }
}

export function newResumeStateAfterResume(
  attempt: ClientResumeAttempt,
  previous: ResumeState,
): ResumeState {
  return {
    sessionId: attempt.sessionId,
    key: attempt.rotatedKey,
    establishedAt: previous.establishedAt,
    resumeCount: (previous.resumeCount ?? 0) + 1,
  };
}

export function clientVerifyAck(
  ack: ServerAck,
  state: ClientHandshakeState,
  pinnedServerIdPk: Uint8Array,
): void {
  // Complete the X25519 half of the hybrid: ECDH with the server's ephemeral
  // X25519 public key the ack just delivered. Combined secret feeds HKDF.
  const serverX25519Pk = b64uDecode(ack.x25519Pk);
  if (serverX25519Pk.length !== 32) throw new Error("bad server X25519 pk length");
  const x25519SS = x25519.getSharedSecret(state.clientX25519Sk, serverX25519Pk);
  const combined = combineSharedSecrets(state.mlKemSharedSecret, x25519SS);

  // Order matters: verify the signature BEFORE touching AEAD state, so a
  // malicious peer cannot poison our recv counter on a bad handshake.
  const tHash = transcriptHash(state.serverKemPk, state.kemCt, state.clientX25519Pk, serverX25519Pk);
  const sig = b64uDecode(ack.sig);
  if (!ed25519.verify(sig, tHash, pinnedServerIdPk)) {
    throw new Error("server signature failed verification — wrong identity or MITM");
  }

  // Derive the session key from the combined secret and try to decrypt the
  // server's "ok" payload. If the server saw a different combined secret
  // (e.g. swapped X25519 pk by a MITM), AEAD-decrypt will fail.
  const key = deriveSessionKey(combined);
  const sessionId = deriveSessionId(combined);
  const session = makeSession(key, DIR_C2S, DIR_S2C);
  const pt = session.recv.open(0, b64uDecode(ack.enc));
  const text = new TextDecoder().decode(pt);
  if (text !== "ok") throw new Error(`bad ack payload: ${text}`);

  // Commit derived state only after both checks pass.
  state.session = session;
  state.sessionId = sessionId;
  state.sessionKey = key;
}

// --- Server side --------------------------------------------------------------

export interface ServerAcceptResult {
  ack: ServerAck;
  session: Session;
  sessionId: Uint8Array;
  sessionKey: Uint8Array;
}

export function serverAccept(
  hello: ClientHello,
  identity: ServerIdentity,
): ServerAcceptResult {
  const ct = b64uDecode(hello.kemCt);
  const clientX25519Pk = b64uDecode(hello.x25519Pk);
  if (clientX25519Pk.length !== 32) throw new Error("bad client X25519 pk length");

  const mlKemSS = ml_kem768.decapsulate(ct, identity.secretKey);
  const serverX25519 = x25519.keygen();
  const x25519SS = x25519.getSharedSecret(serverX25519.secretKey, clientX25519Pk);
  const combined = combineSharedSecrets(mlKemSS, x25519SS);

  const key = deriveSessionKey(combined);
  const sessionId = deriveSessionId(combined);
  const session = makeSession(key, DIR_S2C, DIR_C2S);
  const { ct: ackCt } = session.send.seal(new TextEncoder().encode("ok"));
  const tHash = transcriptHash(identity.publicKey, ct, clientX25519Pk, serverX25519.publicKey);
  const sig = ed25519.sign(tHash, identity.idSecretKey);
  return {
    ack: {
      t: "ack",
      x25519Pk: b64uEncode(serverX25519.publicKey),
      enc: b64uEncode(ackCt),
      sig: b64uEncode(sig),
    },
    session,
    sessionId,
    sessionKey: key,
  };
}

// --- Resumption (server) -----------------------------------------------------

export interface ServerResumeResult {
  ack: ResumeAck;
  session: Session;
  rotatedKey: Uint8Array;
}

export function serverResume(
  request: ResumeRequest,
  oldKey: Uint8Array,
): ServerResumeResult {
  const salt = b64uDecode(request.salt);
  if (salt.length !== 16) throw new Error("resume: bad salt length");
  const rotatedKey = rotateKey(oldKey, salt);
  const session = makeSession(rotatedKey, DIR_S2C, DIR_C2S);
  const { ct } = session.send.seal(new TextEncoder().encode("RESUMED"));
  return {
    ack: { t: "resume-ack", enc: b64uEncode(ct) },
    session,
    rotatedKey,
  };
}

// --- Application framing ------------------------------------------------------

export function encodeAppData(session: Session, plaintext: Uint8Array): AppData {
  const { seq, ct } = session.send.seal(plaintext);
  return { t: "data", seq, enc: b64uEncode(ct) };
}

export function decodeAppData(session: Session, msg: AppData): Uint8Array {
  return session.recv.open(msg.seq, b64uDecode(msg.enc));
}