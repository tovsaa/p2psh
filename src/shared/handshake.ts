// SPDX-License-Identifier: Apache-2.0
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
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
import { randomBytes } from "@noble/hashes/utils";

const HKDF_INFO_SESSION_KEY = new TextEncoder().encode("p2psh/v0/session-key");
const HKDF_INFO_SESSION_ID = new TextEncoder().encode("p2psh/v0/session-id");
const HKDF_INFO_RESUME = new TextEncoder().encode("p2psh/v0/resume");

function deriveSessionKey(sharedSecret: Uint8Array): Uint8Array {
  // Salt left empty: the KEM shared secret is already a uniformly random 32-byte value.
  // HKDF here is for domain separation and to allow future re-keying via different `info` strings.
  return hkdf(sha256, sharedSecret, new Uint8Array(0), HKDF_INFO_SESSION_KEY, 32);
}

/**
 * Stable 16-byte session identifier derived from the KEM shared secret.
 * Used by both sides to look up saved state on resume. Not secret: the only
 * thing this identifier can be used for is checking whether the server still
 * has the matching key; a resume still requires AEAD proof of possession.
 */
function deriveSessionId(sharedSecret: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, new Uint8Array(0), HKDF_INFO_SESSION_ID, 16);
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
 * Bind the signature to (this server identity, this session ciphertext).
 * Including kemPk prevents an attacker from replaying a signature collected
 * against a different server identity that happens to share an Ed25519 key.
 */
function transcriptHash(serverKemPk: Uint8Array, kemCt: Uint8Array): Uint8Array {
  const buf = new Uint8Array(TRANSCRIPT_LABEL.length + serverKemPk.length + kemCt.length);
  buf.set(TRANSCRIPT_LABEL, 0);
  buf.set(serverKemPk, TRANSCRIPT_LABEL.length);
  buf.set(kemCt, TRANSCRIPT_LABEL.length + serverKemPk.length);
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
  const idSecretKey = ed25519.utils.randomPrivateKey();
  const idPublicKey = ed25519.getPublicKey(idSecretKey);
  return {
    publicKey: kem.publicKey,
    secretKey: kem.secretKey,
    idPublicKey,
    idSecretKey,
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
  session: Session;
  // Saved so we can recompute the transcript and verify the server's signature.
  kemCt: Uint8Array;
  serverKemPk: Uint8Array;
  // For producing a resume state once the handshake is verified.
  sessionId: Uint8Array;
  sessionKey: Uint8Array;
}

export function clientInitiate(
  serverPk: Uint8Array,
  replyTo: string,
  transport: TransportChoice,
): ClientHandshakeState {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(serverPk);
  const key = deriveSessionKey(sharedSecret);
  const sessionId = deriveSessionId(sharedSecret);
  const session = makeSession(key, DIR_C2S, DIR_S2C);
  const hello: ClientHello = { t: "hello", kemCt: b64uEncode(cipherText), replyTo, transport };
  return {
    hello,
    session,
    kemCt: cipherText,
    serverKemPk: serverPk,
    sessionId,
    sessionKey: key,
  };
}

// --- Resumption (client) -----------------------------------------------------

/**
 * Persistent state a client needs to attempt a resume. Both fields are produced
 * by `extractResumeState` once a handshake (or previous resume) has completed.
 */
export interface ResumeState {
  sessionId: Uint8Array; // 16 bytes
  key: Uint8Array;       // 32 bytes — current rotated key
}

export function extractResumeStateFromHandshake(
  state: ClientHandshakeState,
): ResumeState {
  return { sessionId: state.sessionId, key: state.sessionKey };
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

export function newResumeStateAfterResume(attempt: ClientResumeAttempt): ResumeState {
  return { sessionId: attempt.sessionId, key: attempt.rotatedKey };
}

export function clientVerifyAck(
  ack: ServerAck,
  state: ClientHandshakeState,
  pinnedServerIdPk: Uint8Array,
): void {
  // Order matters: verify the signature BEFORE touching AEAD state, so a
  // malicious peer cannot poison our recv counter on a bad handshake.
  const tHash = transcriptHash(state.serverKemPk, state.kemCt);
  const sig = b64uDecode(ack.sig);
  if (!ed25519.verify(sig, tHash, pinnedServerIdPk)) {
    throw new Error("server signature failed verification — wrong identity or MITM");
  }
  const pt = state.session.recv.open(0, b64uDecode(ack.enc));
  const text = new TextDecoder().decode(pt);
  if (text !== "ok") throw new Error(`bad ack payload: ${text}`);
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
  const sharedSecret = ml_kem768.decapsulate(ct, identity.secretKey);
  const key = deriveSessionKey(sharedSecret);
  const sessionId = deriveSessionId(sharedSecret);
  const session = makeSession(key, DIR_S2C, DIR_C2S);
  const { ct: ackCt } = session.send.seal(new TextEncoder().encode("ok"));
  const tHash = transcriptHash(identity.publicKey, ct);
  const sig = ed25519.sign(tHash, identity.idSecretKey);
  return {
    ack: { t: "ack", enc: b64uEncode(ackCt), sig: b64uEncode(sig) },
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