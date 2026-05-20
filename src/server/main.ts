// SPDX-License-Identifier: Apache-2.0
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import {
  ServerIdentity,
  Session,
  generateServerIdentity,
  serverAccept,
  serverResume,
} from "../shared/handshake.js";
import { NymTransport } from "../shared/nym-transport.js";
import {
  ClientHello,
  Msg,
  ResumeNack,
  ResumeRequest,
  ServerError,
  TransportChoice,
  b64uDecode,
  b64uEncode,
} from "../shared/protocol.js";
import { bringUpPeer } from "../shared/webrtc-peer.js";
import { NymChannel } from "../shared/channel.js";
import { attachShellToDataChannel } from "./ssh-bridge.js";
import { encodeConnectString } from "../shared/connect-string.js";
import { createRateLimiter } from "./limits.js";

const IDENTITY_PATH = process.env.P2PSH_IDENTITY ?? "./data/server-identity.json";
const NYM_URL = process.env.P2PSH_NYM_URL ?? "ws://127.0.0.1:1977";

// Soft caps to keep a single instance from being trivially DoS'd through
// the Nym route (the connect string is shareable; anyone with it can spam
// hello/resume frames, each of which burns ML-KEM decap CPU).
//
//   P2PSH_MAX_SESSIONS   — hard cap on concurrent active peers. Past this,
//                          new hello/resume requests get a `bad-request`
//                          error frame ("server at capacity"). Defaults to
//                          32, which fits comfortably within typical
//                          single-core CPU and the in-memory session map.
//   P2PSH_RATE_PER_MIN   — sliding-window cap on hello+resume *attempts*
//                          per peer-address per 60 seconds. Spammers
//                          rotate replyTo for each frame to bypass this,
//                          but doing so costs them new Nym SURBs and gives
//                          us logs to correlate; bots that don't rotate
//                          get muted within seconds. Defaults to 10.
const MAX_SESSIONS = (() => {
  const v = parseInt(process.env.P2PSH_MAX_SESSIONS ?? "32", 10);
  return Number.isFinite(v) && v > 0 ? v : 32;
})();
const RATE_PER_MIN = (() => {
  const v = parseInt(process.env.P2PSH_RATE_PER_MIN ?? "10", 10);
  return Number.isFinite(v) && v > 0 ? v : 10;
})();

// P2PSH_TRANSPORT is now an allowlist — the *client* picks the per-session
// transport (it has the privacy/latency context). The server only declares
// which transports it is willing to accept.
//
//   any              both webrtc and nym permitted (default)
//   webrtc           only WebRTC; a "nym" hello/resume gets an error frame
//   nym              only Nym tunnel; a "webrtc" hello/resume gets an error frame
//   webrtc,nym       same as "any" (explicit form)
const ALLOWED_TRANSPORTS: ReadonlySet<TransportChoice> = (() => {
  const raw = (process.env.P2PSH_TRANSPORT ?? "any").toLowerCase();
  if (raw === "any") return new Set<TransportChoice>(["webrtc", "nym"]);
  const out = new Set<TransportChoice>();
  for (const part of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    if (part === "webrtc" || part === "nym") out.add(part);
    else console.error(`[server] ignoring unknown P2PSH_TRANSPORT value: ${part}`);
  }
  if (out.size === 0) {
    console.error("[server] P2PSH_TRANSPORT had no recognized values; defaulting to webrtc+nym");
    return new Set<TransportChoice>(["webrtc", "nym"]);
  }
  return out;
})();

async function loadOrCreateIdentity(): Promise<ServerIdentity> {
  if (existsSync(IDENTITY_PATH)) {
    const raw = JSON.parse(await readFile(IDENTITY_PATH, "utf8"));
    if (!raw.idPublicKey) {
      throw new Error(
        `identity at ${IDENTITY_PATH} is from an older version (missing Ed25519 keys). Delete it to regenerate.`,
      );
    }
    return {
      publicKey: b64uDecode(raw.publicKey),
      secretKey: b64uDecode(raw.secretKey),
      idPublicKey: b64uDecode(raw.idPublicKey),
      idSecretKey: b64uDecode(raw.idSecretKey),
    };
  }
  const id = generateServerIdentity();
  await mkdir(dirname(IDENTITY_PATH), { recursive: true });
  await writeFile(
    IDENTITY_PATH,
    JSON.stringify(
      {
        publicKey: b64uEncode(id.publicKey),
        secretKey: b64uEncode(id.secretKey),
        idPublicKey: b64uEncode(id.idPublicKey),
        idSecretKey: b64uEncode(id.idSecretKey),
      },
      null,
      2,
    ),
  );
  console.log(`[server] generated new identity at ${IDENTITY_PATH}`);
  return id;
}

// In-memory store of session keys. Lost on server restart — client falls back
// to a full ML-KEM handshake transparently when its resume request is NACKed.
interface SavedSession {
  key: Uint8Array;
}

async function main(): Promise<void> {
  const identity = await loadOrCreateIdentity();
  const nym = new NymTransport({ url: NYM_URL });
  await nym.connect();
  const addr = await nym.selfAddress();

  const kemPk = b64uEncode(identity.publicKey);
  const idPk = b64uEncode(identity.idPublicKey);
  const connectString = encodeConnectString({ addr, kemPk, idPk });
  const pagesUrl = process.env.P2PSH_WEB_URL; // e.g. https://you.github.io/P2PSH

  console.log("=".repeat(70));
  console.log(`P2PSH server ready. transports allowed: ${[...ALLOWED_TRANSPORTS].join(", ")}`);
  console.log("");
  console.log("Connect string (paste this in the browser's single field):");
  console.log("  " + connectString);
  if (pagesUrl) {
    console.log("");
    console.log("Or share this direct link (auto-fills + connects):");
    console.log(`  ${pagesUrl.replace(/\/$/, "")}/#c=${encodeURIComponent(connectString)}`);
  }
  console.log("");
  console.log("(Advanced: individual fields for the legacy 3-var setup)");
  console.log("  P2PSH_SERVER_ADDR  = " + addr);
  console.log("  P2PSH_SERVER_PK    = " + kemPk);
  console.log("  P2PSH_SERVER_IDPK  = " + idPk);
  console.log("=".repeat(70));

  const sessions = new Map<string, SavedSession>(); // key: base64url sessionId

  // Per-peer state. On reconnect from the same peer (resume after browser
  // reload, or another full handshake) we tear down the previous handle so
  // the old signaling listener stops trying to decrypt new frames with an old
  // key and the old PTY exits.
  interface PeerState {
    dispose: () => void;
    pty?: { kill: () => void };
  }
  const peers = new Map<string, PeerState>();
  const livePeers = new Set<string>(); // peer addresses currently mid-bring-up

  // Sliding-window rate limiter keyed by replyTo. See src/server/limits.ts;
  // factored out so tests can drive it through an injected clock without
  // spinning up a full server.
  const rateLimiter = createRateLimiter({ max: RATE_PER_MIN, windowMs: 60_000 });

  const tearDownPeer = (peerAddr: string): void => {
    const old = peers.get(peerAddr);
    if (!old) return;
    peers.delete(peerAddr);
    try { old.dispose(); } catch {}
    try { old.pty?.kill(); } catch {}
  };

  const startPeer = async (
    peerAddr: string,
    session: Session,
    transport: TransportChoice,
  ): Promise<void> => {
    tearDownPeer(peerAddr); // replace any prior session for this peer
    livePeers.add(peerAddr);
    try {
      const peerLabel = peerAddr.slice(0, 24);
      if (transport === "nym") {
        const channel = new NymChannel(nym, session, peerAddr, peerLabel);
        console.log(`[server] Nym-tunneled channel open for ${peerLabel}... — attaching PTY shell.`);
        const pty = attachShellToDataChannel(channel, { peerLabel });
        peers.set(peerAddr, { dispose: () => channel.close(), pty });
      } else {
        const handle = await bringUpPeer({
          role: "answerer",
          nym,
          session,
          remoteAddr: peerAddr,
        });
        console.log(`[server] WebRTC DataChannel open for ${peerLabel}... — attaching PTY shell.`);
        const pty = attachShellToDataChannel(handle.dc, { peerLabel });
        peers.set(peerAddr, { dispose: handle.dispose, pty });
      }
    } catch (e) {
      console.error(`[server] ${transport} bring-up failed:`, e);
    } finally {
      livePeers.delete(peerAddr);
    }
  };

  // Resolve the client's requested transport against the server allowlist.
  // Returns the chosen transport, or null after sending an error frame.
  // A missing transport field is treated as a malformed request — every
  // supported client populates it; legacy compatibility was removed.
  const pickTransport = (
    replyTo: string,
    requested: TransportChoice | undefined,
  ): TransportChoice | null => {
    if (requested !== "webrtc" && requested !== "nym") {
      const err: ServerError = {
        t: "error",
        code: "bad-request",
        reason: "missing or invalid transport field",
      };
      nym.send(replyTo, JSON.stringify(err));
      console.log(
        `[server] rejected ${replyTo.slice(0, 24)}...: missing/invalid transport=${String(requested)}`,
      );
      return null;
    }
    if (!ALLOWED_TRANSPORTS.has(requested)) {
      const err: ServerError = {
        t: "error",
        code: "transport-not-allowed",
        reason: `server allows: ${[...ALLOWED_TRANSPORTS].join(", ")}`,
      };
      nym.send(replyTo, JSON.stringify(err));
      console.log(
        `[server] rejected ${replyTo.slice(0, 24)}...: requested transport=${requested} not in allowlist`,
      );
      return null;
    }
    return requested;
  };

  // Reject hello/resume past MAX_SESSIONS or above the per-peer rate limit.
  // Returns true if the caller should proceed; false means a reply was
  // already sent and the caller should bail. peers.size is the number of
  // *attached* peers (post-handshake); livePeers.size catches the in-flight
  // bringups so we don't admit more than we can build out.
  const admit = (replyTo: string): boolean => {
    if (!rateLimiter.check(replyTo)) {
      const err: ServerError = {
        t: "error",
        code: "bad-request",
        reason: `rate limit: ${RATE_PER_MIN}/min per peer`,
      };
      nym.send(replyTo, JSON.stringify(err));
      console.log(`[server] rate-limited ${replyTo.slice(0, 24)}...`);
      return false;
    }
    if (peers.size + livePeers.size >= MAX_SESSIONS) {
      const err: ServerError = {
        t: "error",
        code: "bad-request",
        reason: `server at capacity (${MAX_SESSIONS} sessions)`,
      };
      nym.send(replyTo, JSON.stringify(err));
      console.log(`[server] at capacity, rejected ${replyTo.slice(0, 24)}...`);
      return false;
    }
    return true;
  };

  let shuttingDown = false;
  const detachNymListener = nym.onMessage(async ({ text }) => {
    if (shuttingDown) return;
    let msg: Msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    try {
      if (msg.t === "hello") {
        const hello = msg as ClientHello;
        // Ordering note: we send the ack BEFORE awaiting startPeer to avoid a
        // self-deadlock — the WebRTC answerer waits for the client's SDP
        // offer, which the client only sends after seeing the ack. There is
        // no race window between the ack landing and the next-frame listener
        // being armed: startPeer's synchronous prelude (NymChannel ctor or
        // bringUpPeer's nym.onMessage subscribe) runs in the same tick as
        // nym.send returns, before Node's event loop can deliver another
        // incoming frame.
        if (livePeers.has(hello.replyTo)) return; // frame after handshake belongs to webrtc-peer
        if (!admit(hello.replyTo)) return;
        const transport = pickTransport(hello.replyTo, hello.transport);
        if (!transport) return;
        livePeers.add(hello.replyTo);
        const r = serverAccept(hello, identity);
        sessions.set(b64uEncode(r.sessionId), { key: r.sessionKey });
        nym.send(hello.replyTo, JSON.stringify(r.ack));
        console.log(
          `[server] full handshake complete with ${hello.replyTo.slice(0, 24)}... transport=${transport}`,
        );
        await startPeer(hello.replyTo, r.session, transport);
        return;
      }

      if (msg.t === "resume") {
        const req = msg as ResumeRequest;
        if (livePeers.has(req.replyTo)) return;
        if (!admit(req.replyTo)) return;
        const saved = sessions.get(req.sessionId);
        if (!saved) {
          const nack: ResumeNack = { t: "resume-nack", reason: "unknown sessionId" };
          nym.send(req.replyTo, JSON.stringify(nack));
          console.log(`[server] resume NACK (unknown sessionId) for ${req.replyTo.slice(0, 24)}...`);
          return;
        }
        const transport = pickTransport(req.replyTo, req.transport);
        if (!transport) return;
        livePeers.add(req.replyTo);
        const r = serverResume(req, saved.key);
        sessions.set(req.sessionId, { key: r.rotatedKey });
        nym.send(req.replyTo, JSON.stringify(r.ack));
        console.log(
          `[server] resume OK for ${req.replyTo.slice(0, 24)}... transport=${transport}`,
        );
        await startPeer(req.replyTo, r.session, transport);
        return;
      }
    } catch (e) {
      console.error("[server] message handling failed:", e);
    }
  });

  // Graceful shutdown. systemd / docker stop send SIGTERM and then SIGKILL
  // after 10s by default; we want to spend the first 10s tearing down peers
  // cleanly (close DataChannels so the browser shows "[connection lost]"
  // and starts its backoff, kill PTYs so children don't get orphaned, close
  // the local nym-client WS) and only then exit.
  let shutdownStarted = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    shuttingDown = true;
    console.log(`[server] received ${signal}, shutting down ${peers.size} peer(s)...`);
    try { detachNymListener(); } catch (e) { console.error("[server] detach:", e); }
    for (const [addr] of peers) tearDownPeer(addr);
    try { await nym.close(); } catch (e) { console.error("[server] nym.close:", e); }
    console.log("[server] shutdown complete.");
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});