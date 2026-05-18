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
  b64uDecode,
  b64uEncode,
} from "../shared/protocol.js";
import { bringUpPeer } from "../shared/webrtc-peer.js";
import { attachShellToDataChannel } from "./ssh-bridge.js";
import { encodeConnectString } from "../shared/connect-string.js";

const IDENTITY_PATH = process.env.P2PSH_IDENTITY ?? "./data/server-identity.json";
const NYM_URL = process.env.P2PSH_NYM_URL ?? "ws://127.0.0.1:1977";

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
  console.log("P2PSH server ready.");
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

  const tearDownPeer = (peerAddr: string): void => {
    const old = peers.get(peerAddr);
    if (!old) return;
    peers.delete(peerAddr);
    try { old.dispose(); } catch {}
    try { old.pty?.kill(); } catch {}
  };

  const startPeer = async (peerAddr: string, session: Session): Promise<void> => {
    tearDownPeer(peerAddr); // replace any prior session for this peer
    livePeers.add(peerAddr);
    try {
      const handle = await bringUpPeer({
        role: "answerer",
        nym,
        session,
        remoteAddr: peerAddr,
      });
      console.log("[server] WebRTC DataChannel open — attaching PTY shell.");
      const pty = attachShellToDataChannel(handle.dc);
      peers.set(peerAddr, { dispose: handle.dispose, pty });
    } catch (e) {
      console.error("[server] WebRTC bring-up failed:", e);
    } finally {
      livePeers.delete(peerAddr);
    }
  };

  nym.onMessage(async ({ text }) => {
    let msg: Msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    try {
      if (msg.t === "hello") {
        const hello = msg as ClientHello;
        if (livePeers.has(hello.replyTo)) return; // frame after handshake belongs to webrtc-peer
        livePeers.add(hello.replyTo);
        const r = serverAccept(hello, identity);
        sessions.set(b64uEncode(r.sessionId), { key: r.sessionKey });
        nym.send(hello.replyTo, JSON.stringify(r.ack));
        console.log(`[server] full handshake complete with ${hello.replyTo.slice(0, 24)}...`);
        await startPeer(hello.replyTo, r.session);
        return;
      }

      if (msg.t === "resume") {
        const req = msg as ResumeRequest;
        if (livePeers.has(req.replyTo)) return;
        const saved = sessions.get(req.sessionId);
        if (!saved) {
          const nack: ResumeNack = { t: "resume-nack", reason: "unknown sessionId" };
          nym.send(req.replyTo, JSON.stringify(nack));
          console.log(`[server] resume NACK (unknown sessionId) for ${req.replyTo.slice(0, 24)}...`);
          return;
        }
        livePeers.add(req.replyTo);
        const r = serverResume(req, saved.key);
        sessions.set(req.sessionId, { key: r.rotatedKey });
        nym.send(req.replyTo, JSON.stringify(r.ack));
        console.log(`[server] resume OK for ${req.replyTo.slice(0, 24)}...`);
        await startPeer(req.replyTo, r.session);
        return;
      }
    } catch (e) {
      console.error("[server] message handling failed:", e);
    }
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
