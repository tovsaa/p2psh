import { readFile, writeFile, mkdir, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";
import {
  ClientResumeAttempt,
  ResumeState,
  Session,
  clientInitiate,
  clientResume,
  clientVerifyAck,
  clientVerifyResumeAck,
  encodeAppData,
  extractResumeStateFromHandshake,
  newResumeStateAfterResume,
} from "../shared/handshake.js";
import { NymTransport } from "../shared/nym-transport.js";
import { Msg, b64uDecode, b64uEncode } from "../shared/protocol.js";
import { bringUpPeer } from "../shared/webrtc-peer.js";
import { decodeConnectString } from "../shared/connect-string.js";

const NYM_URL = process.env.P2PSH_NYM_URL ?? "ws://127.0.0.1:1977";

// Prefer the single bundled connect string; fall back to the legacy three
// individual env vars so existing setups keep working.
const SERVER_ADDR: string | undefined = (() => {
  if (process.env.P2PSH_CONNECT) return decodeConnectString(process.env.P2PSH_CONNECT).addr;
  return process.env.P2PSH_SERVER_ADDR;
})();
const SERVER_PK_B64: string | undefined = (() => {
  if (process.env.P2PSH_CONNECT) return decodeConnectString(process.env.P2PSH_CONNECT).kemPk;
  return process.env.P2PSH_SERVER_PK;
})();
const SERVER_IDPK_B64: string | undefined = (() => {
  if (process.env.P2PSH_CONNECT) return decodeConnectString(process.env.P2PSH_CONNECT).idPk;
  return process.env.P2PSH_SERVER_IDPK;
})();

if (!SERVER_ADDR || !SERVER_PK_B64 || !SERVER_IDPK_B64) {
  console.error(
    "Set P2PSH_CONNECT to the p2psh1:// string the server printed,\n" +
      "or set P2PSH_SERVER_ADDR + P2PSH_SERVER_PK + P2PSH_SERVER_IDPK individually.",
  );
  process.exit(2);
}

const STATE_PATH = (() => {
  const hash = createHash("sha256").update(SERVER_IDPK_B64!).digest("hex").slice(0, 16);
  return `./data/client-state-${hash}.json`;
})();

async function loadResumeState(): Promise<ResumeState | null> {
  if (!existsSync(STATE_PATH)) return null;
  try {
    const obj = JSON.parse(await readFile(STATE_PATH, "utf8"));
    return { sessionId: b64uDecode(obj.sessionId), key: b64uDecode(obj.key) };
  } catch {
    return null;
  }
}

async function saveResumeState(state: ResumeState): Promise<void> {
  await mkdir(dirname(STATE_PATH), { recursive: true });
  await writeFile(
    STATE_PATH,
    JSON.stringify({
      sessionId: b64uEncode(state.sessionId),
      key: b64uEncode(state.key),
    }),
  );
}

async function dropResumeState(): Promise<void> {
  try {
    await unlink(STATE_PATH);
  } catch {
    // already gone
  }
}

async function main(): Promise<void> {
  const nym = new NymTransport({ url: NYM_URL });
  await nym.connect();
  const me = await nym.selfAddress();
  console.log(`[client] my mix address: ${me.slice(0, 24)}...`);

  const serverPk = b64uDecode(SERVER_PK_B64!);
  const serverIdPk = b64uDecode(SERVER_IDPK_B64!);

  const saved = await loadResumeState();
  let session: Session;
  if (saved) {
    console.log("[client] found saved session — attempting resume...");
    try {
      session = await attemptResume(nym, saved, me);
      console.log("[client] resume OK — skipped full ML-KEM handshake.");
    } catch (e) {
      console.log(`[client] resume failed (${(e as Error).message}); doing full handshake.`);
      await dropResumeState();
      session = await fullHandshake(nym, serverPk, serverIdPk, me);
    }
  } else {
    session = await fullHandshake(nym, serverPk, serverIdPk, me);
  }

  // WebRTC + simple echo to prove the channel works end-to-end.
  const { dc } = await bringUpPeer({
    role: "offerer",
    nym,
    session,
    remoteAddr: SERVER_ADDR!,
  });
  console.log("[client] WebRTC DataChannel open — sending probe.");
  dc.addEventListener("message", (ev: MessageEvent) => {
    const text = typeof ev.data === "string" ? ev.data : new TextDecoder().decode(ev.data);
    // The server now attaches a PTY shell, so what comes back is JSON {t:"o", d:"..."}.
    // We just print the raw text and exit after the first frame.
    console.log(`[client] DataChannel recv: ${text.slice(0, 120)}${text.length > 120 ? "..." : ""}`);
    setTimeout(() => process.exit(0), 200);
  });
  // Probe input that the PTY shell will echo back via its prompt.
  dc.send(JSON.stringify({ t: "i", d: "\r" }));
}

function attemptResume(
  nym: NymTransport,
  saved: ResumeState,
  me: string,
): Promise<Session> {
  return new Promise((resolve, reject) => {
    const attempt: ClientResumeAttempt = clientResume(saved, me);
    const detach = nym.onMessage(({ text }) => {
      let msg: Msg;
      try {
        msg = JSON.parse(text);
      } catch {
        return;
      }
      if (msg.t === "resume-nack") {
        detach();
        reject(new Error(`NACK: ${msg.reason ?? "unknown"}`));
      } else if (msg.t === "resume-ack") {
        try {
          clientVerifyResumeAck(msg, attempt);
        } catch (e) {
          detach();
          reject(e as Error);
          return;
        }
        saveResumeState(newResumeStateAfterResume(attempt)).catch(() => {});
        detach();
        resolve(attempt.session);
      }
    });
    nym.send(SERVER_ADDR!, JSON.stringify(attempt.request));
  });
}

function fullHandshake(
  nym: NymTransport,
  serverPk: Uint8Array,
  serverIdPk: Uint8Array,
  me: string,
): Promise<Session> {
  return new Promise((resolve, reject) => {
    const state = clientInitiate(serverPk, me);
    const detach = nym.onMessage(({ text }) => {
      let msg: Msg;
      try {
        msg = JSON.parse(text);
      } catch {
        return;
      }
      if (msg.t !== "ack") return;
      try {
        clientVerifyAck(msg, state, serverIdPk);
      } catch (e) {
        detach();
        reject(e as Error);
        return;
      }
      saveResumeState(extractResumeStateFromHandshake(state)).catch(() => {});
      console.log("[client] handshake verified — Ed25519 OK, session key agreed and saved.");
      detach();
      resolve(state.session);
    });
    console.log(`[client] sending ClientHello to ${SERVER_ADDR!.slice(0, 24)}...`);
    nym.send(SERVER_ADDR!, JSON.stringify(state.hello));
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
