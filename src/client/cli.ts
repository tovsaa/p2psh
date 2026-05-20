// SPDX-License-Identifier: Apache-2.0
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
import { Msg, TransportChoice, b64uDecode, b64uEncode } from "../shared/protocol.js";
import { bringUpPeer } from "../shared/webrtc-peer.js";
import { NymChannel, Channel } from "../shared/channel.js";
import { decodeConnectString } from "../shared/connect-string.js";

const NYM_URL = process.env.P2PSH_NYM_URL ?? "ws://127.0.0.1:1977";
const TRANSPORT: TransportChoice = (() => {
  const v = (process.env.P2PSH_TRANSPORT ?? "webrtc").toLowerCase();
  return v === "nym" ? "nym" : "webrtc";
})();

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

  // Bring up the data channel.
  let channel: Channel;
  if (TRANSPORT === "nym") {
    channel = new NymChannel(nym, session, SERVER_ADDR!);
    console.error("[client] Nym-tunneled channel open — entering interactive mode.");
  } else {
    const { dc } = await bringUpPeer({
      role: "offerer",
      nym,
      session,
      remoteAddr: SERVER_ADDR!,
    });
    channel = dc;
    console.error("[client] WebRTC DataChannel open — entering interactive mode.");
  }
  await runInteractive(channel);
}

// Bridges process.stdin/stdout to the data channel, the same wire format the
// browser terminal uses ({t:"i",d}, {t:"o",d}, {t:"r",c,r}).
//
// On a TTY: raw mode so keystrokes (including Ctrl+C, arrow keys, escape
// sequences) pass through to the remote PTY untouched, and SIGWINCH gets
// translated into a resize frame. To exit, run `exit` in the remote shell —
// it kills the PTY which closes the channel which exits us.
//
// On a pipe (e.g. `echo "ls -la" | npm run client`): line mode; we still
// forward stdin to the channel byte-for-byte, but stop when stdin EOFs.
// Useful for one-shot remote command execution from scripts.
async function runInteractive(channel: Channel): Promise<void> {
  const isTTY = process.stdin.isTTY === true && process.stdout.isTTY === true;

  const sendInput = (chunk: string): void => {
    if (channel.readyState !== "open") return;
    channel.send(JSON.stringify({ t: "i", d: chunk }));
  };

  const sendResize = (): void => {
    if (channel.readyState !== "open") return;
    const c = process.stdout.columns ?? 80;
    const r = process.stdout.rows ?? 24;
    channel.send(JSON.stringify({ t: "r", c, r }));
  };

  channel.addEventListener("message", (ev) => {
    const text = typeof ev.data === "string" ? ev.data : new TextDecoder().decode(ev.data);
    let msg: { t?: string; d?: string };
    try { msg = JSON.parse(text); } catch { return; }
    if (msg.t === "o" && typeof msg.d === "string") {
      process.stdout.write(msg.d);
    }
  });

  const cleanup = (code = 0): void => {
    if (isTTY) {
      try { process.stdin.setRawMode(false); } catch { /* not a TTY */ }
    }
    try { process.stdin.pause(); } catch { /* ignore */ }
    // Give the last AEAD frame a moment to flush over Nym if we're closing
    // mid-burst.
    setTimeout(() => process.exit(code), 50);
  };

  channel.addEventListener("close", () => {
    process.stdout.write("\r\n[connection closed]\r\n");
    cleanup(0);
  });

  if (isTTY) {
    process.stdin.setRawMode(true);
    sendResize();
    process.stdout.on("resize", sendResize);
  }
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: Buffer | string) => {
    sendInput(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
  });
  // For piped stdin: when the producer EOFs, we wrap up. For a real TTY,
  // 'end' only fires after Ctrl+D *and* nothing else holds stdin open — in
  // practice it's safe to treat as a request to exit.
  process.stdin.on("end", () => cleanup(0));
  process.stdin.resume();
}

function attemptResume(
  nym: NymTransport,
  saved: ResumeState,
  me: string,
): Promise<Session> {
  return new Promise((resolve, reject) => {
    const attempt: ClientResumeAttempt = clientResume(saved, me, TRANSPORT);
    const detach = nym.onMessage(({ text }) => {
      let msg: Msg;
      try {
        msg = JSON.parse(text);
      } catch {
        return;
      }
      if (msg.t === "error") {
        detach();
        reject(new Error(`server rejected request: ${msg.code} (${msg.reason ?? ""})`));
      } else if (msg.t === "resume-nack") {
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
    const state = clientInitiate(serverPk, me, TRANSPORT);
    const detach = nym.onMessage(({ text }) => {
      let msg: Msg;
      try {
        msg = JSON.parse(text);
      } catch {
        return;
      }
      if (msg.t === "error") {
        detach();
        reject(new Error(`server rejected request: ${msg.code} (${msg.reason ?? ""})`));
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