import {
  ClientHandshakeState,
  ClientResumeAttempt,
  ResumeState,
  Session,
  clientInitiate,
  clientResume,
  clientVerifyAck,
  clientVerifyResumeAck,
  decodeAppData,
  encodeAppData,
  extractResumeStateFromHandshake,
  newResumeStateAfterResume,
} from "../../src/shared/handshake.js";
import { Msg, b64uDecode, b64uEncode } from "../../src/shared/protocol.js";
import { Signal } from "../../src/shared/signaling.js";
import { decodeConnectString } from "../../src/shared/connect-string.js";
import { NymBrowserTransport } from "./nym-browser.js";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const logEl = $<HTMLDivElement>("log");

function log(line: string): void {
  const ts = new Date().toISOString().slice(11, 19);
  logEl.textContent += `[${ts}] ${line}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

const STORAGE_PREFIX = "p2psh-resume:";

function loadResumeState(serverIdPkB64: string): ResumeState | null {
  const raw = localStorage.getItem(STORAGE_PREFIX + serverIdPkB64);
  if (!raw) return null;
  try {
    const obj = JSON.parse(raw);
    return { sessionId: b64uDecode(obj.sessionId), key: b64uDecode(obj.key) };
  } catch {
    return null;
  }
}

function saveResumeState(serverIdPkB64: string, state: ResumeState): void {
  localStorage.setItem(
    STORAGE_PREFIX + serverIdPkB64,
    JSON.stringify({
      sessionId: b64uEncode(state.sessionId),
      key: b64uEncode(state.key),
    }),
  );
}

function dropResumeState(serverIdPkB64: string): void {
  localStorage.removeItem(STORAGE_PREFIX + serverIdPkB64);
}

// Auto-fill the connect string from the URL hash (#c=p2psh1://...), so a
// shared link drops the user straight onto Connect.
(() => {
  const hash = location.hash.replace(/^#/, "");
  const params = new URLSearchParams(hash);
  const c = params.get("c");
  if (c) $<HTMLTextAreaElement>("connect").value = c;
})();

$<HTMLButtonElement>("go").addEventListener("click", () => {
  $<HTMLButtonElement>("go").disabled = true;
  run().catch((e) => {
    log(`FATAL: ${e?.message ?? e}`);
    console.error(e);
  });
});

async function run(): Promise<void> {
  const raw = $<HTMLTextAreaElement>("connect").value.trim();
  if (!raw) throw new Error("paste the connect string from the server");
  const { addr: serverAddr, kemPk: serverPkB64, idPk: serverIdPkB64 } = decodeConnectString(raw);

  log("starting Nym mixnet client (WASM)...");
  const nym = new NymBrowserTransport();
  await nym.connect();
  const me = await nym.selfAddress();
  log(`Nym ready. my address: ${me.slice(0, 24)}...`);

  const serverPk = b64uDecode(serverPkB64);
  const serverIdPk = b64uDecode(serverIdPkB64);

  // Two negotiation paths: resume first if we have saved state, fall back to
  // full ML-KEM handshake on NACK or any decryption failure.
  const saved = loadResumeState(serverIdPkB64);

  let session: Session;
  if (saved) {
    log("found saved session — attempting resume...");
    const attempt = clientResume(saved, me);
    nym.send(serverAddr, JSON.stringify(attempt.request));
    try {
      session = await awaitResumeResult(nym, attempt, serverIdPkB64);
      log("resume OK — skipped full handshake.");
    } catch (e) {
      log(`resume failed (${(e as Error).message}); doing full handshake.`);
      dropResumeState(serverIdPkB64);
      session = await fullHandshake(nym, serverPk, serverIdPk, serverIdPkB64, serverAddr, me);
    }
  } else {
    session = await fullHandshake(nym, serverPk, serverIdPk, serverIdPkB64, serverAddr, me);
  }

  // From here on, everything in the AEAD session is WebRTC signaling.
  await runWebRTC(nym, session, serverAddr);
}

function awaitResumeResult(
  nym: NymBrowserTransport,
  attempt: ClientResumeAttempt,
  serverIdPkB64: string,
): Promise<Session> {
  return new Promise((resolve, reject) => {
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
        saveResumeState(serverIdPkB64, newResumeStateAfterResume(attempt));
        detach();
        resolve(attempt.session);
      }
    });
  });
}

function fullHandshake(
  nym: NymBrowserTransport,
  serverPk: Uint8Array,
  serverIdPk: Uint8Array,
  serverIdPkB64: string,
  serverAddr: string,
  me: string,
): Promise<Session> {
  return new Promise((resolve, reject) => {
    const state: ClientHandshakeState = clientInitiate(serverPk, me);
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
      saveResumeState(serverIdPkB64, extractResumeStateFromHandshake(state));
      log("handshake verified — Ed25519 OK, session key agreed and saved.");
      detach();
      resolve(state.session);
    });
    log(`sending ClientHello to ${serverAddr.slice(0, 24)}...`);
    nym.send(serverAddr, JSON.stringify(state.hello));
  });
}

async function runWebRTC(
  nym: NymBrowserTransport,
  session: Session,
  serverAddr: string,
): Promise<void> {
  const pc = new RTCPeerConnection({
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun.cloudflare.com:3478" },
    ],
  });
  type IceInit = Parameters<typeof pc.addIceCandidate>[0];
  let remoteDescApplied = false;
  const pendingCandidates: IceInit[] = [];

  const sendSignal = (s: Signal): void => {
    const frame = encodeAppData(session, new TextEncoder().encode(JSON.stringify(s)));
    nym.send(serverAddr, JSON.stringify(frame));
  };

  pc.onicecandidate = ({ candidate }) => {
    if (!candidate) {
      sendSignal({ t: "ice", candidate: { candidate: "" }, end: true });
      return;
    }
    sendSignal({
      t: "ice",
      candidate: {
        candidate: candidate.candidate,
        sdpMid: candidate.sdpMid,
        sdpMLineIndex: candidate.sdpMLineIndex,
      },
    });
  };

  nym.onMessage(async ({ text }) => {
    let msg: Msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    if (msg.t !== "data") return;
    let signal: Signal;
    try {
      const pt = decodeAppData(session, msg);
      signal = JSON.parse(new TextDecoder().decode(pt));
    } catch {
      // See comment in src/shared/webrtc-peer.ts — stale frames after a
      // resume can land in our anti-replay window; drop silently.
      return;
    }
    try {
      if (signal.t === "sdp") {
        await pc.setRemoteDescription({ type: signal.role, sdp: signal.sdp });
        remoteDescApplied = true;
        for (const c of pendingCandidates) await pc.addIceCandidate(c);
        pendingCandidates.length = 0;
        if (signal.role === "offer") {
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          sendSignal({ t: "sdp", role: "answer", sdp: pc.localDescription!.sdp! });
        }
      } else if (signal.t === "ice") {
        if (signal.end) return;
        if (remoteDescApplied) await pc.addIceCandidate(signal.candidate);
        else pendingCandidates.push(signal.candidate);
      }
    } catch (e) {
      log(`signal handling failed: ${(e as Error).message}`);
    }
  });

  const dc = pc.createDataChannel("app");
  dc.onopen = () => {
    log("WebRTC DataChannel open — attaching terminal.");
    attachTerminal(dc);
  };

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  sendSignal({ t: "sdp", role: "offer", sdp: pc.localDescription!.sdp! });
}

// Bridges xterm.js <-> DataChannel using the same JSON envelope the server
// expects: { t: "o", d } from server (output), { t: "i", d } from client
// (input), { t: "r", c, r } from client (resize hint).
function attachTerminal(dc: RTCDataChannel): void {
  const term = new Terminal({
    convertEol: false,
    fontSize: 13,
    fontFamily: "ui-monospace, monospace",
    cursorBlink: true,
    theme: { background: "#000000" },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open($("term"));
  fit.fit();

  const sendResize = (): void => {
    if (dc.readyState !== "open") return;
    dc.send(JSON.stringify({ t: "r", c: term.cols, r: term.rows }));
  };
  sendResize();
  window.addEventListener("resize", () => {
    fit.fit();
    sendResize();
  });

  term.onData((data) => {
    if (dc.readyState !== "open") return;
    dc.send(JSON.stringify({ t: "i", d: data }));
  });

  dc.onmessage = (ev) => {
    const text = typeof ev.data === "string" ? ev.data : new TextDecoder().decode(ev.data);
    let msg: { t: string; d?: string };
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    if (msg.t === "o" && typeof msg.d === "string") term.write(msg.d);
  };

  dc.addEventListener("close", () => {
    term.write("\r\n\x1b[31m[connection closed]\x1b[0m\r\n");
  });

  term.focus();
}
