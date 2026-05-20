// SPDX-License-Identifier: Apache-2.0
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
import { Msg, TransportChoice, b64uDecode, b64uEncode } from "../../src/shared/protocol.js";
import { Signal } from "../../src/shared/signaling.js";
import { decodeConnectString } from "../../src/shared/connect-string.js";
// Type-only import: erased at build time. The Nym SDK is heavy (~5 MB
// including WASM), so we lazy-load the runtime module on Connect click —
// see the dynamic `import("./nym-browser.js")` inside run().
import type { NymBrowserTransport } from "./nym-browser.js";
import { NymChannel, Channel } from "../../src/shared/channel.js";
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

// Auto-fill the connect string + transport from the URL hash
// (#c=p2psh1://...&t=nym), so a shared link drops the user straight onto Connect.
(() => {
  const hash = location.hash.replace(/^#/, "");
  const params = new URLSearchParams(hash);
  const c = params.get("c");
  if (c) $<HTMLTextAreaElement>("connect").value = c;
  const t = params.get("t");
  if (t === "nym" || t === "webrtc") {
    const radio = document.querySelector<HTMLInputElement>(`input[name="transport"][value="${t}"]`);
    if (radio) radio.checked = true;
  }
})();

function selectedTransport(): TransportChoice {
  const checked = document.querySelector<HTMLInputElement>('input[name="transport"]:checked');
  return checked?.value === "nym" ? "nym" : "webrtc";
}

// Classify the local NAT against two independent STUN servers within a short
// window. We hit Google and Cloudflare from the same RTCPeerConnection, then:
//
//   "ok"        — at least one srflx candidate appeared AND any srflx
//                 candidates that share a local port (rport) report the same
//                 reflexive ip:port. Cone-style NAT or open network — direct
//                 WebRTC P2P should work.
//   "symmetric" — srflx candidates appeared but with DIFFERENT reflexive
//                 ip:port for the same local port. Symmetric NAT allocates a
//                 fresh external mapping per destination; direct P2P UDP
//                 cannot be hole-punched without a TURN relay (we don't ship
//                 one), so this transport must be Nym.
//   "blocked"   — no srflx candidate at all in the window. UDP egress
//                 blocked, captive portal, or every STUN unreachable. Also
//                 forces Nym.
type NatProbeResult = "ok" | "symmetric" | "blocked";

function classify(reflexivesByRport: Map<string, Set<string>>): NatProbeResult {
  if (reflexivesByRport.size === 0) return "blocked";
  let totalReflexives = 0;
  let inconsistent = false;
  for (const set of reflexivesByRport.values()) {
    totalReflexives += set.size;
    if (set.size > 1) inconsistent = true;
  }
  if (inconsistent) return "symmetric";
  // Only one reflexive in total means a single STUN responded — we can't
  // distinguish cone vs symmetric. Be optimistic; if WebRTC ultimately can't
  // establish, the bring-up timeout will surface that separately.
  void totalReflexives;
  return "ok";
}

async function probeNat(timeoutMs = 3000): Promise<NatProbeResult> {
  return new Promise((resolve) => {
    let settled = false;
    const reflexivesByRport = new Map<string, Set<string>>();
    const pc = new RTCPeerConnection({
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun.cloudflare.com:3478" },
      ],
    });
    const finish = (result: NatProbeResult): void => {
      if (settled) return;
      settled = true;
      try { pc.close(); } catch { /* ignore */ }
      resolve(result);
    };
    pc.onicecandidate = ({ candidate }) => {
      if (!candidate) {
        finish(classify(reflexivesByRport));
        return;
      }
      const line = candidate.candidate;
      // candidate:foundation comp proto prio IP PORT typ srflx raddr R rport P
      const m = line.match(/typ srflx .* rport (\d+)/);
      if (!m) return;
      const rport = m[1];
      const parts = line.split(/\s+/);
      const refKey = `${parts[4]}:${parts[5]}`;
      let bucket = reflexivesByRport.get(rport);
      if (!bucket) {
        bucket = new Set();
        reflexivesByRport.set(rport, bucket);
      }
      bucket.add(refKey);
    };
    pc.createDataChannel("probe");
    pc.createOffer()
      .then((o) => pc.setLocalDescription(o))
      .catch(() => finish("blocked"));
    setTimeout(() => finish(classify(reflexivesByRport)), timeoutMs);
  });
}

void (async () => {
  const statusEl = $<HTMLParagraphElement>("nat-status");
  const webrtcRadio = document.querySelector<HTMLInputElement>('input[name="transport"][value="webrtc"]')!;
  const nymRadio = document.querySelector<HTMLInputElement>('input[name="transport"][value="nym"]')!;
  const result = await probeNat();
  if (result === "ok") {
    statusEl.textContent = "WebRTC reachable (consistent srflx across two STUN servers).";
    statusEl.style.color = "#5a5";
    return;
  }
  if (result === "symmetric") {
    statusEl.textContent =
      "Symmetric NAT detected — direct P2P UDP hole-punch will fail. Forcing Nym tunnel.";
  } else {
    statusEl.textContent =
      "WebRTC unavailable — no STUN srflx candidate (UDP blocked or strict NAT). Forcing Nym tunnel.";
  }
  statusEl.style.color = "#e88";
  webrtcRadio.disabled = true;
  // Keep the user's hash-pinned choice if they explicitly asked for nym;
  // otherwise force-flip.
  if (webrtcRadio.checked) {
    webrtcRadio.checked = false;
    nymRadio.checked = true;
  }
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

  log("loading Nym SDK (WASM)…");
  const { NymBrowserTransport } = await import("./nym-browser.js");
  log("starting Nym mixnet client (WASM)...");
  const nym = new NymBrowserTransport();
  await nym.connect();
  const me = await nym.selfAddress();
  log(`Nym ready. my address: ${me.slice(0, 24)}...`);

  const serverPk = b64uDecode(serverPkB64);
  const serverIdPk = b64uDecode(serverIdPkB64);

  const transport = selectedTransport();
  log(`transport=${transport}`);

  // One full connect cycle: (resume | full handshake) → channel bringup.
  // Returned as a closure so attachTerminal can call it again on a clean
  // channel close, preserving the live xterm instance + the user's WASM
  // Nym SDK initialization across reconnects.
  const connectOnce = async (): Promise<Channel> => {
    const saved = loadResumeState(serverIdPkB64);
    let session: Session;
    if (saved) {
      log("found saved session — attempting resume...");
      const attempt = clientResume(saved, me, transport);
      nym.send(serverAddr, JSON.stringify(attempt.request));
      try {
        session = await awaitResumeResult(nym, attempt, serverIdPkB64);
        log("resume OK — skipped full handshake.");
      } catch (e) {
        log(`resume failed (${(e as Error).message}); doing full handshake.`);
        dropResumeState(serverIdPkB64);
        session = await fullHandshake(nym, serverPk, serverIdPk, serverIdPkB64, serverAddr, me, transport);
      }
    } else {
      session = await fullHandshake(nym, serverPk, serverIdPk, serverIdPkB64, serverAddr, me, transport);
    }

    if (transport === "nym") {
      const channel = new NymChannel(nym, session, serverAddr);
      log("Nym-tunneled channel open.");
      return channel;
    } else {
      return await runWebRTC(nym, session, serverAddr);
    }
  };

  const channel = await connectOnce();
  attachTerminal(channel, connectOnce);
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
  transport: TransportChoice,
): Promise<Session> {
  return new Promise((resolve, reject) => {
    const state: ClientHandshakeState = clientInitiate(serverPk, me, transport);
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
): Promise<Channel> {
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

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  sendSignal({ t: "sdp", role: "offer", sdp: pc.localDescription!.sdp! });

  // Wait for the data channel to actually open before handing it back, so
  // the caller (connectOnce) doesn't try to send through a still-CONNECTING
  // channel.
  await new Promise<void>((resolve, reject) => {
    if (dc.readyState === "open") return resolve();
    dc.addEventListener("open", () => resolve(), { once: true });
    dc.addEventListener("error", (e) => reject(e), { once: true });
  });
  log("WebRTC DataChannel open.");
  return dc as unknown as Channel;
}

// Bridges xterm.js <-> Channel using the same JSON envelope the server expects:
// { t: "o", d } from server (output), { t: "i", d } from client (input),
// { t: "r", c, r } from client (resize hint). Works for both WebRTC and the
// Nym-tunneled NymChannel.
//
// If `reconnect` is provided, channel close triggers an exponential-backoff
// reconnect loop (2 s / 5 s / 15 s, then give up). The xterm instance and
// the WASM Nym client both survive across reconnects — only the data
// channel is re-established.
type ReconnectFn = () => Promise<Channel>;

function attachTerminal(initialChannel: Channel, reconnect: ReconnectFn | null = null): void {
  let channel = initialChannel;
  // Test hook: exposes the active channel and terminal on window so an
  // e2e driver can simulate input without faking keyboard events. Safe to
  // ship — it's just a reference, not extra capability. The getter ensures
  // the hook follows reconnects.
  (window as unknown as { __p2psh?: object }).__p2psh = {
    get channel(): Channel { return channel; },
  };

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
  // term.open() schedules layout; fit.fit() measures the container's
  // computed size. Calling fit synchronously can land before the browser
  // has applied the CSS pass, producing a 1-column terminal. Defer to the
  // next animation frame so layout is settled.
  const sendResize = (): void => {
    if (channel.readyState !== "open") return;
    channel.send(JSON.stringify({ t: "r", c: term.cols, r: term.rows }));
  };
  requestAnimationFrame(() => {
    fit.fit();
    sendResize();
  });
  window.addEventListener("resize", () => {
    fit.fit();
    sendResize();
  });

  term.onData((data) => {
    if (channel.readyState !== "open") return;
    channel.send(JSON.stringify({ t: "i", d: data }));
  });

  const RECONNECT_DELAYS_MS = [2000, 5000, 15000];

  const wireIncoming = (ch: Channel): void => {
    ch.addEventListener("message", (ev) => {
      const text = typeof ev.data === "string" ? ev.data : new TextDecoder().decode(ev.data);
      let msg: { t: string; d?: string };
      try { msg = JSON.parse(text); } catch { return; }
      if (msg.t === "o" && typeof msg.d === "string") term.write(msg.d);
    });
    ch.addEventListener("close", () => {
      if (!reconnect) {
        term.write("\r\n\x1b[31m[connection closed]\x1b[0m\r\n");
        return;
      }
      void attemptReconnect(0);
    });
  };

  const attemptReconnect = async (attempt: number): Promise<void> => {
    if (attempt >= RECONNECT_DELAYS_MS.length) {
      term.write("\r\n\x1b[31m[reconnect gave up — reload the page to retry]\x1b[0m\r\n");
      return;
    }
    const delay = RECONNECT_DELAYS_MS[attempt];
    term.write(`\r\n\x1b[33m[connection lost, reconnecting in ${delay / 1000}s…]\x1b[0m\r\n`);
    await new Promise((r) => setTimeout(r, delay));
    try {
      const next = await reconnect!();
      channel = next;
      wireIncoming(next);
      term.write("\r\n\x1b[32m[reconnected]\x1b[0m\r\n");
      // Re-send terminal size so the new PTY matches our viewport.
      next.send(JSON.stringify({ t: "r", c: term.cols, r: term.rows }));
    } catch (e) {
      term.write(`\r\n\x1b[31m[reconnect attempt ${attempt + 1} failed: ${(e as Error).message}]\x1b[0m\r\n`);
      void attemptReconnect(attempt + 1);
    }
  };

  wireIncoming(initialChannel);

  term.focus();
}