// SPDX-License-Identifier: Apache-2.0
// Minimal transport-agnostic channel surface.
//
// Both werift's RTCDataChannel and the browser-native RTCDataChannel
// structurally satisfy `Channel` for the bits we actually use, so the WebRTC
// path needs no adapter — it's just a type widening. The NymChannel class
// below provides a second implementation that tunnels application frames
// through the Nym mixnet using the existing AEAD session, bypassing WebRTC
// entirely (and therefore the STUN-driven IP exposure).
//
// Framing for the Nym path: every plaintext payload is prefixed with a single
// kind byte before AEAD-sealing.
//   0x00 — data frame; the remainder is the caller's UTF-8 payload.
//   0x01 — close frame; no payload. Sent at most once, on graceful close.
// We could have multiplexed via a JSON wrapper instead, but a 1-byte prefix
// keeps the shell-bridge oblivious — it sees the same `{t:"i"|"o"|"r",…}`
// frames it would see over WebRTC.

import { Session, encodeAppData, decodeAppData } from "./handshake.js";
import { Msg } from "./protocol.js";

// Structural subset of NymTransport / NymBrowserTransport. Both implementations
// satisfy this — the Node version lives in nym-transport.ts, the browser one in
// web/src/nym-browser.ts. Decoupling here keeps `Channel` shareable between
// Node and browser bundles without dragging in a transport choice.
export interface NymLike {
  send(recipient: string, payload: string): void;
  onMessage(cb: (m: { text: string }) => void): () => void;
}

export interface ChannelMessageEvent {
  data: string | ArrayBuffer | Uint8Array;
}

export type ChannelReadyState = "connecting" | "open" | "closing" | "closed";

export interface Channel {
  readyState: ChannelReadyState;
  send(data: string): void;
  close(): void;
  addEventListener(event: "message", listener: (ev: ChannelMessageEvent) => void): void;
  addEventListener(event: "close", listener: () => void): void;
}

const KIND_DATA = 0x00;
const KIND_CLOSE = 0x01;

type MsgListener = (ev: ChannelMessageEvent) => void;
type CloseListener = () => void;

export class NymChannel implements Channel {
  public readyState: ChannelReadyState = "open";
  private readonly msgListeners: MsgListener[] = [];
  private readonly closeListeners: CloseListener[] = [];
  private readonly detach: () => void;
  private readonly label: string;

  constructor(
    private readonly nym: NymLike,
    private readonly session: Session,
    private readonly remoteAddr: string,
    label?: string,
  ) {
    this.label = label ?? remoteAddr.slice(0, 24);
    this.detach = nym.onMessage(({ text }) => this.handleIncoming(text));
  }

  send(data: string): void {
    if (this.readyState !== "open") return;
    const payload = new TextEncoder().encode(data);
    const buf = new Uint8Array(payload.length + 1);
    buf[0] = KIND_DATA;
    buf.set(payload, 1);
    const frame = encodeAppData(this.session, buf);
    this.nym.send(this.remoteAddr, JSON.stringify(frame));
  }

  close(): void {
    if (this.readyState === "closed") return;
    // Best-effort graceful close — peer's onmessage decodes a 0x01 frame and
    // fires its close listeners. Abrupt disconnects (peer crash, network drop)
    // leave the remote side hanging until the next handshake/resume tears it
    // down via tearDownPeer in the server loop.
    if (this.readyState === "open") {
      try {
        const frame = encodeAppData(this.session, new Uint8Array([KIND_CLOSE]));
        this.nym.send(this.remoteAddr, JSON.stringify(frame));
      } catch (e) {
        console.error(`[nym-channel:${this.label}] failed to send close frame:`, e);
      }
    }
    this.markClosed();
  }

  addEventListener(event: "message", listener: MsgListener): void;
  addEventListener(event: "close", listener: CloseListener): void;
  addEventListener(event: "message" | "close", listener: MsgListener | CloseListener): void {
    if (event === "message") this.msgListeners.push(listener as MsgListener);
    else this.closeListeners.push(listener as CloseListener);
  }

  private handleIncoming(text: string): void {
    if (this.readyState !== "open") return;
    let msg: Msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    if (msg.t !== "data") return;
    let pt: Uint8Array;
    try {
      pt = decodeAppData(this.session, msg);
    } catch {
      // Same rationale as webrtc-peer's silent drop: stale frames from a
      // previous session can land in the replay window of a fresh session
      // (especially right after resume). Dropping them is correct.
      return;
    }
    if (pt.length === 0) return;
    const kind = pt[0];
    if (kind === KIND_CLOSE) {
      this.markClosed();
      return;
    }
    if (kind !== KIND_DATA) return; // unknown kind byte — forward-compat reservation
    const data = new TextDecoder().decode(pt.subarray(1));
    for (const l of this.msgListeners) {
      try {
        l({ data });
      } catch (e) {
        console.error(`[nym-channel:${this.label}] message listener threw:`, e);
      }
    }
  }

  private markClosed(): void {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    try {
      this.detach();
    } catch (e) {
      console.error(`[nym-channel:${this.label}] detach on close:`, e);
    }
    for (const l of this.closeListeners) {
      try {
        l();
      } catch (e) {
        console.error(`[nym-channel:${this.label}] close listener threw:`, e);
      }
    }
  }
}