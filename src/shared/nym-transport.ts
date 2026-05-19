// SPDX-License-Identifier: Apache-2.0
import WebSocket from "ws";

// Talks to a locally running `nym-client` over its native WebSocket interface
// (default ws://127.0.0.1:1977). All payloads are JSON text frames per the
// nym-client native protocol:
//   request:  {"type":"send","message":"...","recipient":"...","withReplySurb":false}
//   request:  {"type":"selfAddress"}
//   response: {"type":"selfAddress","address":"..."}
//   incoming: {"type":"received","message":"...","senderTag":null|string}
//   error:    {"type":"error","message":"..."}

export interface NymOptions {
  url?: string; // default ws://127.0.0.1:1977
}

export interface IncomingMessage {
  text: string;
  senderTag: string | null;
}

export class NymTransport {
  private ws!: WebSocket;
  private readyP!: Promise<void>;
  private readonly listeners = new Set<(m: IncomingMessage) => void>();
  private selfAddrResolve?: (addr: string) => void;
  private selfAddrPromise?: Promise<string>;

  constructor(private readonly opts: NymOptions = {}) {}

  async connect(): Promise<void> {
    const url = this.opts.url ?? "ws://127.0.0.1:1977";
    this.ws = new WebSocket(url);
    this.readyP = new Promise((resolve, reject) => {
      this.ws.once("open", () => resolve());
      this.ws.once("error", reject);
    });
    this.ws.on("message", (data) => this.onFrame(data));
    await this.readyP;
  }

  private onFrame(data: WebSocket.RawData): void {
    let text: string;
    if (typeof data === "string") text = data;
    else if (Buffer.isBuffer(data)) text = data.toString("utf8");
    else text = Buffer.concat(data as Buffer[]).toString("utf8");

    let obj: any;
    try {
      obj = JSON.parse(text);
    } catch {
      // Binary frames from nym-client are uncommon for our JSON-only usage; ignore.
      return;
    }
    switch (obj.type) {
      case "selfAddress":
        this.selfAddrResolve?.(obj.address);
        break;
      case "received":
        for (const l of this.listeners) l({ text: obj.message, senderTag: obj.senderTag ?? null });
        break;
      case "error":
        console.error("[nym] error:", obj.message);
        break;
    }
  }

  async selfAddress(): Promise<string> {
    if (!this.selfAddrPromise) {
      this.selfAddrPromise = new Promise<string>((resolve) => {
        this.selfAddrResolve = resolve;
      });
      this.ws.send(JSON.stringify({ type: "selfAddress" }));
    }
    return this.selfAddrPromise;
  }

  send(recipient: string, payload: string): void {
    this.ws.send(
      JSON.stringify({
        type: "send",
        message: payload,
        recipient,
        withReplySurb: false,
      }),
    );
  }

  onMessage(cb: (m: IncomingMessage) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  async close(): Promise<void> {
    this.ws.close();
  }
}