// SPDX-License-Identifier: Apache-2.0
import { createNymMixnetClient, NymMixnetClient, EventKinds } from "@nymproject/sdk-full-fat";

// Browser-side Nym transport. Exposes the same surface our Node transport
// uses (`connect`, `selfAddress`, `send`, `onMessage`) so the rest of the
// browser code can be written against a single interface.
//
// Sends our JSON wire frames as raw byte payloads (BinaryMessage). The peer
// (Node `nym-client` over native WebSocket) receives them as text frames —
// nym-client decodes UTF-8 binary payloads to the `message` field of the
// `received` event, which is what our server already reads.

export interface IncomingMessage {
  text: string;
}

export class NymBrowserTransport {
  private mix!: NymMixnetClient;
  private readonly listeners = new Set<(m: IncomingMessage) => void>();

  async connect(): Promise<void> {
    this.mix = await createNymMixnetClient();

    // Subscribe BEFORE start() so we don't miss the Connected event that
    // resolves selfAddress availability.
    const connected = new Promise<void>((resolve) => {
      this.mix.events.subscribeToConnected(() => resolve());
    });

    // The Linux nym-client we talk to uses its native WebSocket protocol and
    // sends raw text payloads with no mime envelope. Those arrive here as raw
    // message events. We subscribe to all three flavours so we don't miss
    // anything the peer might send under a different mime regime.
    this.mix.events.subscribeToTextMessageReceivedEvent((e) => {
      for (const l of this.listeners) l({ text: e.args.payload });
    });
    this.mix.events.subscribeToBinaryMessageReceivedEvent((e) => {
      const text = new TextDecoder().decode(e.args.payload);
      for (const l of this.listeners) l({ text });
    });
    this.mix.events.subscribeToRawMessageReceivedEvent((e) => {
      const text = new TextDecoder().decode(e.args.payload);
      for (const l of this.listeners) l({ text });
    });

    // Same network the Linux nym-client uses by default, so the two ends meet
    // in the same mixnet.
    await this.mix.client.start({
      nymApiUrl: "https://validator.nymtech.net/api",
    });

    await connected;
  }

  async selfAddress(): Promise<string> {
    const a = await this.mix.client.selfAddress();
    if (!a) throw new Error("nym selfAddress not available yet");
    return a;
  }

  send(recipient: string, payload: string): void {
    // rawSend ships the bytes with no mime envelope, matching what the Linux
    // nym-client's native WS does on the peer side. With `client.send` the
    // WASM client prepends a Content-Type header, which the peer then sees as
    // part of the message body and our JSON parser silently drops the frame.
    void this.mix.client.rawSend({
      payload: new TextEncoder().encode(payload),
      recipient,
    });
  }

  onMessage(cb: (m: IncomingMessage) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }
}

// Keep import happy if EventKinds tree-shakes away in the bundle.
void EventKinds;