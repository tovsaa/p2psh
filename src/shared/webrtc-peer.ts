import { RTCPeerConnection, RTCDataChannel } from "werift";
import { Session, decodeAppData, encodeAppData } from "./handshake.js";
import { Msg } from "./protocol.js";
import { Signal } from "./signaling.js";
import { NymTransport } from "./nym-transport.js";

export interface PeerOptions {
  role: "offerer" | "answerer";
  nym: NymTransport;
  session: Session;
  remoteAddr: string;
}

export interface PeerHandle {
  dc: RTCDataChannel;
  pc: RTCPeerConnection;
  // Releases the Nym signaling listener and closes the PeerConnection. Call
  // when the peer reconnects so we don't accumulate stale sessions that keep
  // trying to decrypt frames with old keys.
  dispose: () => void;
}

/**
 * Brings up a single WebRTC DataChannel between two peers whose Nym addresses
 * are already known and whose AEAD session has been established.
 *
 * The offerer creates the DataChannel; the answerer waits for it. SDP and ICE
 * traffic is wrapped in `Signal` envelopes and sent through the AEAD session,
 * so the local nym-client (and the entire mixnet) only see ciphertext.
 *
 * Returns a Promise that resolves with a handle containing the open DC, the
 * PeerConnection, and a dispose function for cleanup on reconnect.
 */
export async function bringUpPeer(opts: PeerOptions): Promise<PeerHandle> {
  const { role, nym, session, remoteAddr } = opts;

  // No ICE servers: for the MVP both processes run on the same Windows host,
  // so host candidates (127.0.0.1 / WSL-NAT IPs) are sufficient. Real
  // deployments will set iceServers to public STUN.
  const pc = new RTCPeerConnection({ iceServers: [] });

  const sendSignal = (s: Signal): void => {
    const frame = encodeAppData(session, new TextEncoder().encode(JSON.stringify(s)));
    nym.send(remoteAddr, JSON.stringify(frame));
  };

  // Local ICE candidates → ship to the peer through the AEAD/Nym channel.
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

  // The DataChannel: offerer creates, answerer receives via the negotiation event.
  let dcResolve!: (dc: RTCDataChannel) => void;
  let dcReject!: (e: unknown) => void;
  const dcPromise = new Promise<RTCDataChannel>((res, rej) => {
    dcResolve = res;
    dcReject = rej;
  });

  const armDc = (dc: RTCDataChannel): void => {
    if (dc.readyState === "open") {
      dcResolve(dc);
      return;
    }
    dc.addEventListener("open", () => dcResolve(dc));
    dc.addEventListener("error", (e) => dcReject(e));
  };

  if (role === "offerer") {
    armDc(pc.createDataChannel("app"));
  } else {
    pc.ondatachannel = (ev) => armDc(ev.channel);
  }

  // Nym reorders and trickle ICE candidates arrive nearly back-to-back with
  // the SDP. Buffer candidates that show up before the remote description.
  type IceInit = Parameters<typeof pc.addIceCandidate>[0];
  let remoteDescApplied = false;
  const pendingCandidates: IceInit[] = [];

  const detach = nym.onMessage(async ({ text }) => {
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
      // Expected after a resume: late-arriving frames from the previous
      // session were AEAD-sealed under the old key with overlapping wire
      // seqs. They hit either the wrong key or our anti-replay window for
      // the new session. Drop silently — the live session is unaffected.
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
          sendSignal({ t: "sdp", role: "answer", sdp: pc.localDescription!.sdp });
        }
      } else if (signal.t === "ice") {
        if (signal.end) return; // werift handles end-of-candidates implicitly
        if (remoteDescApplied) await pc.addIceCandidate(signal.candidate);
        else pendingCandidates.push(signal.candidate);
      }
    } catch (e) {
      console.error("[webrtc] signal handling failed:", e);
    }
  });

  if (role === "offerer") {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendSignal({ t: "sdp", role: "offer", sdp: pc.localDescription!.sdp });
  }

  const openDc = await dcPromise;
  return {
    dc: openDc,
    pc,
    dispose: () => {
      detach();
      try {
        pc.close();
      } catch {
        // already closed
      }
    },
  };
}
