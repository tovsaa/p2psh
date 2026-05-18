// Messages exchanged inside AppData.enc once the AEAD session is up.
// The Nym mixnet only ever sees these in encrypted form.
//
// Flow:
//   client -> server : { t: "sdp", role: "offer",  sdp: "..." }
//   server -> client : { t: "sdp", role: "answer", sdp: "..." }
//   both ways        : { t: "ice", candidate: <RTCIceCandidateInit> }
//   either way       : { t: "app", payload: "..." }
//                       (last one is for any pre-WebRTC chatter / debugging;
//                        real app traffic goes through the DataChannel.)

export type Signal = SdpSignal | IceSignal | AppSignal;

export interface SdpSignal {
  t: "sdp";
  role: "offer" | "answer";
  sdp: string;
}

export interface IceSignal {
  t: "ice";
  candidate: {
    candidate: string;
    sdpMid?: string | null;
    sdpMLineIndex?: number | null;
  };
  // null marks end-of-candidates per the WebRTC spec; both werift and browsers emit it.
  end?: boolean;
}

export interface AppSignal {
  t: "app";
  payload: string;
}
