import { spawn, IPty } from "node-pty";
import type { RTCDataChannel } from "werift";

// Wire format over the DataChannel (JSON text frames):
//   server -> client : { t: "o", d: "<stdout chunk>" }
//   client -> server : { t: "i", d: "<keystrokes>" }
//   client -> server : { t: "r", c: <cols>, r: <rows> }
//
// "ssh-bridge" is a bit of a misnomer — we hand the peer a PTY shell directly
// on this host. That is the same UX as `ssh user@host` (interactive shell)
// without the SSH key exchange, which our ML-KEM/Ed25519 layer already provides.
// For a more locked-down deployment, replace the spawn target with `ssh
// fixed-user@localhost` so OpenSSH does session enforcement.

const SHELL = process.env.P2PSH_SHELL ?? (process.platform === "win32" ? "wsl.exe" : "bash");
const SHELL_ARGS_ENV = process.env.P2PSH_SHELL_ARGS;
const SHELL_ARGS = SHELL_ARGS_ENV ? SHELL_ARGS_ENV.split(" ") : [];

interface InMsg {
  t: "i" | "r";
  d?: string;
  c?: number;
  r?: number;
}

export function attachShellToDataChannel(dc: RTCDataChannel): IPty {
  const pty = spawn(SHELL, SHELL_ARGS, {
    name: "xterm-256color",
    cols: 80,
    rows: 24,
    cwd: process.env.HOME || process.env.USERPROFILE,
    env: process.env as Record<string, string>,
  });

  pty.onData((data) => {
    if (dc.readyState !== "open") return;
    dc.send(JSON.stringify({ t: "o", d: data }));
  });

  pty.onExit(({ exitCode, signal }) => {
    if (dc.readyState === "open") {
      dc.send(JSON.stringify({ t: "o", d: `\r\n[shell exited code=${exitCode} signal=${signal}]\r\n` }));
    }
    try {
      dc.close();
    } catch {
      // already closed
    }
  });

  dc.addEventListener("message", (ev: MessageEvent) => {
    const text = typeof ev.data === "string" ? ev.data : new TextDecoder().decode(ev.data);
    let msg: InMsg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    if (msg.t === "i" && typeof msg.d === "string") {
      pty.write(msg.d);
    } else if (msg.t === "r" && typeof msg.c === "number" && typeof msg.r === "number") {
      try {
        pty.resize(Math.max(1, msg.c), Math.max(1, msg.r));
      } catch {
        // resize after exit
      }
    }
  });

  dc.addEventListener("close", () => {
    try {
      pty.kill();
    } catch {
      // already gone
    }
  });

  return pty;
}
