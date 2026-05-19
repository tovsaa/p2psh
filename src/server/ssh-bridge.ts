// SPDX-License-Identifier: Apache-2.0
import { spawn, IPty } from "node-pty";
import { appendFile } from "node:fs/promises";
import type { Channel, ChannelMessageEvent } from "../shared/channel.js";

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

// Anything not in this set is dropped before spawn, so a peer cannot read
// host credentials (AWS_*, GITHUB_TOKEN, SSH_AUTH_SOCK, …) via `printenv`.
const ENV_ALLOWLIST = new Set([
  "PATH", "HOME", "USER", "USERNAME", "LOGNAME",
  "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_NUMERIC", "LC_TIME",
  "TERM", "TZ", "SHELL", "PWD",
  "USERPROFILE", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "TEMP", "TMP",
]);

function buildShellEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    if (ENV_ALLOWLIST.has(k)) out[k] = v;
  }
  out.P2PSH_SESSION = "1";
  return out;
}

const SHELL = process.env.P2PSH_SHELL ?? (process.platform === "win32" ? "wsl.exe" : "bash");
const SHELL_ARGS_ENV = process.env.P2PSH_SHELL_ARGS;
const SHELL_ARGS = SHELL_ARGS_ENV ? SHELL_ARGS_ENV.split(" ").filter((s) => s.length > 0) : [];
const RESTRICT = process.env.P2PSH_RESTRICT === "1";
const AUDIT_LOG_PATH = process.env.P2PSH_AUDIT_LOG;

function resolveShell(): { cmd: string; args: string[] } {
  // P2PSH_RESTRICT=1 swaps in rbash on POSIX (no-op on Windows / when the user
  // already pinned P2PSH_SHELL explicitly). rbash blocks cd, PATH changes,
  // absolute-path execs and output redirection — enough to keep an honest peer
  // out of trouble. It is NOT a security boundary; pair with an unprivileged
  // user/container for real isolation.
  if (RESTRICT && process.platform !== "win32" && !process.env.P2PSH_SHELL) {
    return { cmd: "rbash", args: SHELL_ARGS };
  }
  return { cmd: SHELL, args: SHELL_ARGS };
}

interface InMsg {
  t: "i" | "r";
  d?: string;
  c?: number;
  r?: number;
}

export function attachShellToDataChannel(
  dc: Channel,
  opts: { peerLabel?: string } = {},
): IPty {
  const peerLabel = opts.peerLabel ?? "peer";
  const { cmd, args } = resolveShell();
  const env = buildShellEnv();

  const pty = spawn(cmd, args, {
    name: "xterm-256color",
    cols: 80,
    rows: 24,
    cwd: env.HOME || env.USERPROFILE || process.cwd(),
    env,
  });

  // Audit log buffers per-peer (not module-level — would interleave across peers).
  // Flushes on newline; truncated trailing line is flushed on dc close.
  let auditBuf = "";
  const flushAudit = (chunk: string): void => {
    if (!AUDIT_LOG_PATH) return;
    auditBuf += chunk;
    const parts = auditBuf.split(/\r?\n/);
    auditBuf = parts.pop() ?? "";
    if (parts.length === 0) return;
    const now = new Date().toISOString();
    const text = parts.map((line) => `${now} ${peerLabel} ${line}\n`).join("");
    appendFile(AUDIT_LOG_PATH, text).catch((e) =>
      console.error(`[ssh-bridge:${peerLabel}] audit log write failed:`, e),
    );
  };

  pty.onData((data) => {
    if (dc.readyState !== "open") return;
    dc.send(JSON.stringify({ t: "o", d: data }));
  });

  pty.onExit(({ exitCode, signal }) => {
    if (dc.readyState === "open") {
      try {
        dc.send(JSON.stringify({ t: "o", d: `\r\n[shell exited code=${exitCode} signal=${signal}]\r\n` }));
      } catch (e) {
        console.error(`[ssh-bridge:${peerLabel}] failed to send exit notice:`, e);
      }
    }
    try {
      dc.close();
    } catch (e) {
      console.error(`[ssh-bridge:${peerLabel}] dc.close after exit:`, e);
    }
  });

  dc.addEventListener("message", (ev: ChannelMessageEvent) => {
    const text = typeof ev.data === "string" ? ev.data : new TextDecoder().decode(ev.data);
    let msg: InMsg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    if (msg.t === "i" && typeof msg.d === "string") {
      pty.write(msg.d);
      flushAudit(msg.d);
    } else if (msg.t === "r" && typeof msg.c === "number" && typeof msg.r === "number") {
      try {
        pty.resize(Math.max(1, msg.c), Math.max(1, msg.r));
      } catch (e) {
        // PTY already exited; benign.
        void e;
      }
    }
  });

  dc.addEventListener("close", () => {
    if (auditBuf.length > 0) flushAudit("\n");
    try {
      pty.kill();
    } catch (e) {
      console.error(`[ssh-bridge:${peerLabel}] pty.kill on dc close:`, e);
    }
  });

  return pty;
}