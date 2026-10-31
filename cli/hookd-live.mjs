// Whether moorai-hookd is up on a port, for the plugin copy of the hook (cli/moorai-hook.mjs settingsCovers).
// A MoorAI http entry with onFailure "continue" covers an event only while moorai-hookd answers it: when the
// daemon is down Claude Code treats the failed request as a non-blocking error and runs the tool call unchecked
// (hooks reference: "Connection failure: non-blocking error"), so the plugin copy must not stand down then.
// moorai-hookd writes its pid to ~/.moorai/hookd-<port>.pid once it listens and removes it when it stops. Live
// means: that file names a process this user can signal (process.kill(pid, 0)) AND a loopback connection to the
// port is accepted. A stale file (a killed daemon, its pid reused) fails the second test; a port taken by another
// process with no daemon of ours fails the first.
import { readFileSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";

const CONNECT_MS = 200;

export const hookdPidPath = (port, stateDir = STATE_DIR) => join(stateDir, `hookd-${port}.pid`);

export function writeHookdPid(port, { stateDir = STATE_DIR, pid = process.pid } = {}) {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  writeFileSync(hookdPidPath(port, stateDir), `${pid}\n`, { mode: 0o600 });
}

export function removeHookdPid(port, { stateDir = STATE_DIR, pid = process.pid } = {}) {
  try { if (Number(readFileSync(hookdPidPath(port, stateDir), "utf8").trim()) === pid) rmSync(hookdPidPath(port, stateDir), { force: true }); } catch { /* already gone */ }
}

export function pidAlive(pid) {
  if (!(Number.isSafeInteger(pid) && pid > 1)) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}

export function portListening(port, { timeoutMs = CONNECT_MS } = {}) {
  return new Promise((res) => {
    const s = connect({ host: "127.0.0.1", port });
    const done = (v) => { s.destroy(); res(v); };
    s.setTimeout(timeoutMs, () => done(false));
    s.once("connect", () => done(true));
    s.once("error", () => done(false));
  });
}

export async function hookdLive(port, { stateDir = STATE_DIR, timeoutMs = CONNECT_MS } = {}) {
  let pid = 0;
  try { pid = Number(readFileSync(hookdPidPath(port, stateDir), "utf8").trim()); } catch { return false; }
  return pidAlive(pid) && portListening(port, { timeoutMs });
}

// The loopback port an http handler's URL names, else 0.
export function loopbackPort(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" || u.hostname !== "127.0.0.1") return 0;
    return Number(u.port || 80);
  } catch { return 0; }
}

// An http entry covers its event when it cannot fail open: every handler has onFailure "block", or moorai-hookd
// is live on the port it names.
export async function httpEntryCovers(entry, { live = hookdLive } = {}) {
  for (const h of entry.hooks) {
    if (h.onFailure === "block") continue;
    const port = loopbackPort(h.url);
    if (!port || !(await live(port))) return false;
  }
  return true;
}
