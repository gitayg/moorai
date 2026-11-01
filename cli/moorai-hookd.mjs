#!/usr/bin/env node
// moorai-hookd — Claude Code's HTTP hook transport for MoorAI. Claude Code POSTs each hook event here instead of
// starting `node cli/moorai-hook.mjs`; a pre-warmed hook worker runs that same hook on the event and its output
// becomes the answer (cli/hook-http.mjs, cli/hook-warm-pool.mjs). Same decisions, reasons, alerts and state
// files as the command hook, without paying Node start-up and module loading on every tool call.
//
//   POST /v1/hook/claude-code   the event JSON (Claude Code's own request) -> the hook's JSON output, or empty
//   GET  /healthz               -> { status, version, transport: "http", workers: { waiting, alive } }
//
// A separate process from moorai-serve: moorai-serve is the Agent SDK runtime in one process (server-mode
// semantics, its own principals and console reporter) for agent loops that are not Claude Code; this daemon runs
// the user's own command hook, as the user, with the user's configuration, and holds no engine of its own.
//
// EXPOSURE. Loopback only: a non-loopback --host is refused. Every POST needs the per-device bearer token
// (~/.moorai/hookd.token, 0600, created on first start; `moorai-hook install --hook-transport http` writes it
// into the hook entries). A Host header that is not a loopback name is refused (421), as in moorai-serve, and the
// body must be application/json. Request bodies are never logged and never written to disk by the daemon.
//
//   moorai-hookd [--port 8793] [--token-file <path>] [--workers 2] [--max-workers 8] [--max-age-ms 30000]
//                [--timeout-ms 30000] [--max-body 33554432] [--log]
//   moorai-hookd unit [--out <dir>] [--port 8793]   write the launchd agent (macOS) / systemd --user unit (Linux)
//                                                   into <dir> (default: print it) and print how to install it
import http from "node:http";
import { readFileSync, writeFileSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { timingSafeEqual, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { isLoopback, hostHeaderOk, readJson, HttpError } from "./moorai-serve.mjs";
import { createPool, PoolBusy, WorkerTimeout } from "./hook-warm-pool.mjs";
import { HOOK_PATH, workerHeader, mapHookResult } from "./hook-http.mjs";
import { hookdToken, tokenPath, HOOKD_DEFAULT_PORT } from "./hook-transport.mjs";
import { peerOf } from "./quarantine-owner.mjs";
import { unitFor } from "./hookd-unit.mjs";
import { writeHookdPid, removeHookdPid, pidAlive } from "./hookd-live.mjs";
import { STATE_DIR } from "./state-dirs.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SELF = fileURLToPath(import.meta.url);
export const HOOKD_DEFAULTS = Object.freeze({ host: "127.0.0.1", port: HOOKD_DEFAULT_PORT, workers: 2, maxWorkers: 8, maxAgeMs: 30000, timeoutMs: 30000, maxBody: 32 * 1048576 });
const PEER_CACHE = 1024;

export function parseArgs(argv) {
  const o = { ...HOOKD_DEFAULTS, log: false, tokenFile: "" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], v = () => { const x = argv[++i]; if (x === undefined) throw new Error(`${a} needs a value`); return x; };
    if (a === "--host") o.host = v();
    else if (a === "--port") o.port = Number(v());
    else if (a === "--token-file") o.tokenFile = resolve(v());
    else if (a === "--workers") o.workers = Number(v());
    else if (a === "--max-workers") o.maxWorkers = Number(v());
    else if (a === "--max-age-ms") o.maxAgeMs = Number(v());
    else if (a === "--timeout-ms") o.timeoutMs = Number(v());
    else if (a === "--max-body") o.maxBody = Number(v());
    else if (a === "--log") o.log = true;
    else throw new Error(`unknown argument ${a}`);
  }
  if (!isLoopback(o.host)) throw new Error(`refusing to listen on ${o.host}: moorai-hookd listens on loopback only`);
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) throw new Error("--port must be 0-65535");
  if (!Number.isInteger(o.workers) || o.workers < 0 || o.workers > 64) throw new Error("--workers must be 0-64");
  if (!Number.isInteger(o.maxWorkers) || o.maxWorkers < Math.max(1, o.workers) || o.maxWorkers > 256) throw new Error("--max-workers must be at least --workers (and 1), at most 256");
  if (!Number.isInteger(o.maxAgeMs) || o.maxAgeMs < 1000) throw new Error("--max-age-ms must be an integer >= 1000");
  if (!Number.isInteger(o.timeoutMs) || o.timeoutMs < 1000) throw new Error("--timeout-ms must be an integer >= 1000");
  if (!Number.isInteger(o.maxBody) || o.maxBody < 1024) throw new Error("--max-body must be an integer >= 1024");
  return o;
}

// The token file: the given path, else ~/.moorai/hookd.token (created 0600 on first start). A file that group or
// others can read is refused: anyone holding the token can have hooks run as this user.
export function loadToken(tokenFile) {
  if (!tokenFile) return hookdToken();
  const st = statSync(tokenFile);
  if (st.mode & 0o077) throw new Error(`${tokenFile} is readable by others: chmod 600 it`);
  const t = readFileSync(tokenFile, "utf8").trim();
  if (!/^[A-Za-z0-9._~+/=-]{16,256}$/.test(t)) throw new Error(`${tokenFile} does not hold a token (16-256 characters of A-Z a-z 0-9 . _ ~ + / = -)`);
  return t;
}

const digest = (s) => createHash("sha256").update(String(s)).digest();
function authorized(req, want) {
  const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
  return !!m && timingSafeEqual(digest(m[1].trim()), want);
}

// The agent process on the other end of a request's connection (cli/quarantine-owner.mjs peerOf: on macOS two of
// netstat, lsof and nettop must agree, ~100 ms; Linux reads /proc). Asked once per session and per connection:
// the hook starts its parent-process walk there (cli/ai-cli-parents.mjs) and, in server mode, names it on alerts.
// A pid remembered for a session is reused only while that process is alive; otherwise it is read again.
export function peerResolver({ lookup = peerOf, alive = pidAlive } = {}) {
  const bySession = new Map();
  const bySocket = new WeakMap();
  return (req, event, serverPort) => {
    const sid = typeof event.session_id === "string" ? event.session_id : "";
    if (sid && bySession.has(sid) && alive(bySession.get(sid))) return bySession.get(sid);
    let pid = bySocket.get(req.socket);
    if (pid === undefined) {
      try { pid = lookup(req.socket.remotePort, serverPort).pid || 0; } catch { pid = 0; }
      bySocket.set(req.socket, pid);
    }
    if (sid) {
      bySession.set(sid, pid);
      if (bySession.size > PEER_CACHE) bySession.delete(bySession.keys().next().value);
    }
    return pid;
  };
}

export async function createHookd(opts = {}) {
  const o = { ...HOOKD_DEFAULTS, ...opts };
  const token = o.token || loadToken(o.tokenFile || "");
  const want = digest(token);
  const version = (() => { try { return JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version; } catch { return "unknown"; } })();
  const pool = o.pool || createPool({ size: o.workers, max: o.maxWorkers, maxAgeMs: o.maxAgeMs, timeoutMs: o.timeoutMs, env: o.env, execPath: o.execPath });
  const peer = peerResolver({ lookup: o.peerLookup });
  let serverPort = 0;
  const log = (req, status, t0, ev) => { if (o.log) process.stderr.write(`${new Date().toISOString()} ${req.method} ${req.url.split("?")[0]} ${ev || "-"} ${status} ${(performance.now() - t0).toFixed(1)}ms\n`); };

  async function route(req) {
    const path = req.url.split("?")[0];
    if (path === "/healthz") {
      if (req.method !== "GET") throw new HttpError(405, "use GET");
      return { status: 200, json: { status: "ok", version, transport: "http", workers: { waiting: pool.waiting, alive: pool.alive } } };
    }
    if (path !== HOOK_PATH) throw new HttpError(404, "not found");
    if (req.method !== "POST") throw new HttpError(405, "use POST");
    if (!authorized(req, want)) throw new HttpError(401, "missing or wrong bearer token");
    const { value: event, raw } = await readJson(req, o.maxBody, { raw: true });
    if (!event || typeof event !== "object" || Array.isArray(event)) throw new HttpError(400, "body must be a JSON object");
    const header = workerHeader(event, req.headers, peer(req, event, serverPort));
    let r;
    try { r = await pool.run(raw, header); } catch (e) {
      if (e instanceof PoolBusy) throw new HttpError(503, e.message);
      if (e instanceof WorkerTimeout) throw new HttpError(504, e.message);
      throw e;
    }
    const m = mapHookResult(event, r);
    return { status: m.status, text: m.body, ev: typeof event.hook_event_name === "string" ? event.hook_event_name.slice(0, 32) : "" };
  }

  const server = http.createServer(async (req, res) => {
    const t0 = performance.now();
    let status = 200, body = "", ev = "";
    try {
      if (!hostHeaderOk(req.headers.host)) throw new HttpError(421, "Host header is not a loopback name");
      const r = await route(req);
      status = r.status; ev = r.ev;
      body = r.json ? JSON.stringify(r.json) : r.text || "";
    } catch (e) {
      status = e instanceof HttpError ? e.status : 500;
      body = JSON.stringify({ error: e instanceof HttpError ? e.message : "internal error" });
    }
    const headers = { "cache-control": "no-store", "x-content-type-options": "nosniff", "content-length": Buffer.byteLength(body) };
    if (body) headers["content-type"] = status >= 200 && status < 300 ? "application/json" : "application/json; charset=utf-8";
    res.writeHead(status, headers);
    res.end(body);
    log(req, status, t0, ev);
  });
  server.headersTimeout = 5000;
  server.requestTimeout = o.timeoutMs + 5000;
  server.keepAliveTimeout = 5000;
  server.maxConnections = 256;
  await new Promise((res, rej) => { server.once("error", rej); server.listen(o.port, o.host, () => { server.off("error", rej); res(); }); });
  serverPort = server.address().port;
  const url = `http://${o.host}:${serverPort}`;
  const close = async () => { await pool.close(); await new Promise((r) => server.close(() => r())); server.closeAllConnections?.(); };
  return { server, url, pool, close };
}

function unitCommand(argv) {
  let out = "", port = HOOKD_DEFAULT_PORT;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") out = resolve(argv[++i] || "");
    else if (argv[i] === "--port") port = Number(argv[++i]);
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("--port must be 1-65535");
  const u = unitFor({ node: process.execPath, script: realpathSync(SELF), args: ["--port", String(port)], outDir: out || ".", logFile: join(STATE_DIR, "hookd.log") });
  if (!u) throw new Error("no service file for this platform: keep the command transport (moorai-hook install)");
  hookdToken();
  if (!out) { process.stdout.write(u.text); process.stderr.write(`# save as ${u.file}, then: ${u.install.join(" && ")}\n`); return; }
  mkdirSync(out, { recursive: true });
  writeFileSync(u.file, u.text, { mode: 0o644 });
  process.stdout.write(`${JSON.stringify({ file: u.file, install: u.install, uninstall: u.uninstall, token: tokenPath() })}\n`);
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "unit") {
    try { unitCommand(argv.slice(1)); } catch (e) { process.stderr.write(`moorai-hookd: ${e.message}\n`); process.exit(2); }
    return;
  }
  let o, s;
  try { o = parseArgs(argv); s = await createHookd(o); } catch (e) { process.stderr.write(`moorai-hookd: ${e.message}\n`); process.exit(2); }
  await s.pool.ready();
  const port = Number(new URL(s.url).port);
  try { writeHookdPid(port); } catch { /* without it the plugin copy keeps enforcing */ }
  process.stdout.write(`${JSON.stringify({ listening: s.url, path: HOOK_PATH, workers: o.workers })}\n`);
  const stop = async () => { removeHookdPid(port); await s.close(); process.exit(0); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
const invoked = (() => { try { return realpathSync(process.argv[1]) === realpathSync(SELF); } catch { return false; } })();
if (invoked) main();
