#!/usr/bin/env node
// A pre-warmed Claude Code hook process for moorai-hookd (cli/hook-warm-pool.mjs). It loads every module the
// hook imports (the slow part of a hook run: module loading, compiling and the engine's pattern tables) and
// then waits. For one request it is told, on fd 3, the working directory and the few environment values
// Claude Code would have given a command hook, applies them, and only then imports cli/moorai-hook.mjs, whose
// main() reads the event from stdin exactly as a command hook does. So the hook's own module-level reads
// (CONFIG, the admin binding, server mode, identity, honeytokens) happen per request, never ahead of it, and
// stdout, stderr and the exit code are the command hook's own. One request per process: it exits after it.
//
// Measured (notes, v1.45.0): the hook's dependencies read no file at import time, only environment values
// (XDG_CONFIG_HOME, XDG_STATE_HOME, MOORAI_RETENTION_DAYS, MOORAI_SCAN_MAX_*, MOORAI_PROVIDER_MODEL,
// MOORAI_LOCAL_MODEL, MOORAI_LOCAL_TIMEOUT_MS) and the home directory, which are moorai-hookd's own for its
// whole life. The pool still retires a waiting worker after a bounded age and when the code on disk changes.
//
// fd 3 protocol (newline-delimited JSON): worker -> pool {"ready":true} once warm; pool -> worker one header
// { cwd, env: { NAME: value }, peerPid }.
import net from "node:net";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join, resolve } from "node:path";
import { setHookPeerPid } from "./hook-peer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = join(HERE, "moorai-hook.mjs");

// Every relative module the hook names, static or dynamic, read from its source so the list cannot drift.
export function hookImports(src) {
  return [...new Set([...String(src).matchAll(/(?:\bfrom|\bimport\()\s*"(\.{1,2}\/[^"]+\.m?js)"/g)].map((m) => m[1]))];
}

// The header values a worker applies. cwd: an existing directory (the pool resolved it); env: string values
// for the names the pool forwards (cli/hook-http.mjs FORWARDED_ENV); an empty value unsets the name.
export function applyHeader(h) {
  if (h && h.env && typeof h.env === "object") {
    for (const [k, v] of Object.entries(h.env)) {
      if (typeof v !== "string") continue;
      if (v) process.env[k] = v; else delete process.env[k];
    }
  }
  if (h && typeof h.cwd === "string" && h.cwd) process.chdir(h.cwd);
  setHookPeerPid(h ? h.peerPid : 0);
}

const WARM_TEXTS = ["warm up the MoorAI hook worker", "ls -la src && git status", "cat ./notes/readme.txt", "https://example.com/docs?q=1"];
async function warm() {
  const src = readFileSync(HOOK, "utf8");
  // A module that fails to load here fails the same way inside the hook, where its own error handling runs.
  await Promise.all(hookImports(src).map((s) => import(pathToFileURL(resolve(HERE, s)).href).catch(() => {})));
  // V8 compiles a regular expression the first time it runs, so one scan of a neutral text per stage compiles
  // every built-in detector pattern here instead of inside the request. The engine is pure: nothing is
  // written, posted or kept but the compiled patterns.
  try {
    const { buildEngine } = await import("./hook-core.mjs");
    const engine = buildEngine(null);
    const stages = new Set(engine.detectors.flatMap((d) => d.stages || [d.stage]).filter((s) => typeof s === "string"));
    // Three passes: V8 runs a new pattern in its interpreter first and compiles it to machine code on a later run.
    for (let i = 0; i < 3; i++) for (const t of WARM_TEXTS) for (const s of stages) engine.scan(t, s);
  } catch { /* warm-up only */ }
}

function readHeader(ctl) {
  return new Promise((res, rej) => {
    let buf = "";
    const onData = (c) => {
      buf += c;
      const nl = buf.indexOf("\n");
      if (nl < 0) { if (buf.length > 65536) rej(new Error("header too long")); return; }
      ctl.off("data", onData);
      try { res(JSON.parse(buf.slice(0, nl))); } catch (e) { rej(e); }
    };
    ctl.setEncoding("utf8");
    ctl.on("data", onData);
    ctl.once("end", () => rej(new Error("pool closed")));
    ctl.once("error", rej);
  });
}

async function main() {
  const ctl = new net.Socket({ fd: 3, readable: true, writable: true });
  await warm();
  ctl.write('{"ready":true}\n');
  let header;
  try { header = await readHeader(ctl); } catch { process.exit(0); }
  ctl.destroy();
  applyHeader(header);
  await import(pathToFileURL(HOOK).href);
}

const invoked = (() => { try { return resolve(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })();
if (invoked) main();
