// The pool of pre-warmed hook workers behind moorai-hookd (cli/hook-warm-worker.mjs). Each worker serves one
// request and exits; a replacement is started in the background as soon as one is taken.
//   size        workers kept warm and waiting (default 2), so parallel tool calls each find one
//   max         workers alive at once, waiting and running (default 8); past it a request queues
//   maxQueue    requests waiting for a worker (default 64); past it run() rejects (busy)
//   maxAgeMs    a waiting worker older than this is retired unused (default 30000), and so is every waiting
//               worker when the hook's code on disk changes (its file or package.json), so a request never
//               runs on modules loaded from an older install
//   timeoutMs   a request whose worker has not exited by then is killed and rejected (default 30000)
// run() resolves { code, signal, stdout, stderr, warm, ms } with the worker's exit code and its raw output.
import { spawn } from "node:child_process";
import { statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import os from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
export const WORKER = join(HERE, "hook-warm-worker.mjs");
export const POOL_DEFAULTS = Object.freeze({ size: 2, max: 8, maxQueue: 64, maxAgeMs: 30000, timeoutMs: 30000, maxOutput: 4 * 1048576 });

export class PoolBusy extends Error {}
export class WorkerTimeout extends Error {}

function codeStamp(files) {
  return files.map((f) => { try { const s = statSync(f); return `${s.mtimeMs}:${s.size}:${s.ino}`; } catch { return "-"; } }).join("|");
}

export function createPool(opts = {}) {
  const o = { ...POOL_DEFAULTS, ...opts };
  const env = o.env || process.env;
  const watched = o.watch || [join(HERE, "moorai-hook.mjs"), join(HERE, "..", "package.json")];
  const waiting = []; // { child, ready, born, stamp }
  const queue = [];
  let alive = 0, closed = false, stamp = codeStamp(watched);
  const stats = { spawned: 0, served: 0, warm: 0, cold: 0, retired: 0, timeouts: 0 };

  function spawnWorker() {
    alive++;
    stats.spawned++;
    const child = spawn(o.execPath || process.execPath, [WORKER], { cwd: os.homedir(), env, stdio: ["pipe", "pipe", "pipe", "pipe"] });
    const w = { child, ready: false, born: Date.now(), stamp, readyP: null, exited: false };
    w.readyP = new Promise((res) => {
      let buf = "";
      child.stdio[3].setEncoding("utf8");
      const onData = (c) => { buf += c; if (buf.includes("\n")) { child.stdio[3].off("data", onData); w.ready = true; res(true); } };
      child.stdio[3].on("data", onData);
      child.once("exit", () => res(false));
    });
    child.once("exit", () => { w.exited = true; alive--; const i = waiting.indexOf(w); if (i >= 0) waiting.splice(i, 1); pump(); });
    child.on("error", () => {});
    for (const s of child.stdio) if (s) s.on("error", () => {});
    return w;
  }

  function retire(w) {
    stats.retired++;
    try { w.child.stdio[3].end(); } catch { /* exiting */ }
    try { w.child.kill("SIGKILL"); } catch { /* gone */ }
  }

  // Drop waiting workers that are too old or from older code, then top the pool up to size.
  function refill() {
    if (closed) return;
    const now = Date.now();
    const cur = codeStamp(watched);
    if (cur !== stamp) stamp = cur;
    for (const w of [...waiting]) if (w.stamp !== stamp || now - w.born > o.maxAgeMs || w.exited) { waiting.splice(waiting.indexOf(w), 1); retire(w); }
    while (waiting.length < o.size && alive < o.max) waiting.push(spawnWorker());
  }

  function take() {
    refill();
    // A ready worker first, else the oldest one still warming (it is closest to ready), else a new one.
    let i = waiting.findIndex((w) => w.ready);
    if (i < 0 && waiting.length) i = 0;
    if (i >= 0) { const w = waiting.splice(i, 1)[0]; return w; }
    if (alive < o.max) return spawnWorker();
    return null;
  }

  function pump() {
    while (queue.length && !closed) {
      const w = take();
      if (!w) break;
      const job = queue.shift();
      serve(w, job);
    }
    if (!closed) setImmediate(refill);
  }

  function serve(w, job) {
    const t0 = performance.now();
    const warm = w.ready;
    stats[warm ? "warm" : "cold"]++;
    const { child } = w;
    const out = [], err = [];
    let outN = 0, errN = 0, done = false;
    child.stdout.on("data", (c) => { if (outN < o.maxOutput) out.push(c); outN += c.length; });
    child.stderr.on("data", (c) => { if (errN < o.maxOutput) err.push(c); errN += c.length; });
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      stats.timeouts++;
      try { child.kill("SIGKILL"); } catch { /* gone */ }
      job.rej(new WorkerTimeout(`hook worker exceeded ${o.timeoutMs} ms`));
    }, o.timeoutMs);
    // close, not exit: every byte of stdout and stderr has been read by then.
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (done) return;
      done = true;
      stats.served++;
      job.res({ code, signal, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), warm, ms: performance.now() - t0 });
    });
    try { child.stdio[3].write(JSON.stringify(job.header) + "\n"); } catch { /* the close handler answers */ }
    child.stdin.end(job.input);
    setImmediate(refill);
  }

  function run(input, header = {}) {
    if (closed) return Promise.reject(new PoolBusy("pool closed"));
    return new Promise((res, rej) => {
      const job = { input, header, res, rej };
      const w = queue.length ? null : take();
      if (w) return serve(w, job);
      if (queue.length >= o.maxQueue) return rej(new PoolBusy("too many hook requests waiting"));
      queue.push(job);
    });
  }

  const sweep = setInterval(refill, Math.max(1000, Math.min(o.maxAgeMs, 10000)));
  sweep.unref();

  async function close() {
    closed = true;
    clearInterval(sweep);
    for (const j of queue.splice(0)) j.rej(new PoolBusy("pool closed"));
    const ws = waiting.splice(0);
    for (const w of ws) retire(w);
  }

  // Resolves once `size` workers are warm (start-up, tests, the benchmark).
  async function ready() {
    refill();
    await Promise.all(waiting.map((w) => w.readyP));
  }

  refill();
  return { run, close, ready, stats, get waiting() { return waiting.length; }, get alive() { return alive; } };
}
