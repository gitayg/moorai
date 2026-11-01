// The hand-off from the hook to the static model scanner. When a Bash command downloads model weights
// (data/model-download.js, detector model-download → #76, report-only), the PreToolUse hook appends the
// download's target to a local queue and returns: nothing is scanned on the hook path. A later hook
// event (any one) sees the queue is due and spawns the detached `moorai-hook.mjs modelscan` worker, and
// the daily posture worker drains whatever is left (cli/model-scan-posture.mjs).
//
// The queue is local state (~/.moorai/model-scan-queue.json, mode 0600): it holds the target paths the
// worker must scan, which never leave the device. Bounded to QUEUE_CAP entries; an entry older than
// QUEUE_TTL_MS is dropped unscanned.
import { readFileSync, writeFileSync, mkdirSync, renameSync, statSync } from "node:fs";
import { join, resolve, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { modelDownloads } from "../data/model-download.js";

export const QUEUE_FILE = "model-scan-queue.json";
export const QUEUE_CAP = 50;
export const QUEUE_TTL_MS = 24 * 3600 * 1000;
export const SETTLE_MS = 60 * 1000;          // a download target is scanned once nothing in it changed for this long
export const WORKER_RETRY_MS = 5 * 60 * 1000; // at most one modelscan worker spawn per this interval
const PENDING_FILE = "model-scan-worker.json";

// Ollama and Hugging Face store locations (the same rules as cli/local-ai-inventory.mjs modelStoreDirs).
export function storeDir(store, { home = homedir(), env = process.env, platform = process.platform } = {}) {
  if (store === "ollama") return env.OLLAMA_MODELS || join(home, ".ollama", "models");
  if (store === "hf-cache") return env.HF_HUB_CACHE || (env.HF_HOME ? join(env.HF_HOME, "hub") : join(home, ".cache", "huggingface", "hub"));
  return null;
}

const expandHome = (p, home) => (p === "~" ? home : p.startsWith("~/") ? join(home, p.slice(2)) : p);

// Absolute scan targets for one command. → [{ kind, path, isFile }]
export function downloadTargets(command, { cwd = process.cwd(), home = homedir(), env = process.env, platform = process.platform } = {}) {
  const out = [];
  for (const d of modelDownloads(command)) {
    let p = null, isFile = false;
    if (d.target.store) p = storeDir(d.target.store, { home, env, platform });
    else if (d.target.file) { p = expandHome(d.target.file, home); isFile = true; }
    else if (d.target.dir) p = expandHome(d.target.dir, home);
    if (!p) continue;
    out.push({ kind: d.kind, path: isAbsolute(p) ? p : resolve(cwd || process.cwd(), p), isFile });
  }
  return out;
}

export function readQueue(stateDir) {
  try { const o = JSON.parse(readFileSync(join(stateDir, QUEUE_FILE), "utf8")); return Array.isArray(o && o.items) ? o.items : []; } catch { return []; }
}
export function writeQueue(stateDir, items) {
  mkdirSync(stateDir, { recursive: true });
  const file = join(stateDir, QUEUE_FILE), tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ items: items.slice(-QUEUE_CAP) }), { mode: 0o600 });
  renameSync(tmp, file);
}

// Hook side: append this command's targets. Cheap (one small JSON file); never throws.
export function queueModelDownload(command, { cwd, stateDir = join(homedir(), ".moorai"), home = homedir(), env = process.env, platform = process.platform, now = Date.now() } = {}) {
  try {
    const targets = downloadTargets(command, { cwd, home, env, platform });
    if (!targets.length) return 0;
    const items = readQueue(stateDir).filter((x) => now - x.ts < QUEUE_TTL_MS);
    for (const t of targets) {
      const ex = items.find((x) => x.path === t.path);
      if (ex) ex.ts = now; else items.push({ ...t, ts: now });
    }
    writeQueue(stateDir, items);
    return targets.length;
  } catch { return 0; }
}

// Hook side, every event: should the detached worker be spawned now? True when the queue has an entry
// past SETTLE_MS and no spawn happened in the last WORKER_RETRY_MS. Costs one stat when the queue is
// absent. Writes the spawn stamp when it answers true.
export function modelScanDue({ stateDir = join(homedir(), ".moorai"), now = Date.now() } = {}) {
  try {
    statSync(join(stateDir, QUEUE_FILE));
  } catch { return false; }
  try {
    const items = readQueue(stateDir);
    if (!items.some((x) => now - x.ts >= SETTLE_MS)) return false;
    let last = 0;
    try { last = JSON.parse(readFileSync(join(stateDir, PENDING_FILE), "utf8")).ts || 0; } catch { last = 0; }
    if (now - last < WORKER_RETRY_MS) return false;
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(join(stateDir, PENDING_FILE), JSON.stringify({ ts: now }), { mode: 0o600 });
    return true;
  } catch { return false; }
}
