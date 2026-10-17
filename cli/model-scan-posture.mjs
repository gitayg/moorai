// The static model scan off the hook path: run by the daily posture worker (cli/agent-posture.mjs
// inventoryPosture) and by the detached `moorai-hook.mjs modelscan` worker a download hands off to.
// Never on PreToolUse.
//
// Signed policy:
//   "modelScan": {
//     "inventory":   "off" | "scan"   default "off"   scan the local model stores (Ollama, LM Studio, the
//                                                     Hugging Face hub cache: cli/local-ai-inventory.mjs
//                                                     modelStoreDirs) on the daily posture run
//     "downloads":   "scan" | "off"   default "scan"  scan what a model download the hook saw fetched
//     "allowHashes": ["<sha256>", …]                  known-good files: verdict "allowed", not inspected
//     "maxGiBPerRun": number           default 32     bytes hashed and parsed per run; the rest waits for
//                                                     the next run (a file already scanned and unchanged
//                                                     costs nothing: its verdict is remembered)
//   }
//
// What leaves the device. Heartbeat field `modelFiles`: counts only (scanned, unsafe, suspicious,
// clean, allowed, unscanned, pending, by format, by finding class at medium or above). Alerts, once per
// file content: threat #76, reasonCode MODEL_FILE_UNSAFE / MODEL_FILE_SUSPICIOUS, the format, verdict,
// severity, finding classes and the file's sha256. Never a path, a file name, a model name or any
// detail text. Local state (~/.moorai/model-scan-state.json, 0600) keys remembered verdicts by a hash of
// path, size and mtime, so no path is stored there either.
import { readFileSync, writeFileSync, mkdirSync, renameSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { modelStoreDirs } from "./local-ai-inventory.mjs";
import { findModelFiles, scanModelFile, verdictCounts, SCAN_LIMITS, SEVERITY_RANK } from "./model-scan.mjs";
import { readQueue, writeQueue, QUEUE_FILE, QUEUE_TTL_MS, SETTLE_MS } from "./model-scan-queue.mjs";

export const MODEL_SCAN_STATE = "model-scan-state.json";
export const MODEL_FILE_REASON = { unsafe: "MODEL_FILE_UNSAFE", suspicious: "MODEL_FILE_SUSPICIOUS" };
const CATEGORY = { unsafe: "Unsafe model file", suspicious: "Suspicious model file" };
const RISK = { critical: "Critical", high: "High", medium: "Medium" };
const STATE_CAP = 20_000;
const MISSING_GRACE_MS = 6 * 3600 * 1000;
const SHA = /^[0-9a-f]{64}$/;

export function modelScanPolicy(policy) {
  const m = policy && typeof policy.modelScan === "object" && policy.modelScan ? policy.modelScan : {};
  const gib = Number.isFinite(m.maxGiBPerRun) && m.maxGiBPerRun > 0 ? Math.min(m.maxGiBPerRun, 4096) : 32;
  return {
    inventory: m.inventory === "scan" ? "scan" : "off",
    downloads: m.downloads === "off" ? "off" : "scan",
    allowHashes: new Set((Array.isArray(m.allowHashes) ? m.allowHashes : []).map((h) => String(h).toLowerCase()).filter((h) => SHA.test(h))),
    maxBytesPerRun: gib * 1024 ** 3
  };
}

const fileKey = (p, st) => createHash("sha256").update(`${p}\0${st.size}\0${st.mtimeMs}`).digest("hex").slice(0, 32);
const classesOf = (r) => [...new Set((r.findings || []).filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.medium).map((f) => f.class))].sort();

function readState(stateDir) {
  try { const o = JSON.parse(readFileSync(join(stateDir, MODEL_SCAN_STATE), "utf8")); return { files: o.files && typeof o.files === "object" ? o.files : {}, alerted: Array.isArray(o.alerted) ? o.alerted : [] }; } catch { return { files: {}, alerted: [] }; }
}

// Newest mtime among files modified at or after `since` under dir (bounded), and whether a partial
// download is present (*.incomplete — Hugging Face; *-partial* — Ollama; *.part, *.download — curl/wget/browsers).
export function downloadActivity(dir, since, { maxEntries = 50_000, maxDepth = 8 } = {}) {
  let newest = 0, partial = false, entries = 0;
  const walk = (d, depth) => {
    if (depth > maxDepth || entries > maxEntries) return;
    let list;
    try { list = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of list) {
      if (++entries > maxEntries) return;
      const p = join(d, e.name);
      if (e.isDirectory()) { walk(p, depth + 1); continue; }
      let st;
      try { st = statSync(p); } catch { continue; }
      if (st.mtimeMs < since) continue;
      newest = Math.max(newest, st.mtimeMs);
      if (/\.incomplete$|-partial(?:-\d+)?$|\.part$|\.download$|\.crdownload$/i.test(e.name)) partial = true;
    }
  };
  let st;
  try { st = statSync(dir); } catch { return { exists: false, newest: 0, partial: false }; }
  if (st.isFile()) return { exists: true, newest: st.mtimeMs, partial: false };
  walk(dir, 0);
  return { exists: true, newest, partial };
}

// → { field, alerts, notes, commit(failed) }, or null when nothing was due (inventory off and no queued
// download). write false: read-only (moorai doctor) — nothing is scanned, the queue is not touched.
export function modelScanPosture({ policy = null, home = homedir(), env = process.env, platform = process.platform, stateDir = join(home, ".moorai"),
  write = true, now = Date.now(), ts = new Date(now).toISOString(), limits = SCAN_LIMITS, stores = null, scan = scanModelFile } = {}) {
  if (!write) return null;
  const pol = modelScanPolicy(policy);
  const queue = pol.downloads === "scan" ? readQueue(stateDir) : [];
  if (pol.inventory === "off" && !queue.length) return null;
  const state = readState(stateDir);
  const nextFiles = {};
  const records = [];
  let budget = pol.maxBytesPerRun, pending = 0;
  const one = (path, size, source) => {
    let st;
    try { st = statSync(path); } catch { return; }
    const key = fileKey(path, st);
    const prev = state.files[key];
    if (prev && prev.v) { nextFiles[key] = prev; records.push({ format: prev.f, verdict: prev.v, severity: prev.sev || null, sha256: prev.s || null, findings: (prev.c || []).map((c) => ({ class: c, severity: "medium" })), source, cached: true }); return; }
    if (Math.min(size, limits.maxFileBytes) > budget) { pending++; return; }
    budget -= Math.min(size, limits.maxFileBytes);
    const r = scan(path, { allowHashes: pol.allowHashes, limits });
    r.source = source;
    records.push(r);
    nextFiles[key] = { v: r.verdict, f: r.format, s: r.sha256, sev: r.severity, c: classesOf(r) };
  };

  // 1. Downloads the hook queued.
  const keep = [];
  let downloadsScanned = 0;
  for (const item of queue) {
    if (!item || typeof item.path !== "string" || now - item.ts >= QUEUE_TTL_MS) continue;
    const since = item.ts - 5 * 60 * 1000;
    const act = downloadActivity(item.path, since);
    if (!act.exists) { if (now - item.ts < MISSING_GRACE_MS) keep.push(item); continue; }
    if (now - act.newest < SETTLE_MS || (act.partial && now - item.ts < MISSING_GRACE_MS)) { keep.push(item); continue; }
    const before = pending;
    const { files } = findModelFiles(item.path, { limits, since: item.isFile ? 0 : since });
    for (const f of files) one(f.path, f.size, "download");
    downloadsScanned++;
    if (pending > before) keep.push(item); // over budget: the rest is scanned next run
  }

  // 2. The model stores (opt-in).
  let storeCount = 0;
  if (pol.inventory === "scan") {
    const dirs = stores ?? modelStoreDirs({ home, env, platform });
    storeCount = dirs.length;
    for (const { dir } of dirs) {
      const { files } = findModelFiles(dir, { limits });
      for (const f of files) one(f.path, f.size, "inventory");
    }
  }

  const counts = verdictCounts(records);
  const field = { inventory: pol.inventory, downloads: pol.downloads, stores: storeCount, ...counts, pending, pendingDownloads: keep.length };

  // Alerts: once per file content (sha256), unsafe and suspicious only.
  const alerted = new Set(state.alerted);
  const alerts = [];
  for (const r of records) {
    if (r.verdict !== "unsafe" && r.verdict !== "suspicious") continue;
    const id = r.sha256 || null;
    if (!id || alerted.has(id) || alerts.some((a) => a.modelFile.sha256 === id)) continue;
    alerts.push({
      threatId: 76, reasonCode: MODEL_FILE_REASON[r.verdict], category: CATEGORY[r.verdict], riskLevel: RISK[r.severity] || "Medium",
      stage: "inventory", tool: r.source === "download" ? "download:model-scan" : "inventory:model-scan", ts,
      contentHash: `model-file:${id}`, modelFile: { format: r.format, verdict: r.verdict, severity: r.severity, classes: classesOf(r), sha256: id }
    });
  }

  const commit = (failed = []) => {
    const lost = new Set((Array.isArray(failed) ? failed : []).map((a) => a && a.modelFile && a.modelFile.sha256));
    const nextAlerted = [...new Set([...state.alerted, ...alerts.map((a) => a.modelFile.sha256)])].filter((h) => !lost.has(h)).slice(-STATE_CAP);
    // Downloads remembered from earlier runs stay remembered until the cap, so a store scan does not forget them.
    const files = pol.inventory === "scan" ? { ...nextFiles } : { ...state.files, ...nextFiles };
    const keys = Object.keys(files);
    if (keys.length > STATE_CAP) for (const k of keys.slice(0, keys.length - STATE_CAP)) delete files[k];
    try {
      mkdirSync(stateDir, { recursive: true });
      const file = join(stateDir, MODEL_SCAN_STATE), tmp = `${file}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify({ files, alerted: nextAlerted }), { mode: 0o600 });
      renameSync(tmp, file);
      // Re-read: the hook may have queued another download while this run scanned. Only the entries this
      // run finished (or dropped) leave the queue.
      if (queue.length) {
        const kept = new Set(keep.map((x) => `${x.path}|${x.ts}`));
        const done = new Set(queue.map((x) => `${x && x.path}|${x && x.ts}`).filter((k) => !kept.has(k)));
        writeQueue(stateDir, readQueue(stateDir).filter((x) => !done.has(`${x.path}|${x.ts}`)));
      }
    } catch { /* a lost state file costs one rescan and one repeated alert */ }
  };
  return { field, alerts, notes: { downloadsScanned, queueFile: QUEUE_FILE }, commit };
}
