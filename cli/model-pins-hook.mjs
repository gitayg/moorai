// The provenance pin check on the PreToolUse path: a shell command that loads or serves a model file it
// names (cli/model-pins-targets.mjs) is checked against the approved sha256 list (cli/model-pins.mjs).
//
//   mode "report"  the command runs; each unapproved file is alerted on
//   mode "ask"     an unapproved or unverified file holds the command for the user's confirmation
//   mode "block"   an unapproved or unverified file denies the command
//
// The sha256: from the hash cache when the file's identity (path, inode, size, mtime, ctime) is unchanged
// since it was last hashed; otherwise hashed here while the command's files fit in HOOK_HASH_BUDGET_BYTES
// (2 GiB, about 1 s at the 1.9-2.0 GiB/s measured on the dev Mac). A file past the budget is "unverified":
// asked or denied by mode, never allowed silently, and queued for the background scan
// (cli/model-scan-posture.mjs), which hashes it and fills the cache, so the next attempt is decided from
// the cache. An Ollama blob's file name is the sha256 its manifest claims; it is compared with the file's
// own hash and never trusted alone: the store is user-writable and a blob replaced in place keeps its name.
//
// Content-free alert (threat #76, reasonCode MODEL_NOT_APPROVED): the load kind, the format, a size class,
// pinned false, verified, the first 12 hex of the sha256, the outcome. Never a path, a file name or a
// model name.
import { FileSource } from "./model-scan-bytes.mjs";
import { detectFormat, sha256File, findModelFiles, SCAN_LIMITS } from "./model-scan.mjs";
import { readQueue, writeQueue, QUEUE_TTL_MS } from "./model-scan-queue.mjs";
import { modelLoadTargets } from "./model-pins-targets.mjs";
import { resolveModelPins, fileIdentity, readPinCache, cachedSha, rememberHashes, sizeClass, hashPrefix, MODEL_NOT_APPROVED } from "./model-pins.mjs";

export const HOOK_HASH_BUDGET_BYTES = 2 * 1024 ** 3;
const DIR_LIMITS = { ...SCAN_LIMITS, maxFiles: 64, maxDepth: 4, maxEntries: 5000 };
const OUTCOME = { report: "reported", ask: "asked", block: "blocked" };
const DECISION = { report: "allow", ask: "ask", block: "deny" };
const RISK = { report: "Medium", ask: "High", block: "Blocked" };

function formatOf(path) {
  let src;
  try { src = new FileSource(path); return src.size ? detectFormat(path, src) : null; } catch { return null; } finally { if (src) try { src.close(); } catch { /* closed */ } }
}

// → null (pinning off, or the command loads no model it names), or
//   { decision: "allow" | "ask" | "deny", reason, files: [{ kind, approval }], alerts: [alert without ts/identity] }
export function modelPinCheck({ command, cwd, policy = null, admin = null, stateDir, home, env = process.env, platform = process.platform,
  budget = HOOK_HASH_BUDGET_BYTES, hash = sha256File, tool = "Bash", now = Date.now(), warn } = {}) {
  const cfg = resolveModelPins(policy, { admin, ...(warn ? { warn } : {}) });
  if (cfg.mode === "off") return null;
  const targets = modelLoadTargets(command, { cwd, ...(home ? { home } : {}), env, platform });
  if (!targets.length) return null;
  const files = [];
  for (const t of targets) {
    if (!t.path) { files.push({ kind: t.kind, path: null }); continue; }
    if (t.isFile) { files.push({ kind: t.kind, path: t.path, claimed: t.claimed }); continue; }
    const { files: found, truncated } = findModelFiles(t.path, { limits: DIR_LIMITS });
    // A directory with no model file this reader knows, or more than the walk reads, cannot be fully checked.
    if (!found.length || Object.values(truncated || {}).some(Boolean)) files.push({ kind: t.kind, path: null });
    for (const f of found) files.push({ kind: t.kind, path: f.path });
  }
  const cache = readPinCache(stateDir);
  const remember = [], unverified = [];
  let left = budget;
  for (const f of files) {
    f.ident = f.path ? fileIdentity(f.path) : null;
    if (!f.ident) { f.approval = "unverified"; continue; }
    let sha = cachedSha(stateDir, f.ident, cache);
    if (!sha && f.ident.size <= left) {
      left -= f.ident.size;
      try { sha = hash(f.path); remember.push({ before: f.ident, path: f.path, sha256: sha }); } catch { sha = null; }
    }
    f.sha = sha;
    if (!sha) { f.approval = "unverified"; unverified.push(f.path); continue; }
    if (f.claimed && f.claimed !== sha) f.mismatch = true;
    f.approval = !f.mismatch && cfg.pins.has(sha) ? "pinned" : "not-approved";
  }
  if (remember.length) rememberHashes(stateDir, remember);
  if (unverified.length) {
    try {
      const items = readQueue(stateDir).filter((x) => x && now - x.ts < QUEUE_TTL_MS && !unverified.includes(x.path));
      writeQueue(stateDir, [...items, ...unverified.map((path) => ({ kind: "pin-verify", path, isFile: true, ts: now }))]);
    } catch { /* the next load queues it again */ }
  }
  const bad = files.filter((f) => f.approval !== "pinned");
  const out = { decision: "allow", reason: "", files: files.map((f) => ({ kind: f.kind, approval: f.approval })), alerts: [] };
  if (!bad.length) return out;
  out.decision = DECISION[cfg.mode];
  out.reason = bad.some((f) => f.approval === "not-approved")
    ? "model file not on the approved list (provenance pin)"
    : "model file could not be checked against the approved list in time (provenance pin)";
  for (const f of bad.slice(0, 10)) {
    const prefix = hashPrefix(f.sha);
    out.alerts.push({
      threatId: 76, reasonCode: MODEL_NOT_APPROVED, category: "Model file not approved", riskLevel: RISK[cfg.mode], stage: "load", tool: `hook:${tool}`,
      decision: out.decision, contentHash: `model-pin:${prefix || "unverified"}:${f.kind}`,
      modelLoad: { kind: f.kind, format: f.path ? formatOf(f.path) : null, sizeClass: f.ident ? sizeClass(f.ident.size) : null, pinned: false, verified: !!f.sha,
        ...(f.mismatch ? { nameMismatch: true } : {}), hashPrefix: prefix, outcome: OUTCOME[cfg.mode], mode: cfg.mode, source: cfg.source }
    });
  }
  return out;
}
