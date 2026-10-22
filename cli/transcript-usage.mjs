// F15 endpoint source: Claude Code's own transcripts. Claude Code writes each session to
// <config dir>/projects/<encoded cwd>/<session>.jsonl (sub-agents under <session>/subagents/), and each
// assistant line carries the API's usage object (message.usage: input_tokens, output_tokens,
// cache_read_input_tokens, cache_creation_input_tokens), the model (message.model), the message id, a
// timestamp and the session cwd. MEASURED on this repo's own machine (2026-10-21): one line per content
// block, every line of one message repeating the same usage (291 repeats, 0 that differed), so a message
// is counted once, by id. Transcripts reach hundreds of MB (eight over 100 MB, one past 512 MB), so they
// are read incrementally from a saved offset, in 1 MiB chunks, within a byte budget per run.
//
// What leaves the device is cli/token-usage.mjs's bucket, source "transcript", instance TRANSCRIPT_INSTANCE
// (fixed per transcript host): hour, "claude-code", "anthropic", the model id, the keyed hash of the cwd
// (cli/content-hash.mjs), counters. The transcript text is parsed line by line in memory and only the usage
// fields are kept. The local state (~/.moorai/token-usage-transcript.json, 0600) keys files by a digest of
// their path and holds offsets, the last message ids per file and the buckets.
//
// Runs in a detached hook worker (scheduleTranscriptUsage, at most once an hour, enrolled devices, Claude
// Code's own hook only). Codex and other hosts' transcripts are not read: their usage records are not
// verified. "<synthetic>" messages (written by Claude Code itself, not returned by the API) are skipped.
import { readdirSync, statSync, openSync, readSync, closeSync, readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { contentHash } from "./content-hash.mjs";
import { normalizeUsage, hourStart, cleanModel, createBuckets, flushBuckets } from "./token-usage.mjs";

export const TRANSCRIPT_STATE = "token-usage-transcript.json";
export const TRANSCRIPT_STAMP = "token-usage-transcript.stamp";
export const TRANSCRIPT_INSTANCE = `tr-${createHash("sha256").update("claude-code").digest("hex").slice(0, 8)}`;
export const TRANSCRIPT_INTERVAL_MS = 3600_000;
const CHUNK = 1024 * 1024;
const MAX_LINE = 16 * 1024 * 1024;
const MAX_AGE_MS = 35 * 86400_000;           // a file untouched this long is not read (covers a calendar month)
const MAX_FILES = 2000;
const MAX_DEPTH = 4;
const KEEP_IDS = 64;
const PAUSE_MS = 24 * 3600_000;
const BUCKET_KEEP_MS = 40 * 86400_000;
const digest = (s) => createHash("sha256").update(s).digest("hex").slice(0, 24);

function projectsDirs(home, env) {
  const dirs = [join(home, ".claude", "projects")];
  const c = env && typeof env.CLAUDE_CONFIG_DIR === "string" && env.CLAUDE_CONFIG_DIR ? join(env.CLAUDE_CONFIG_DIR, "projects") : null;
  if (c && c !== dirs[0]) dirs.push(c);
  return dirs;
}
function listTranscripts(root, now) {
  const out = [];
  const walk = (d, depth) => {
    let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (out.length >= MAX_FILES * 4) return;
      const p = join(d, e.name);
      if (e.isDirectory() && depth < MAX_DEPTH) walk(p, depth + 1);
      else if (e.isFile() && e.name.endsWith(".jsonl")) { try { const st = statSync(p); if (now - st.mtimeMs <= MAX_AGE_MS) out.push({ p, size: st.size, mtime: st.mtimeMs }); } catch { /* gone */ } }
    }
  };
  walk(root, 0);
  return out;
}

function loadState(stateDir) {
  try { const o = JSON.parse(readFileSync(join(stateDir, TRANSCRIPT_STATE), "utf8")); if (o && o.v === 1 && o.files && typeof o.files === "object") return o; } catch { /* first run */ }
  return { v: 1, files: {}, buckets: [], pausedUntil: 0 };
}
function saveState(stateDir, st) {
  mkdirSync(stateDir, { recursive: true });
  const file = join(stateDir, TRANSCRIPT_STATE), tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(st), { mode: 0o600 });
  renameSync(tmp, file);
}

// One assistant line → bucket input, or null.
function lineUsage(line, hash) {
  if (!line.includes("\"assistant\"") || !line.includes("\"message\"")) return null;
  let o; try { o = JSON.parse(line); } catch { return null; }
  if (!o || o.type !== "assistant" || !o.message || typeof o.message !== "object") return null;
  const m = o.message;
  if (typeof m.id !== "string" || !m.id || m.model === "<synthetic>") return null;
  const ts = Date.parse(o.timestamp);
  if (!Number.isFinite(ts)) return null;
  return { id: m.id, key: { hour: hourStart(ts), agentName: "claude-code", provider: "anthropic", model: cleanModel(m.model), projectKey: typeof o.cwd === "string" && o.cwd ? hash(o.cwd) : null }, usage: normalizeUsage("anthropic", m.usage) };
}

// Reads one file from its saved offset; → bytes consumed. Only complete lines are consumed.
function readFile(f, fst, buckets, hash, budget) {
  let off = fst.off, consumed = 0, fd;
  const ids = fst.ids;
  try { fd = openSync(f.p, "r"); } catch { return 0; }
  try {
    let carry = Buffer.alloc(0), skipping = !!fst.skip;
    while (off + carry.length < f.size && consumed < budget) {
      const n = Math.min(CHUNK, f.size - off - carry.length);
      const buf = Buffer.alloc(n);
      const got = readSync(fd, buf, 0, n, off + carry.length);
      if (got <= 0) break;
      let data = carry.length ? Buffer.concat([carry, buf.subarray(0, got)]) : buf.subarray(0, got);
      let start = 0, nl;
      while ((nl = data.indexOf(10, start)) >= 0) {
        if (!skipping) {
          const u = lineUsage(data.toString("utf8", start, nl), hash);
          if (u && !ids.includes(u.id)) { buckets.add(u.key, u.usage); ids.push(u.id); if (ids.length > KEEP_IDS) ids.shift(); }
        }
        skipping = false;
        start = nl + 1;
      }
      off += start; consumed += start;
      carry = data.subarray(start);
      // A line past MAX_LINE is skipped whole: drop what is held and skip to its end.
      if (carry.length > MAX_LINE) { off += carry.length; consumed += carry.length; carry = Buffer.alloc(0); skipping = true; }
    }
    fst.skip = skipping;
  } finally { closeSync(fd); }
  fst.off = off; fst.size = f.size;
  return consumed;
}

// Scan, then post what changed. → { files, bytes, sent, failed, paused }. Never throws on a bad file.
export async function runTranscriptUsage({ home = homedir(), env = process.env, stateDir = join(home, ".moorai"), config, identity, fetchImpl = globalThis.fetch, hash = contentHash, now = Date.now(), maxBytes = 64 * 1024 * 1024 } = {}) {
  const st = loadState(stateDir);
  const buckets = createBuckets();
  buckets.load(st.buckets);
  const files = projectsDirs(home, env).flatMap((d) => listTranscripts(d, now)).sort((a, b) => b.mtime - a.mtime).slice(0, MAX_FILES);
  const seen = {};
  let bytes = 0;
  for (const f of files) {
    const k = digest(f.p);
    const fst = st.files[k] && typeof st.files[k] === "object" ? st.files[k] : { off: 0, size: 0, ids: [] };
    if (!Array.isArray(fst.ids)) fst.ids = [];
    // A file shorter than its saved offset was rewritten: its earlier usage is already counted, so it is not read again.
    if (f.size < fst.off) fst.off = f.size;
    seen[k] = fst;
    if (bytes < maxBytes && f.size > fst.off) bytes += readFile(f, fst, buckets, hash, maxBytes - bytes);
  }
  st.files = seen;
  let res = { sent: 0, failed: 0, unsupported: false };
  const paused = now < (st.pausedUntil || 0);
  if (!paused && config && config.serverUrl) {
    const header = { v: 1, user: identity && identity.user, device: identity && identity.device, platform: identity && identity.platform, source: "transcript", instance: TRANSCRIPT_INSTANCE };
    res = await flushBuckets({ buckets, header, config, fetchImpl });
    if (res.unsupported) st.pausedUntil = now + PAUSE_MS;
  }
  buckets.prune(hourStart(now - BUCKET_KEEP_MS));
  st.buckets = buckets.toJSON();
  saveState(stateDir, st);
  return { files: files.length, bytes, sent: res.sent, failed: res.failed, paused };
}

// The hook's trigger: at most once per TRANSCRIPT_INTERVAL_MS, stamped before the worker starts. spawnWorker
// starts the detached worker. → true when it did.
export function scheduleTranscriptUsage({ stateDir, spawnWorker, now = Date.now() }) {
  try {
    const stamp = join(stateDir, TRANSCRIPT_STAMP);
    try { if (now - statSync(stamp).mtimeMs < TRANSCRIPT_INTERVAL_MS) return false; } catch { /* never ran */ }
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(stamp, "", { mode: 0o600 });
    spawnWorker();
    return true;
  } catch { return false; }
}
