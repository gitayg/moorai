// F22 — on-disk cache of on-device escalation verdicts.
//
// The escalation layer runs in a detached worker that is a NEW process for every tool call
// (cli/moorai-hook.mjs maybeEscalate), so a verdict for text the agent re-reads or re-sends was paid for
// with a full local-model call each time. This cache keeps the model's verdict, never the text:
//   * key   = HMAC-SHA256(per-device random key, model + "\0" + prompt id + "\0" + text), truncated. The
//             prompt id is a hash of the classifier prompt (data/model-escalation.mjs CLASSIFIER_PROMPT_ID),
//             so a verdict from an older prompt is never reused after the prompt changes. The key is a random
//             32-byte file next to the cache (0600), so it works on an unenrolled device too and the
//             cache file alone cannot be used to confirm a guessed text.
//   * value = { flagged, category (the model's short label, max 40 chars), confidence, time }.
//   * bounded: entries older than CACHE_TTL_MS are dropped, and past CACHE_MAX_ENTRIES the oldest go.
//   * only verdicts a model returned are stored; a timeout, an error or an unparseable answer is not
//     cached, so a model that is cold or briefly down is asked again next time.
//   * off switch: MOORAI_ESCALATION_CACHE=off (or 0 / false / no) disables reads and writes. The
//     measurement scripts set it so repeated runs measure the model, not the cache.
// Every function is fail-open: a missing, unreadable or corrupt file is a miss, and a write failure is
// ignored. The cache can never change a verdict; it only avoids asking for the same one twice.
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, renameSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "../cli/state-dirs.mjs";

export const CACHE_FILE = "escalation-cache.json";
export const CACHE_KEY_FILE = "escalation-cache.key";
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
export const CACHE_MAX_ENTRIES = 2000;
const KEY_HEX = 32;

function readKey(dir) {
  const p = join(dir, CACHE_KEY_FILE);
  try {
    const k = readFileSync(p);
    if (k.length >= 32) return k;
  } catch { /* create below */ }
  const k = randomBytes(32);
  mkdirSync(dir, { recursive: true });
  writeFileSync(p, k, { mode: 0o600 });
  return k;
}

export function cacheDisabled() {
  return /^(off|0|false|no)$/i.test(String(process.env.MOORAI_ESCALATION_CACHE || "").trim());
}

function entryKey(dir, text, model, promptId) {
  return createHmac("sha256", readKey(dir)).update(`${model}\0${promptId}\0${text}`, "utf8").digest("hex").slice(0, KEY_HEX);
}

function load(dir) {
  try {
    const j = JSON.parse(readFileSync(join(dir, CACHE_FILE), "utf8"));
    if (j && j.v === 1 && j.entries && typeof j.entries === "object") return j;
  } catch { /* miss */ }
  return { v: 1, entries: {} };
}

export function getCachedVerdict(text, model, { dir = STATE_DIR, now = Date.now(), ttlMs = CACHE_TTL_MS, promptId = "" } = {}) {
  try {
    if (!text || !model || cacheDisabled()) return null;
    const e = load(dir).entries[entryKey(dir, String(text), String(model), String(promptId))];
    if (!e || typeof e.f !== "boolean" || !(now - e.t <= ttlMs) || e.t > now + 60000) return null;
    return { flagged: e.f, category: String(e.c || "model-flagged").slice(0, 40), confidence: Math.max(0, Math.min(1, Number(e.p) || 0)) };
  } catch { return null; }
}

export function putCachedVerdict(text, model, verdict, { dir = STATE_DIR, now = Date.now(), ttlMs = CACHE_TTL_MS, maxEntries = CACHE_MAX_ENTRIES, promptId = "" } = {}) {
  try {
    if (!text || !model || !verdict || typeof verdict.flagged !== "boolean" || cacheDisabled()) return;
    const j = load(dir);
    j.entries[entryKey(dir, String(text), String(model), String(promptId))] = {
      f: verdict.flagged,
      c: String(verdict.category || "model-flagged").slice(0, 40),
      p: Math.max(0, Math.min(1, Number(verdict.confidence) || 0)),
      t: now
    };
    const live = Object.entries(j.entries).filter(([, e]) => e && now - e.t <= ttlMs).sort((a, b) => a[1].t - b[1].t);
    j.entries = Object.fromEntries(live.slice(Math.max(0, live.length - maxEntries)));
    mkdirSync(dir, { recursive: true });
    const tmp = join(dir, `${CACHE_FILE}.${process.pid}.tmp`);
    writeFileSync(tmp, JSON.stringify(j), { mode: 0o600 });
    try { chmodSync(tmp, 0o600); } catch { /* best effort */ }
    renameSync(tmp, join(dir, CACHE_FILE));
  } catch { /* the cache is an optimisation, never enforcement */ }
}
