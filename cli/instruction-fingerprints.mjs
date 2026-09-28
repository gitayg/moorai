// Discovery, key and on-disk cache for the instruction-leak fingerprints (data/instruction-fingerprint.js).
//
// WHAT IS STORED, and where (STATE_DIR = ~/.moorai):
//   instruction-fp.key   32 random bytes (hex), mode 0600. Per DEVICE: the fingerprints never leave the
//                        device, so there is nothing to correlate across a fleet and no reason to tie the
//                        key to the enrollment token (an unenrolled device needs one too).
//   instruction-fp.json  { v, keyId, entries: { <pathId>: { m, s, kind, n, max, h:[40-bit ints], t } } }
//                        pathId = HMAC(key, absolute path) — neither the path nor any file text is kept.
//                        At most MAX_ENTRIES files * MAX_KEPT hashes; least-recently-used evicted.
// A file is re-fingerprinted only when its mtime or size changed; everything else is read from the cache.
import { readFileSync, writeFileSync, statSync, readdirSync, mkdirSync, renameSync, chmodSync } from "node:fs";
import { join, dirname, resolve, parse } from "node:path";
import { randomBytes } from "node:crypto";
import os from "node:os";
import { STATE_DIR } from "./state-dirs.mjs";
import { makeKeyedHash } from "../data/keyed-hash.js";
import { fingerprintText, makeFingerprintSet, setInstructionFingerprintLoader, MAX_KEPT } from "../data/instruction-fingerprint.js";
import { instructionFileKind } from "../data/instruction-files.js";

export const KEY_FILE = "instruction-fp.key";
export const CACHE_FILE = "instruction-fp.json";
const MAX_FILES = 48;
const MAX_ENTRIES = 96;
const MAX_FILE_BYTES = 262144;
const MAX_DIR_FILES = 32;

const isFile = (p) => { try { return statSync(p).isFile(); } catch { return false; } };

// *.md / *.mdc directly under dir, one level of subdirectories, bounded.
function listRuleDir(dir, exts = /\.mdc?$/i) {
  const out = [];
  const walk = (d, depth) => {
    let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (out.length >= MAX_DIR_FILES) return;
      const p = join(d, e.name);
      if (e.isDirectory() && depth < 2) walk(p, depth + 1);
      else if (e.isFile() && exts.test(e.name)) out.push(p);
    }
  };
  walk(dir, 0);
  return out;
}

// Every instruction file an agent working in `cwd` runs under. Paths only; nothing is read here.
export function discoverInstructionFiles(cwd, { home = os.homedir(), env = process.env, managed = true } = {}) {
  const found = new Set();
  const add = (p) => { if (found.size < MAX_FILES && isFile(p)) found.add(resolve(p)); };
  // Project scope: cwd and every directory above it (Claude Code, Codex, Gemini CLI all walk up).
  let dir = resolve(cwd || process.cwd());
  for (let depth = 0; depth < 32; depth++) {
    for (const n of ["CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md",
      ".cursorrules", ".windsurfrules", ".clinerules", ".github/copilot-instructions.md"]) add(join(dir, n));
    for (const d of [".claude/rules", ".cursor/rules", ".windsurf/rules", ".devin/rules", ".clinerules", ".cline/rules"]) for (const p of listRuleDir(join(dir, d))) add(p);
    for (const p of listRuleDir(join(dir, ".github/instructions"), /\.instructions\.md$/i)) add(p);
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  // User scope.
  const codexHome = env.CODEX_HOME || join(home, ".codex");
  for (const p of [join(home, ".claude", "CLAUDE.md"), join(codexHome, "AGENTS.md"), join(codexHome, "AGENTS.override.md"),
    join(home, ".gemini", "GEMINI.md"), join(home, ".codeium", "windsurf", "memories", "global_rules.md"), join(home, ".agents", "AGENTS.md")]) add(p);
  for (const d of [join(home, ".claude", "rules"), join(home, ".cline", "rules"), join(home, "Documents", "Cline", "Rules")]) for (const p of listRuleDir(d)) add(p);
  // Managed (organization) policy.
  if (managed) for (const p of ["/Library/Application Support/ClaudeCode/CLAUDE.md", "/etc/claude-code/CLAUDE.md", "C:\\Program Files\\ClaudeCode\\CLAUDE.md"]) add(p);
  return [...found];
}

export function loadOrCreateKey(stateDir = STATE_DIR) {
  const p = join(stateDir, KEY_FILE);
  try {
    const hex = readFileSync(p, "utf8").trim();
    if (/^[0-9a-f]{64}$/.test(hex)) return Uint8Array.from(Buffer.from(hex, "hex"));
  } catch { /* create below */ }
  mkdirSync(stateDir, { recursive: true });
  const key = randomBytes(32);
  writeFileSync(p, key.toString("hex") + "\n", { mode: 0o600 });
  try { chmodSync(p, 0o600); } catch { /* best effort on Windows */ }
  return Uint8Array.from(key);
}

function readCache(stateDir, keyId) {
  try {
    const c = JSON.parse(readFileSync(join(stateDir, CACHE_FILE), "utf8"));
    if (c && c.v === 1 && c.keyId === keyId && c.entries && typeof c.entries === "object") return c;
  } catch { /* rebuild */ }
  return { v: 1, keyId, entries: {} };
}

function writeCache(stateDir, cache) {
  const ids = Object.keys(cache.entries);
  if (ids.length > MAX_ENTRIES) {
    ids.sort((a, b) => (cache.entries[a].t || 0) - (cache.entries[b].t || 0));
    for (const id of ids.slice(0, ids.length - MAX_ENTRIES)) delete cache.entries[id];
  }
  const p = join(stateDir, CACHE_FILE);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(cache), { mode: 0o600 });
  renameSync(tmp, p);
}

// Fingerprint every discovered file, reusing cached entries whose mtime+size are unchanged. Returns the
// runtime set (data/instruction-fingerprint.js makeFingerprintSet) or null when there is nothing to guard.
export function buildInstructionFingerprints(cwd, { stateDir = STATE_DIR, home, env, managed, files } = {}) {
  const paths = files || discoverInstructionFiles(cwd, { home, env, managed });
  if (!paths.length) return null;
  const key = loadOrCreateKey(stateDir);
  const hash = makeKeyedHash(key);
  const keyId = hash.hex("moorai-instruction-fp-v1").slice(0, 16);
  const cache = readCache(stateDir, keyId);
  const now = Date.now();
  let dirty = false;
  const sources = [];
  for (const p of paths) {
    let st; try { st = statSync(p); } catch { continue; }
    const id = hash.hex(`path:${p}`).slice(0, 24);
    let e = cache.entries[id];
    if (!e || e.m !== st.mtimeMs || e.s !== st.size) {
      let text; try { text = readFileSync(p).subarray(0, MAX_FILE_BYTES).toString("utf8"); } catch { continue; }
      const fp = fingerprintText(text, hash, { maxKept: MAX_KEPT });
      e = { m: st.mtimeMs, s: st.size, kind: instructionFileKind(p) || parse(p).base, n: fp.n, max: fp.max, h: fp.h, t: now };
      cache.entries[id] = e;
      dirty = true;
    } else if (now - (e.t || 0) > 3600e3) { e.t = now; dirty = true; }
    sources.push(e);
  }
  if (dirty) { try { mkdirSync(stateDir, { recursive: true }); writeCache(stateDir, cache); } catch { /* cache is an optimisation */ } }
  return makeFingerprintSet(key, sources);
}

// The hook's one call: register a LAZY loader, so discovery, the key read and the cache parse happen
// only if a scan actually reaches a fingerprint detector with enough text to judge. Fail-open.
export function registerInstructionFingerprints(cwd, opts = {}) {
  setInstructionFingerprintLoader(() => { try { return buildInstructionFingerprints(cwd, opts); } catch { return null; } });
}
