// Tier-2 (#65) — local secret-value egress detection ("Option C"). Reads local secret stores ON-DEVICE
// only, fingerprints each value as a one-way hash, and checks whether any value appears verbatim in an
// outbound flow (command / MCP arg / prompt). The value itself is NEVER emitted — only the hash of the
// matched secret + a verdict leave. This catches an agent shipping a real .env / cloud credential off
// the device even when the string isn't in a recognizable provider-token shape.
import { readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

function djb2(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0; return "h" + h.toString(16); }

// Values too short or obviously non-secret (placeholders) are ignored to avoid false matches.
const PLACEHOLDER = /^(?:todo|tbd|changeme|placeholder|example|test|none|null|true|false|localhost|your[-_ ]?\w*|<[^>]*>|\$\{[^}]*\}|x{3,}|\*{3,}|\.{3,})$/i;
function isSecretish(v) {
  if (!v || v.length < 8 || v.length > 512) return false;
  if (PLACEHOLDER.test(v)) return false;
  if (/^\d+$/.test(v)) return false;               // pure numbers (ports, timestamps)
  if (/^[a-z]+$/i.test(v) && v.length < 16) return false; // short plain words
  return /[^\w]|[A-Z].*[0-9]|[0-9].*[A-Z]|[-_./+=]/.test(v) || v.length >= 20; // some entropy / structure
}

function parseEnv(text) {
  const out = [];
  for (const line of String(text).split("\n")) {
    const m = line.match(/^\s*(?:export\s+)?[\w.-]+\s*=\s*(.+?)\s*$/);
    if (!m) continue;
    let v = m[1].trim().replace(/^["']|["']$/g, "");
    if (isSecretish(v)) out.push(v);
  }
  return out;
}

let _cache = null; // { dir, values: [{hash,value}] } — memoized per process, values stay in memory only
function loadLocalSecrets(cwd) {
  const dir = cwd || process.cwd();
  if (_cache && _cache.dir === dir) return _cache.values;
  const values = new Map(); // value -> hash (dedup)
  const add = (v) => { if (isSecretish(v) && !values.has(v)) values.set(v, djb2(v)); };
  const readFileSafe = (p) => { try { const b = readFileSync(p); return b.includes(0) ? "" : b.subarray(0, 262144).toString("utf8"); } catch { return ""; } };
  // Project dotenv files
  try { for (const f of readdirSync(dir)) { if (f === ".env" || f.startsWith(".env.")) parseEnv(readFileSafe(join(dir, f))).forEach(add); } } catch { /* no dir access */ }
  // Well-known credential files (KEY=VALUE / INI-ish) — values only.
  for (const p of [join(homedir(), ".aws", "credentials"), join(homedir(), ".npmrc"), join(homedir(), ".netrc"), join(dir, ".git-credentials")]) {
    const t = readFileSafe(p);
    if (t) parseEnv(t.replace(/:/g, "=")).forEach(add); // tolerate `key: value`
  }
  const arr = [...values.entries()].map(([value, hash]) => ({ value, hash }));
  _cache = { dir, values: arr };
  return arr;
}

// Return the one-way hashes of any local secret VALUE that appears verbatim in `text`. Content-free
// output: the caller emits only these hashes, never the value. Empty array = no local secret is leaking.
export function egressHits(text, cwd) {
  const t = String(text || "");
  if (!t) return [];
  const hits = [];
  for (const { value, hash } of loadLocalSecrets(cwd)) { if (t.includes(value)) hits.push(hash); }
  return [...new Set(hits)];
}
