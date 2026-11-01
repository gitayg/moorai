// F13 credential exposure map: a content-free answer, per agent host, to three questions.
//   1. Which credential CLASSES can an agent on this device reach? (credentialInventory)
//   2. Which of them did an agent read? (noteCredentialCall on PreToolUse, rolled up by credentialExposure)
//   3. To which destination CLASS did that session send data within 10 minutes after the read?
// The result is the `credentialExposure` field of the daily posture heartbeat (POST /api/agent-posture),
// shape v1 of the F28 contract §2. It is heuristic and says so (`coverage: "heuristic"`).
//
// NEVER IN THE FIELD: a path, a file's contents, a credential value, a profile / context / cluster name, a
// custom env var name, a host name, a session id. What is in it: the kind and location enums, booleans,
// counts, hour-rounded timestamps, allow-listed env var names (data/credential-env-names.js), and for an
// AI key at rest the existing keyed fingerprint from cli/aibom-keys.mjs (`h2:`, per tenant).
//
// REACHABLE is a stat plus an access(R_OK) check on a SMALL, FIXED set of locations (KIND_FILES below, the
// session cwd's top level, the MCP client configs). Three things are read, and only for a derived bit:
//   * ~/.aws/config, ~/.aws/credentials and ~/.kube/config: section headers and `name:` lines only, for
//     `prodLike` (any name matching /prod/i). The names and everything else in the file stay here.
//   * MCP client configs: the KEY names under each server's `env` and `headers`, to tell whether one is
//     credential-shaped. Values are never looked at.
//   * AI keys at rest: the existing keys-at-rest scan (cli/aibom-keys.mjs), which returns keyed hashes.
// Each read is bounded (1 MiB; 8 MiB for ~/.claude.json, which also holds per-project history).
//
// READS are what the agent asked for at PreToolUse (a Read path, a shell command, an MCP call's string
// arguments) where a credential location matches, including calls MoorAI then denied. The local log
// (~/.moorai/credential-exposure.jsonl, 0600) keeps the kind, the scope class, the agent host, the session's
// keyed hash and the time; egress entries keep only destination classes. Never a path or a host.
import { readFileSync, readdirSync, statSync, accessSync, openSync, writeSync, closeSync, writeFileSync, renameSync, mkdirSync, constants } from "node:fs";
import { homedir } from "node:os";
import { join, resolve, isAbsolute, relative } from "node:path";
import { CRED_ALTERNATIVES } from "../data/cred-alternatives.js";
import { CREDENTIAL_ENV_NAMES, CREDENTIAL_ENV_SHAPE } from "../data/credential-env-names.js";
import { throwawayHost } from "../data/throwaway-hosts.js";
import { LLM_ENDPOINT_HOSTS } from "../data/model-endpoints.js";
import { egressTargets } from "./egress-rules.mjs";
import { isWithin } from "./path-within.mjs";
import { scanKeysAtRest } from "./aibom-keys.mjs";

// AI keys at rest, with the path kept only long enough to classify its scope here.
export const defaultKeysAtRest = ({ home }) => scanKeysAtRest({ home, includePath: true }).findings;

export const KINDS = Object.freeze(["aws", "ssh", "kube", "npm", "git", "docker", "gcloud", "azure", "env", "gh", "netrc", "pgpass", "mcp-config", "ai-key"]);
export const LOCATION_CLASSES = Object.freeze(["home-config", "project-file", "system", "env", "mcp-config"]);
export const SCOPES = Object.freeze(["home", "project", "outside-project", "system", "env"]);
export const DEST_CLASSES = Object.freeze(["throwaway-host", "ai-provider", "private-range", "other"]);
export const EXPOSURE_FILE = "credential-exposure.jsonl";
export const EXPOSURE_KEEP = 2000;                    // entries kept on compaction
const CHECK_AT_BYTES = EXPOSURE_KEEP * 48;            // past this size an append counts lines (no entry is under 48 bytes)
const KEEP_MS = 8 * 24 * 3600_000;                     // entries older than this are dropped on compaction
export const SENT_WINDOW_MS = 10 * 60_000;
export const WINDOW_MS = 24 * 3600_000;
export const MAX_ITEMS = 64;
export const MAX_ENV_NAMES = 16;
export const MAX_HOSTS = 6;
export const POSTURE_FIT_LIMIT = 15360;                // the console refuses a posture body over 16384 (413)
const MAX_FILE = 1024 * 1024;
const MAX_CLAUDE_JSON = 8 * 1024 * 1024;
const MAX_MCP_CHARS = 65536;

// Credential locations, by kind, as path patterns. #55's kind table (data/cred-alternatives.js) minus the
// one alternative that names a command rather than a file (`gcloud auth`), plus gh, netrc and pgpass.
const KIND_PATTERNS = [
  ...CRED_ALTERNATIVES.map((c) => ({ kind: c.kind, re: c.kind === "gcloud" ? /\.config[\/\\]gcloud\b/i : c.re })),
  { kind: "gh", re: /\.config[\/\\]gh[\/\\]hosts\.yml\b/i },
  { kind: "netrc", re: /(?:^|[\/\\\s"'`~=])[._]netrc\b/i },
  { kind: "pgpass", re: /\.pgpass\b/i }
].map(({ kind, re }) => ({ kind, re: new RegExp(re.source, re.flags.replace("g", "") + "g") }));
const NOT_SECRET = /\.(?:pub|crt|cer)$|(?:^|[\/\\])(?:ca|certs?|certificate|chain|fullchain|public|pubkey)[\w-]*\.pem$/i;
const TEMPLATE = /\.env\.(?:example|sample|template|dist)\b/i;

// Fixed home-config files per kind (relative to home). A directory entry ending in "/" is listed instead.
const KIND_FILES = {
  aws: [".aws/credentials", ".aws/config"],
  ssh: [".ssh/"],
  kube: [".kube/config"],
  npm: [".npmrc"],
  git: [".git-credentials"],
  docker: [".docker/config.json"],
  gcloud: [".config/gcloud/application_default_credentials.json", ".config/gcloud/credentials.db", ".config/gcloud/access_tokens.db"],
  azure: [".azure/msal_token_cache.json", ".azure/msal_token_cache.bin", ".azure/accessTokens.json"],
  gh: [".config/gh/hosts.yml"],
  netrc: [".netrc", "_netrc"],
  pgpass: [".pgpass"]
};
// MCP client configs (home), and the project-level ones (session cwd).
const MCP_HOME = [".claude.json", ".cursor/mcp.json", ".codeium/windsurf/mcp_config.json", ".gemini/settings.json", "Library/Application Support/Claude/claude_desktop_config.json", ".config/Claude/claude_desktop_config.json"];
const MCP_PROJECT = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"];
// Credential files at the top level of the session's project.
const PROJECT_FILES = { ".npmrc": "npm", ".netrc": "netrc", ".pgpass": "pgpass", ".git-credentials": "git" };
const DOTENV = /^\.env(?:\.[A-Za-z0-9_-]+)?$/;

const readable = (p) => { try { if (!statSync(p).isFile()) return false; accessSync(p, constants.R_OK); return true; } catch { return false; } };
const listDir = (p) => { try { return readdirSync(p, { withFileTypes: true }); } catch { return []; } };
function readBounded(p, max = MAX_FILE) {
  try { const st = statSync(p); if (!st.isFile() || st.size > max) return null; return readFileSync(p, "utf8"); } catch { return null; }
}
const PROD = /prod/i;
// Profile and context names only; the names never leave this function.
function awsProdLike(home) {
  for (const rel of KIND_FILES.aws) {
    const t = readBounded(join(home, rel));
    if (t && [...t.matchAll(/^\s*\[(?:profile\s+)?([^\]\r\n]{1,128})\]/gm)].some((m) => PROD.test(m[1]))) return true;
  }
  return false;
}
function kubeProdLike(home) {
  const t = readBounded(join(home, ".kube/config"));
  return !!t && [...t.matchAll(/^\s*(?:-\s+)?(?:name|current-context):\s*["']?([^\s"'#]{1,253})/gm)].some((m) => PROD.test(m[1]));
}
function gcloudProdLike(home) {
  return listDir(join(home, ".config/gcloud/configurations")).some((e) => e.isFile() && /^config_/.test(e.name) && PROD.test(e.name.slice(7)));
}
// Does an MCP client config hold a credential-shaped key under a server's env or headers? Key names only.
function mcpHasCredential(p, max) {
  const t = readBounded(p, max);
  if (!t) return false;
  let j; try { j = JSON.parse(t); } catch { return false; }
  const credKey = (k) => CREDENTIAL_ENV_SHAPE.test(k) || Object.prototype.hasOwnProperty.call(CREDENTIAL_ENV_NAMES, k) || /^authorization$/i.test(k) || /^x-api-key$/i.test(k);
  const servers = (o) => (o && typeof o === "object" && o.mcpServers && typeof o.mcpServers === "object" ? Object.values(o.mcpServers) : []);
  const all = [...servers(j)];
  if (j && typeof j.projects === "object" && j.projects) for (const p2 of Object.values(j.projects)) all.push(...servers(p2));
  return all.some((s) => s && typeof s === "object" && ["env", "headers"].some((f) => s[f] && typeof s[f] === "object" && Object.keys(s[f]).some(credKey)));
}

const blank = (kind, locationClass, scope, extra = {}) => ({ kind, locationClass, scope, reachable: true, keyHash: null, envNames: [], envOtherCount: 0, prodLike: false, byHost: {}, ...extra });

// The scope class of a path an agent named. cwd: the session's project root.
function scopeOf(p, { home, cwd, platform = process.platform }) {
  if (cwd && (isWithin(p, cwd, platform) || p === cwd)) return "project";
  if (home && isWithin(p, home, platform)) {
    const first = relative(home, p).split(/[\/\\]/)[0] || "";
    return first.startsWith(".") || first === "_netrc" || first === "Library" || first === "AppData" ? "home" : "outside-project";
  }
  if (/^(?:\/etc|\/var|\/root|\/opt|\/usr|\/Library|\/private\/etc)(?:\/|$)/.test(p) || /^[A-Za-z]:\\(?:ProgramData|Windows)\\/i.test(p)) return "system";
  return "outside-project";
}
// The token around a match in a command: the whole word, quotes stripped.
function tokenAt(s, i, len) {
  let a = i, b = i + len;
  while (a > 0 && !/[\s;|&<>()]/.test(s[a - 1])) a--;
  while (b < s.length && !/[\s;|&<>()]/.test(s[b])) b++;
  return s.slice(a, b).replace(/^[A-Za-z_][A-Za-z0-9_-]*=/, "").replace(/["'`]/g, "");
}
function expand(tok, { home, cwd }) {
  let t = tok;
  if (t.startsWith("~/") || t === "~") t = join(home, t.slice(1));
  t = t.replace(/^\$\{?HOME\}?(?=\/|$)/, home);
  if (!isAbsolute(t)) t = resolve(cwd || home, t);
  return resolve(t);
}
// Credential reads one string names: [{ kind, scope }]. `pathOnly` when the string IS a path (Read).
export function credentialReadsIn(text, { home = homedir(), cwd = "", pathOnly = false } = {}) {
  const s = String(text || "").slice(0, MAX_MCP_CHARS);
  const out = [], seen = new Set();
  for (const { kind, re } of KIND_PATTERNS) {
    re.lastIndex = 0;
    let m, n = 0;
    while ((m = re.exec(s)) && n++ < 16) {
      const tok = pathOnly ? s : tokenAt(s, m.index, m[0].length);
      if (!tok || NOT_SECRET.test(tok) || TEMPLATE.test(tok)) continue;
      const scope = scopeOf(expand(tok, { home, cwd }), { home, cwd });
      const k = `${kind}|${scope}`;
      if (!seen.has(k)) { seen.add(k); out.push({ kind, scope }); }
      if (pathOnly) break;
    }
  }
  return out;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function privateIp(h) {
  const host = String(h).replace(/^\[|\]$/g, "").toLowerCase();
  const m = IPV4.exec(host.replace(/^::ffff:/, ""));
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  return host === "::1" || /^f[cd][0-9a-f]{2}:/.test(host) || /^fe[89ab][0-9a-f]:/.test(host) || host === "localhost" || host.endsWith(".localhost");
}
const aiProvider = (h) => LLM_ENDPOINT_HOSTS.some((x) => h === x || h.endsWith(`.${x}`) || (!x.includes(".") && h.includes(x)));
// The destination class of one host (a closed enum; the host itself never leaves the device).
export function destClassFor(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  if (!h) return "other";
  if (throwawayHost(h)) return "throwaway-host";
  if (aiProvider(h)) return "ai-provider";
  if (privateIp(h)) return "private-range";
  return "other";
}

function appendEntries(stateDir, entries) {
  if (!entries.length) return;
  mkdirSync(stateDir, { recursive: true });
  const file = join(stateDir, EXPOSURE_FILE);
  const fd = openSync(file, "a", 0o600);
  try { writeSync(fd, entries.map((e) => JSON.stringify(e)).join("\n") + "\n"); } finally { closeSync(fd); }
  let size = 0;
  try { size = statSync(file).size; } catch { return; }
  if (size > CHECK_AT_BYTES && lineCount(file) > EXPOSURE_KEEP) compact(stateDir, Date.now());
}
function lineCount(file) { try { const b = readFileSync(file); let n = 0; for (let i = 0; i < b.length; i++) if (b[i] === 10) n++; return n; } catch { return 0; } }
function readEntries(stateDir) {
  let raw = "";
  try { raw = readFileSync(join(stateDir, EXPOSURE_FILE), "utf8"); } catch { return []; }
  const out = [];
  for (const l of raw.split("\n")) { if (!l) continue; try { const e = JSON.parse(l); if (e && typeof e === "object" && Number.isFinite(e.ts)) out.push(e); } catch { /* a torn line */ } }
  return out.slice(-EXPOSURE_KEEP);
}
function compact(stateDir, now) {
  const file = join(stateDir, EXPOSURE_FILE);
  const newest = readEntries(stateDir).filter((e) => e.ts > now - KEEP_MS).slice(-Math.floor(EXPOSURE_KEEP * 0.75));
  const tmp = `${file}.${process.pid}.tmp`;
  try { writeFileSync(tmp, newest.map((e) => JSON.stringify(e)).join("\n") + (newest.length ? "\n" : ""), { mode: 0o600 }); renameSync(tmp, file); } catch { /* the next append retries */ }
}

// One agent call at PreToolUse: credential reads it names, and the destination classes it reaches.
// Synchronous, no network; writes only when there is something to record. Never throws.
export function noteCredentialCall({ stateDir, tool, toolInput, cwd = "", home = homedir(), session = "", host = "", now = Date.now() } = {}) {
  try {
    const t = String(tool || ""), ti = toolInput && typeof toolInput === "object" ? toolInput : {};
    const ctx = { home, cwd: typeof cwd === "string" ? cwd : "" };
    let reads = [];
    if (t === "Read" && typeof ti.file_path === "string") reads = credentialReadsIn(ti.file_path, { ...ctx, pathOnly: true });
    else if ((t === "Bash" || t === "PowerShell" || t === "Monitor") && typeof ti.command === "string") reads = credentialReadsIn(ti.command, ctx);
    else if (t.startsWith("mcp__")) {
      const strings = [];
      let budget = MAX_MCP_CHARS;
      const walk = (v, d) => { if (d > 16 || budget <= 0) return; if (typeof v === "string") { budget -= v.length; strings.push(v); } else if (v && typeof v === "object") for (const k of Object.keys(v)) walk(v[k], d + 1); };
      walk(ti, 0);
      const seen = new Set();
      for (const s of strings) for (const r of credentialReadsIn(s, ctx)) { const k = `${r.kind}|${r.scope}`; if (!seen.has(k)) { seen.add(k); reads.push(r); } }
    }
    const h = String(host || "unknown").slice(0, 32), s = String(session || "").slice(0, 80);
    const entries = reads.map((r) => ({ t: "r", k: r.kind, sc: r.scope, h, s, ts: now }));
    let classes = [];
    try { classes = [...new Set(egressTargets(t, ti).map((x) => x && x.host).filter(Boolean).map(destClassFor))].sort(); } catch { classes = []; }
    if (classes.length && s) entries.push({ t: "e", d: classes, s, ts: now });
    if (stateDir) appendEntries(stateDir, entries);
    return { reads: reads.length, egress: classes.length };
  } catch { return { reads: 0, egress: 0 }; }
}

// What an agent on this device can reach now. keysAtRest: () => findings with `path` (cli/aibom-keys.mjs).
export function credentialInventory({ home = homedir(), env = process.env, cwd = "", platform = process.platform, keysAtRest = defaultKeysAtRest } = {}) {
  const items = [];
  for (const [kind, rels] of Object.entries(KIND_FILES)) {
    let reach = false;
    for (const rel of rels) {
      if (rel.endsWith("/")) { const dir = join(home, rel); reach = listDir(dir).some((e) => e.isFile() && /^id_[A-Za-z0-9_]+$/.test(e.name) && readable(join(dir, e.name))); }
      else reach = readable(join(home, rel));
      if (reach) break;
    }
    if (!reach) continue;
    const prodLike = kind === "aws" ? awsProdLike(home) : kind === "kube" ? kubeProdLike(home) : kind === "gcloud" ? gcloudProdLike(home) : false;
    items.push(blank(kind, "home-config", "home", { prodLike }));
  }
  if (MCP_HOME.some((rel) => mcpHasCredential(join(home, rel), rel === ".claude.json" ? MAX_CLAUDE_JSON : MAX_FILE))) items.push(blank("mcp-config", "mcp-config", "home"));
  if (cwd && typeof cwd === "string") {
    const seen = new Set();
    for (const e of listDir(cwd)) {
      if (!e.isFile()) continue;
      const kind = DOTENV.test(e.name) && !TEMPLATE.test(e.name) ? "env" : PROJECT_FILES[e.name];
      if (!kind || seen.has(kind) || !readable(join(cwd, e.name))) continue;
      seen.add(kind);
      items.push(blank(kind, "project-file", "project"));
    }
    if (MCP_PROJECT.some((rel) => mcpHasCredential(join(cwd, rel), MAX_FILE))) items.push(blank("mcp-config", "mcp-config", "project"));
  }
  // Env var names: allow-listed names by kind; every other credential-shaped name is a count.
  const byKind = new Map();
  let other = 0;
  for (const name of Object.keys(env || {})) {
    if (typeof env[name] !== "string" || !env[name]) continue;
    const k = Object.prototype.hasOwnProperty.call(CREDENTIAL_ENV_NAMES, name) ? CREDENTIAL_ENV_NAMES[name] : null;
    if (k) { if (!byKind.has(k)) byKind.set(k, []); byKind.get(k).push(name); }
    else if (CREDENTIAL_ENV_SHAPE.test(name)) other++;
  }
  for (const [k, names] of byKind) items.push(blank(k, "env", "env", { envNames: names.sort().slice(0, MAX_ENV_NAMES) }));
  if (other) items.push(blank("env", "env", "env", { envOtherCount: other }));
  // AI keys at rest: one item per keyHash and location class.
  let keys = [];
  try { keys = typeof keysAtRest === "function" ? keysAtRest({ home }) || [] : []; } catch { keys = []; }
  const seenKeys = new Set();
  for (const f of keys) {
    if (!f || typeof f.keyHash !== "string") continue;
    const fixed = typeof f.location === "string" && f.location.startsWith("~/");
    const scope = fixed ? "home" : typeof f.path === "string" && cwd && isWithin(f.path, cwd, platform) ? "project" : "outside-project";
    const lc = fixed ? "home-config" : "project-file";
    const k = `${lc}|${scope}|${f.keyHash}`;
    if (seenKeys.has(k)) continue;
    seenKeys.add(k);
    items.push(blank("ai-key", lc, scope, { keyHash: f.keyHash }));
  }
  return items;
}

const hourIso = (ms) => new Date(Math.floor(ms / 3600_000) * 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
const LC_OF_SCOPE = { home: "home-config", project: "project-file", "outside-project": "project-file", system: "system", env: "env" };
const hasReads = (i) => Object.values(i.byHost).some((b) => b.reads > 0);
const outside = (i) => Object.values(i.byHost).some((b) => b.outsideProjectReads > 0);
const rank = (i) => (hasReads(i) ? 0 : i.prodLike ? 1 : outside(i) ? 2 : 3);

// The heartbeat field. Default keysAtRest is the existing AIBOM scan; tests inject one.
export function credentialExposure({ home = homedir(), env = process.env, cwd = "", stateDir = join(home, ".moorai"), now = Date.now(), keysAtRest = defaultKeysAtRest, platform = process.platform } = {}) {
  const items = credentialInventory({ home, env, cwd, platform, keysAtRest });
  const to = Math.floor(now / 3600_000) * 3600_000 + 3600_000, from = to - WINDOW_MS;
  const entries = readEntries(stateDir).filter((e) => e.ts >= from && e.ts <= now);
  const egress = entries.filter((e) => e.t === "e" && Array.isArray(e.d));
  for (const r of entries) {
    if (r.t !== "r" || !KINDS.includes(r.k) || !SCOPES.includes(r.sc)) continue;
    let item = items.find((i) => i.kind === r.k && i.scope === r.sc && i.locationClass !== "env");
    if (!item) { item = blank(r.k, LC_OF_SCOPE[r.sc] || "project-file", r.sc, { reachable: false }); items.push(item); }
    const host = typeof r.h === "string" && r.h ? r.h : "unknown";
    if (!item.byHost[host]) {
      if (Object.keys(item.byHost).length >= MAX_HOSTS) continue;
      item.byHost[host] = { reads: 0, lastReadAt: null, outsideProjectReads: 0, sentTo: [] };
    }
    const b = item.byHost[host];
    b.reads++;
    const at = hourIso(r.ts);
    if (!b.lastReadAt || at > b.lastReadAt) b.lastReadAt = at;
    if (r.sc === "outside-project") b.outsideProjectReads++;
    if (r.s) for (const e of egress) if (e.s === r.s && e.ts >= r.ts && e.ts - r.ts <= SENT_WINDOW_MS) for (const d of e.d) if (DEST_CLASSES.includes(d) && !b.sentTo.includes(d)) b.sentTo.push(d);
  }
  for (const i of items) for (const b of Object.values(i.byHost)) b.sentTo.sort();
  const sorted = items.map((i, n) => [i, n]).sort((a, b) => rank(a[0]) - rank(b[0]) || a[1] - b[1]).map((x) => x[0]);
  return { v: 1, coverage: "heuristic", window: { from: hourIso(from), to: hourIso(to) }, items: sorted.slice(0, MAX_ITEMS), truncated: sorted.length > MAX_ITEMS };
}

// The posture body, fitted under the console's size cap: items drop from the tail (the lowest priority, the
// order credentialExposure sorts them in) until the serialized body fits, then the field goes entirely.
export function fitPostureBody(body, limit = POSTURE_FIT_LIMIT) {
  const size = (b) => Buffer.byteLength(JSON.stringify(b));
  if (!body || !body.credentialExposure || size(body) <= limit) return body;
  const ce = { ...body.credentialExposure, items: [...(body.credentialExposure.items || [])], truncated: true };
  const out = { ...body, credentialExposure: ce };
  while (ce.items.length && size(out) > limit) ce.items.pop();
  if (!ce.items.length || size(out) > limit) { const { credentialExposure: _drop, ...rest } = out; return rest; }
  return out;
}

