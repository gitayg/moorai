// First-seen MCP server reputation — the on-device half: identify the server from its launch config,
// collect signals, cache the result per server identity + version, and re-score when the version moves.
// data/mcp-reputation.js holds the pure scoring, the policy action and the alert shape.
//
// WHERE THE SIGNALS COME FROM, and which of them leave the device:
//
//   always, offline   the package NAME against the known-malicious / popular-library list
//                     (data/popular-packages.js, via nameFindings) and the popular MCP server list
//                     (data/popular-mcp-servers.js); an unpinned `npx -y pkg`; a local / docker / remote /
//                     unresolvable launch. Nothing is fetched.
//   always, offline   the INSTALLED copy npx already put on disk (~/.npm/_npx/*/node_modules/<name>) is
//                     read with the same package heuristics and scoped engine scan SkillTriage runs
//                     (install scripts, remote code, credential reads with egress, obfuscation…).
//   proxy only        tool-stage findings on the server's own tools/list (#60 poisoning, #50 hidden
//                     content), handed in by mcp-proxy/moorai-mcp-guard.mjs through addToolSignals.
//   OPT-IN lookup     policy.mcpReputation.lookup = "registry": MoorAI's analyzePackage fetches the exact
//                     registry artifact. Only the public package name (and version) reaches the public
//                     registry — the same request npx/uvx makes to install it. Adds new-package,
//                     name-not-published and whatever the downloaded code shows. In parallel,
//                     cli/mcp-repo-link.mjs checks the repository the package declares (registry
//                     provenance, else the repository's own manifest on github.com / gitlab.com):
//                     repo-missing, repo-unreachable, repo-mismatch. Public package and repo names only.
//                     And cli/mcp-package/maintainers.mjs counts who can publish (npm packument
//                     `maintainers`, PyPI `ownership.roles`): single-maintainer. Counted, never kept.
//   OPT-IN feed       policy.mcpReputation.feed = true (or an https URL): SkillTriage's published
//                     verdicts, downloaded WHOLE with a bare GET and matched here. The request names no
//                     server, so the feed host learns only that a MoorAI device fetched the feed.
//
// Local paths, arguments and environment variables are never sent anywhere; a local path or a remote URL
// is hashed even in the on-device cache key, and a URL's query string never enters it at all.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, mkdirSync, readdirSync, lstatSync, statSync, openSync, readSync, closeSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveLaunch } from "./mcp-package/resolve.mjs";
import { nameFindings, packageHeuristics } from "./mcp-package/heuristics.mjs";
import { scanPackageFiles } from "./mcp-package/scope.mjs";
import { analyzePackage } from "./mcp-package.mjs";
import { checkRepoLink } from "./mcp-repo-link.mjs";
import { checkMaintainers } from "./mcp-package/maintainers.mjs";
import { buildEngine } from "./hook-core.mjs";
import { STATE_DIR } from "./state-dirs.mjs";
import { scoreReputation, signal, classifyMcpName, reputationAction, reputationAlert, REASON_WEIGHTS, TIER_WEIGHT } from "../data/mcp-reputation.js";

export const DEFAULT_FEED_URL = "https://skilltriage.moorai.dev/api/reputation-feed.json";
export const CACHE_FILE = "mcp-reputation.json";
export const FEED_FILE = "mcp-reputation-feed.json";
const FEED_TTL_MS = 24 * 3600 * 1000;
const MAX_FEED_BYTES = 8 * 1024 * 1024;
const MAX_ENTRIES = 512;
const MAX_FILES = 2000;
const MAX_DEPTH = 12;
const MAX_NPX_DIRS = 500;

const SELF = dirname(fileURLToPath(import.meta.url));
// The rules revision: a change to the scoring, the name lists or the package heuristics re-scores every
// cached server instead of serving a verdict computed under older rules.
const REP_REV = (() => {
  const h = createHash("sha256");
  for (const f of ["mcp-reputation.mjs", "mcp-package/heuristics.mjs", "mcp-package/scope.mjs", "../data/mcp-reputation.js", "../data/popular-mcp-servers.js", "../data/popular-packages.js", "../data/detectors.js", "mcp-repo-link.mjs", "../data/repo-link.js", "mcp-package/maintainers.mjs", "mcp-package/metadata.mjs"]) {
    try { h.update(readFileSync(join(SELF, f))); } catch { h.update(f); }
  }
  return h.digest("hex").slice(0, 16);
})();

const sha = (s) => createHash("sha256").update(String(s)).digest("hex").slice(0, 16);

// ---- identity ----------------------------------------------------------------------------------

// A server already wrapped by `mcp-proxy/install.mjs` is `node …/moorai-mcp-guard.mjs [--server x] -- real…`.
function unwrapGuard(argv) {
  const i = argv.findIndex((a) => /moorai-mcp-guard\.mjs$/.test(String(a)));
  if (i < 0) return argv;
  const sep = argv.indexOf("--", i);
  return sep >= 0 ? argv.slice(sep + 1) : argv;
}

function remoteKey(url) {
  try { const u = new URL(url); return `remote:${sha(u.protocol + "//" + u.host + u.pathname)}`; } catch { return `remote:${sha("invalid")}`; }
}

// decl = { command, args } | { url } (a config entry; env is never read) → identity.
export function serverIdentity(decl) {
  const d = decl || {};
  if (typeof d.url === "string" && d.url) return { kind: "remote", key: remoteKey(d.url), ref: null };
  const argv = unwrapGuard([d.command, ...(Array.isArray(d.args) ? d.args : [])].filter((x) => x != null).map(String));
  if (!argv.length) return { kind: "unknown", key: `unknown:${sha("")}`, ref: null };
  const ref = resolveLaunch(argv);
  if (ref.ecosystem === "npm" || ref.ecosystem === "pypi") {
    return { kind: ref.ecosystem, key: `${ref.ecosystem}:${String(ref.name).toLowerCase()}`, ref, pinned: !!ref.version };
  }
  if (ref.ecosystem === "local") return { kind: "local", key: `local:${sha(ref.path)}`, ref, entry: ref.path };
  if (ref.ecosystem === "docker") return { kind: "docker", key: `docker:${sha(ref.name)}`, ref };
  return { kind: "unknown", key: `unknown:${sha(ref.runner || argv[0])}`, ref };
}

// ---- the installed copy ------------------------------------------------------------------------

function readJson(p) { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } }

// The newest ~/.npm/_npx/<hash>/node_modules/<name> whose version matches the pin (any, if unpinned).
export function findInstalledNpm(name, version, home = homedir()) {
  const root = join(home, ".npm", "_npx");
  let dirs;
  try { dirs = readdirSync(root).slice(0, MAX_NPX_DIRS); } catch { return null; }
  let best = null;
  for (const h of dirs) {
    const dir = join(root, h, "node_modules", ...String(name).split("/"));
    const pkg = readJson(join(dir, "package.json"));
    if (!pkg || typeof pkg.version !== "string") continue;
    if (version && pkg.version !== version) continue;
    let mtime = 0;
    try { mtime = statSync(join(dir, "package.json")).mtimeMs; } catch { /* keep 0 */ }
    if (!best || mtime > best.mtime) best = { dir, version: pkg.version, mtime };
  }
  return best;
}

// Bounded, symlink-free walk that skips nested dependency trees.
function walk(root) {
  const out = [];
  const rec = (dir, depth) => {
    if (depth > MAX_DEPTH || out.length >= MAX_FILES) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= MAX_FILES) return;
      if (e.name === "node_modules" || e.name === ".git") continue;
      const full = join(dir, e.name);
      let st;
      try { st = lstatSync(full); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) rec(full, depth + 1);
      else if (st.isFile()) out.push(full);
    }
  };
  rec(root, 0);
  return out;
}

let ENGINE = null;
function engineFor(opts) { return opts.engine || ENGINE || (ENGINE = buildEngine({})); }

function findingSignal(f) {
  const code = typeof f.threatId === "string" ? f.threatId : `threat-${f.threatId}`;
  return signal(code, REASON_WEIGHTS[code] ?? TIER_WEIGHT[f.tier] ?? 0);
}

function scanInstalled(dir, opts) {
  const files = walk(dir);
  const scoped = scanPackageFiles(dir, files, { engine: engineFor(opts), policy: {} });
  return [...scoped.findings, ...packageHeuristics(dir, files)].map(findingSignal);
}

// First 1 MB of a local entry file: an edit to the script is a new version.
function fileVersion(path) {
  try {
    const fd = openSync(path, "r");
    try { const b = Buffer.alloc(1024 * 1024); const n = readSync(fd, b, 0, b.length, 0); return sha(b.subarray(0, n)); } finally { closeSync(fd); }
  } catch { return "missing"; }
}

// ---- offline signals: identity + name lists + installed copy ------------------------------------
function baseSignals(id, opts) {
  const signals = [], evidence = [];
  let version = null;
  if (id.kind === "npm" || id.kind === "pypi") {
    for (const f of nameFindings(id.ref)) signals.push(findingSignal(f));
    const c = classifyMcpName(id.ref.name, id.kind);
    if (c === "listed") evidence.push("catalogue-listed");
    else if (c === "typosquat") signals.push(signal("mcp-typosquat"));
    if (!id.pinned) signals.push(signal("unpinned-version"));
    version = id.ref.version || null;
    if (id.kind === "npm") {
      const inst = findInstalledNpm(id.ref.name, id.ref.version, opts.home);
      if (inst) {
        version = inst.version;
        signals.push(...scanInstalled(inst.dir, opts));
        evidence.push("installed-copy-scanned");
      }
    }
    return { signals, evidence, version: version || "unresolved" };
  }
  if (id.kind === "local") return { signals: [signal("local-source")], evidence, version: fileVersion(id.entry) };
  if (id.kind === "docker") return { signals: [signal("docker-image")], evidence, version: "image" };
  if (id.kind === "remote") return { signals: [signal("remote-server")], evidence, version: "remote" };
  return { signals: [signal("unresolved-launch")], evidence, version: "unknown" };
}

// ---- opt-in registry lookup ---------------------------------------------------------------------
const LOOKUP_NOTES = { "new-package": "new-package", "integrity-mismatch": "integrity-mismatch" };
async function registryLookup(id, opts) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const [e, link, maint] = await Promise.all([
    analyzePackage(id.ref, { fetchImpl, cacheDir: opts.stateDir || STATE_DIR, engine: engineFor(opts) }),
    checkRepoLink(id.ref, { fetchImpl }).catch(() => ({ signals: [], evidence: ["repo-check-failed"] })),
    checkMaintainers(id.ref, { fetchImpl }).catch(() => ({ signals: [], evidence: ["maintainers-check-failed"] }))
  ]);
  const signals = [...(e.findings || []).map(findingSignal), ...link.signals.map((c) => signal(c)), ...maint.signals.map((c) => signal(c))];
  const evidence = [...link.evidence, ...maint.evidence];
  for (const n of e.notes || []) {
    if (LOOKUP_NOTES[n.id]) signals.push(signal(LOOKUP_NOTES[n.id]));
    // A scoped npm 404 may just be a private package; an unscoped one, or PyPI, is a claimable name.
    if (n.id === "registry-http-404" && !(id.kind === "npm" && String(id.ref.name).startsWith("@"))) signals.push(signal("name-not-published"));
  }
  evidence.push(e.analysed ? "registry-analysed" : "registry-not-analysed");
  return { signals, evidence };
}

// ---- opt-in SkillTriage feed ----------------------------------------------------------------------
function feedUrl(policy) {
  if (policy.feed === true) return DEFAULT_FEED_URL;
  if (typeof policy.feed !== "string") return null;
  try {
    const u = new URL(policy.feed);
    const loop = u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost");
    return u.protocol === "https:" || loop ? u.origin + u.pathname : null;
  } catch { return null; }
}

function validFeed(f) { return f && f.feed === "skilltriage-mcp-reputation" && Array.isArray(f.entries); }

function readFeedFile(stateDir) {
  const f = readJson(join(stateDir, FEED_FILE));
  return f && validFeed(f.feed) ? f : null;
}

async function refreshFeed(url, opts, stateDir) {
  const cur = readFeedFile(stateDir);
  const now = opts.now || Date.now();
  if (cur && cur.url === url && now - cur.fetchedAt < FEED_TTL_MS) return cur.feed;
  try {
    const res = await (opts.fetchImpl || globalThis.fetch)(url, { method: "GET", redirect: "error", signal: AbortSignal.timeout(5000) });
    if (!res || !res.ok) return cur ? cur.feed : null;
    const text = await res.text();
    if (text.length > MAX_FEED_BYTES) return cur ? cur.feed : null;
    const feed = JSON.parse(text);
    if (!validFeed(feed)) return cur ? cur.feed : null;
    writeAtomic(join(stateDir, FEED_FILE), { url, fetchedAt: now, feed });
    return feed;
  } catch { return cur ? cur.feed : null; }
}

const FEED_VERDICT = { "DO-NOT-INSTALL": "catalogue-do-not-install", REVIEW: "catalogue-review", CAUTION: "catalogue-caution", "NAME-NOT-PUBLISHED": "catalogue-name-not-published" };
function feedSignals(feed, id, version) {
  if (!feed || !(id.kind === "npm" || id.kind === "pypi")) return { signals: [], evidence: [] };
  const name = String(id.ref.name).toLowerCase();
  const e = feed.entries.find((x) => x && x.ecosystem === id.kind && String(x.name).toLowerCase() === name);
  if (!e) return { signals: [], evidence: [] };
  const known = version && version !== "unresolved";
  if (e.verdict !== "NAME-NOT-PUBLISHED" && known && e.version && e.version !== version) return { signals: [], evidence: ["catalogue-other-version"] };
  if (e.verdict === "CLEAN") return { signals: [], evidence: ["catalogue-clean"] };
  const code = FEED_VERDICT[e.verdict];
  return code ? { signals: [signal(code)], evidence: [] } : { signals: [], evidence: [] };
}

// moorai-mcp-check: SkillTriage's verdict for one registry package, only when the policy enables the feed.
// → {enabled: false} | {enabled: true, available, verdict, signals, evidence}
export async function feedVerdict(ref, { policy = {}, fetchImpl, stateDir = STATE_DIR, now } = {}) {
  const url = feedUrl(policy && typeof policy === "object" ? policy : {});
  if (!url) return { enabled: false };
  const feed = await refreshFeed(url, { fetchImpl, now }, stateDir);
  if (!feed) return { enabled: true, available: false, verdict: null, signals: [], evidence: [] };
  const id = { kind: ref.ecosystem, ref };
  const name = String(ref.name || "").toLowerCase();
  const e = feed.entries.find((x) => x && x.ecosystem === ref.ecosystem && String(x.name).toLowerCase() === name);
  const f = feedSignals(feed, id, ref.version || null);
  const otherVersion = f.evidence.includes("catalogue-other-version");
  return { enabled: true, available: true, verdict: e && !otherVersion ? e.verdict : null, ...(e && otherVersion ? { scannedVersion: e.version } : {}), signals: f.signals, evidence: f.evidence };
}

// ---- tool-stage signals ---------------------------------------------------------------------------
export function toolCode(f) {
  const t = Number(f && f.threatId);
  return t === 60 ? "tool-poisoning" : t === 50 ? "tool-hidden-content" : "tool-metadata";
}

// ---- cache ------------------------------------------------------------------------------------
function writeAtomic(path, obj) {
  try {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(obj));
    renameSync(tmp, path);
  } catch { /* the cache is an optimisation; a failed write only means re-scoring next time */ }
}
function loadCache(stateDir) {
  const c = readJson(join(stateDir, CACHE_FILE));
  return c && c.v === 1 && c.servers && typeof c.servers === "object" ? c : { v: 1, servers: {} };
}
function saveCache(stateDir, cache) {
  const keys = Object.keys(cache.servers);
  if (keys.length > MAX_ENTRIES) {
    keys.sort((a, b) => String(cache.servers[a].scoredAt).localeCompare(String(cache.servers[b].scoredAt)));
    for (const k of keys.slice(0, keys.length - MAX_ENTRIES)) delete cache.servers[k];
  }
  writeAtomic(join(stateDir, CACHE_FILE), cache);
}

function present(id, entry, feed, flags) {
  const f = feedSignals(feed, id, entry.version);
  const lookup = entry.lookup || { signals: [], evidence: [] };
  const tools = (entry.tools || []).map((c) => signal(c));
  const r = scoreReputation([...entry.base, ...lookup.signals, ...f.signals, ...tools]);
  return {
    key: id.key, kind: id.kind, versionHash: entry.ver, ...r,
    evidence: [...new Set([...entry.evidence, ...lookup.evidence, ...f.evidence])].sort(),
    scoredAt: entry.scoredAt, firstSeenAt: entry.firstSeenAt, ...flags
  };
}

function core(decl, opts, lookupResult) {
  const stateDir = opts.stateDir || STATE_DIR;
  const policy = opts.policy && typeof opts.policy === "object" ? opts.policy : {};
  const id = serverIdentity(decl);
  const cache = loadCache(stateDir);
  const prior = cache.servers[id.key];
  const b = baseSignals(id, { ...opts, home: opts.home || homedir() });
  const ver = sha(`${id.key}\0${b.version}`);
  const wantLookup = policy.lookup === "registry" && (id.kind === "npm" || id.kind === "pypi");
  if (prior && prior.ver === ver && prior.rev === REP_REV && (!wantLookup || prior.lookup) && !lookupResult) {
    return { id, cache, entry: prior, flags: { cached: true, firstSeen: false, versionChanged: false }, needLookup: false };
  }
  const now = new Date(opts.now || Date.now()).toISOString();
  const sameVersion = prior && prior.ver === ver;
  const entry = {
    ver, rev: REP_REV, version: b.version, base: b.signals, evidence: b.evidence,
    lookup: lookupResult || (sameVersion && prior.rev === REP_REV ? prior.lookup || null : null),
    tools: sameVersion ? prior.tools || [] : [],
    firstSeenAt: prior ? prior.firstSeenAt : now, scoredAt: now
  };
  return { id, cache, entry, flags: { cached: false, firstSeen: !prior, versionChanged: !!prior && prior.ver !== ver }, needLookup: wantLookup && !entry.lookup };
}

// Offline only: no network, ever. The AIBOM / shadow path.
export function assessServerSync(decl, opts = {}) {
  const stateDir = opts.stateDir || STATE_DIR;
  const r = core(decl, opts, null);
  if (!r.flags.cached) { r.cache.servers[r.id.key] = r.entry; saveCache(stateDir, r.cache); }
  const f = readFeedFile(stateDir);
  return present(r.id, r.entry, f ? f.feed : null, r.flags);
}

// The proxy / hook path. Network only when the org policy opts in (lookup and/or feed).
export async function assessServer(decl, opts = {}) {
  const stateDir = opts.stateDir || STATE_DIR;
  const policy = opts.policy && typeof opts.policy === "object" ? opts.policy : {};
  let r = core(decl, opts, null);
  if (r.needLookup) {
    let lookup;
    try { lookup = await registryLookup(r.id, opts); } catch { lookup = { signals: [], evidence: ["registry-not-analysed"] }; }
    const flags = r.flags;
    r = core(decl, opts, lookup);
    r.flags = flags;
  }
  if (!r.flags.cached) { r.cache.servers[r.id.key] = r.entry; saveCache(stateDir, r.cache); }
  const url = feedUrl(policy);
  const feed = url ? await refreshFeed(url, opts, stateDir) : (readFeedFile(stateDir) || {}).feed || null;
  return present(r.id, r.entry, feed, r.flags);
}

// Tool-stage findings from the server's own tools/list → merged into its cached entry and re-scored.
// `changed` is true only when a code this entry did not already carry was added.
export function addToolSignals(decl, findings, opts = {}) {
  const stateDir = opts.stateDir || STATE_DIR;
  const r = core(decl, opts, null);
  const have = new Set(r.entry.tools || []);
  let changed = false;
  for (const f of findings || []) { const c = toolCode(f); if (!have.has(c)) { have.add(c); changed = true; } }
  r.entry.tools = [...have].sort();
  if (changed || !r.flags.cached) { r.cache.servers[r.id.key] = r.entry; saveCache(stateDir, r.cache); }
  const f = readFeedFile(stateDir);
  return { ...present(r.id, r.entry, f ? f.feed : null, r.flags), changed };
}

// ---- config lookup: a hook sees `mcp__<server>__<tool>`, i.e. only the label ----------------------
function desktopConfig(home) {
  if (process.platform === "darwin") return join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  if (process.platform === "win32") return join(process.env.APPDATA || join(home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
  return join(home, ".config", "Claude", "claude_desktop_config.json");
}

function pick(cfg) {
  if (!cfg || typeof cfg !== "object") return null;
  if (typeof cfg.url === "string" && cfg.url) return { url: cfg.url };
  if (typeof cfg.command === "string" && cfg.command) return { command: cfg.command, args: Array.isArray(cfg.args) ? cfg.args.map(String) : [] };
  return null;
}

// → { command, args } | { url } | null. Command and args only; env is never copied out.
export function findServerDecl(name, { home = homedir(), cwd = process.cwd() } = {}) {
  const maps = [];
  const claude = readJson(join(home, ".claude.json"));
  if (claude) {
    if (claude.projects && claude.projects[cwd]) maps.push(claude.projects[cwd].mcpServers);
    maps.push(claude.mcpServers);
    if (claude.projects) for (const p of Object.values(claude.projects)) maps.push(p && p.mcpServers);
  }
  const proj = readJson(join(cwd, ".mcp.json"));
  if (proj) maps.push(proj.mcpServers);
  const cursor = readJson(join(home, ".cursor", "mcp.json"));
  if (cursor) maps.push(cursor.mcpServers);
  const desk = readJson(desktopConfig(home));
  if (desk) maps.push(desk.mcpServers);
  for (const m of maps) {
    if (m && typeof m === "object" && Object.prototype.hasOwnProperty.call(m, name)) {
      const d = pick(m[name]);
      if (d) return d;
    }
  }
  return null;
}

// The Claude Code hook's entry point. The hook sees only `mcp__<label>__<tool>`, so the label is resolved
// to its launch config first; an unconfigured label, or the off switch, returns null (fail open). OFFLINE
// only — a hook runs once per tool call and must not wait on a registry — so the opt-in registry lookup
// is the proxy's job; a feed the proxy already downloaded is still matched here.
// → null | { action: "allow"|"alert"|"block"|"coach", rep, report, alert }
//   report = first sight or a version change (post `alert` then; later calls stay quiet).
export function hookReputation(label, { policy = {}, enforce = false, home = homedir(), cwd = process.cwd(), stateDir = STATE_DIR, identityHash = null } = {}) {
  const p = policy && typeof policy === "object" ? policy : {};
  if (p.enabled === false) return null;
  const decl = findServerDecl(label, { home, cwd });
  if (!decl) return null;
  const rep = assessServerSync(decl, { home, stateDir });
  const action = reputationAction(rep, p, { enforce });
  const report = (rep.firstSeen || rep.versionChanged) && action !== "allow";
  const alert = reputationAlert(rep, { server: label, decision: action, identityHash: identityHash ? identityHash(`mcp-reputation:${rep.key}`) : "", tool: `hook:mcp__${label}` });
  return { action, rep, report, alert };
}

export { REP_REV };
