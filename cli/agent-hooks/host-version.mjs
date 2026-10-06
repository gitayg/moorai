// Which version of each agent host is running, and was MoorAI's adapter tested against it.
// The tested versions live in ONE place, data/host-versions.json; the adapters' source comments point
// there. Used by cli/agent-posture.mjs (the daily, content-free posture beat) and
// scripts/host-drift.mjs (the nightly CI drift job). Never called on the hook's verdict path.
//
// Detection order, cheapest and most specific first:
//   1. An env var the host sets for its hook processes — read ONLY for the host that is calling,
//      because hook env is inherited (a cursor-agent run inside a Claude Code shell still carries
//      Claude's AI_AGENT). See ENV_SOURCES for what each host provides, with citations.
//   2. A no-spawn PATH probe: resolve the host's binary on PATH, follow symlinks, and read the version
//      from the install path (native installers keep versions/<ver>/) or from the nearest package.json
//      whose name is the host's npm package.
//   3. `<bin> --version`, 3 s timeout. Only from the posture beat (at most once per host per day), and
//      cached by the binary's real path + mtime so an upgrade invalidates it.
// Nothing here throws: every failure is "version unknown", which reports as tested:false.
import { readFileSync, writeFileSync, mkdirSync, realpathSync, statSync, existsSync } from "node:fs";
import { join, dirname, delimiter } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

export const MANIFEST_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "data", "host-versions.json");

let manifestCache = null;
export function loadManifest(file = MANIFEST_PATH) {
  if (file === MANIFEST_PATH && manifestCache) return manifestCache;
  let m;
  try { m = JSON.parse(readFileSync(file, "utf8")); } catch { m = { v: 1, hosts: {} }; }
  if (!m || typeof m.hosts !== "object" || !m.hosts) m = { v: 1, hosts: {} };
  if (file === MANIFEST_PATH) manifestCache = m;
  return m;
}

// A version string that may leave the device: digits and dots, an optional short build suffix.
const VERSION_RE = /\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z][0-9A-Za-z.]{0,23})?/;
const VERSION_ONLY = new RegExp(`^${VERSION_RE.source}$`);
export function parseVersion(text) {
  const m = VERSION_RE.exec(String(text ?? ""));
  return m ? m[0] : null;
}
export const cleanVersion = (v) => (typeof v === "string" && v.length <= 40 && VERSION_ONLY.test(v) ? v : null);
export const coreOf = (v) => (cleanVersion(v) || "").split("-")[0];

export function compareVersions(a, b) {
  const pa = coreOf(a).split(".").map(Number), pb = coreOf(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// tested = the running version's numeric core equals the manifest's. Older and newer both count as
// untested: an older host may lack a field the adapter relies on just as a newer one may drop it.
export function isTested(host, version, manifest = loadManifest()) {
  const want = manifest.hosts?.[host]?.tested;
  if (!cleanVersion(version) || !cleanVersion(want)) return false;
  return coreOf(version) === coreOf(want);
}

// What each host hands its hook processes, as measured or quoted:
//   claude-code  AI_AGENT="claude-code_2-1-284_harness" (dots as dashes). Measured 2026-10-06: Claude
//                Code 2.1.284 run with a SessionStart/UserPromptSubmit hook that dumped `env` (model
//                endpoint pointed at a dead local port). The binary sets it at startup
//                (`process.env.AI_AGENT = "claude-code_" + VERSION.replace(/\./g,"-") + "_harness"`) and
//                spreads process.env into hook env. Undocumented. The hook stdin carries no version.
//   cursor       CURSOR_VERSION, and `cursor_version` on every hook payload. cursor-agent
//                2026.05.27-fe9a6e2 3880.index.js buildHookEnvironment(): {CURSOR_PROJECT_DIR,
//                CURSOR_VERSION: globalContext.cursor_version, ...}; cursor.com/docs/hooks.md lists
//                cursor_version among the common input fields. In the IDE it is the IDE's version.
//   codex, gemini, copilot: no version in hook env or payload (see the per-host notes below).
const ENV_SOURCES = {
  "claude-code": (env) => {
    const m = /^claude-code[_/](\d+(?:-\d+){1,3})(?:_|$)/.exec(String(env.AI_AGENT || ""));
    return m ? m[1].replace(/-/g, ".") : null;
  },
  cursor: (env) => {
    const v = cleanVersion(String(env.CURSOR_VERSION || "").trim());
    return v === "1.0.0" ? null : v; // cursor-agent's own fallback when it has no version
  }
};
export function versionFromEnv(host, env = process.env) {
  try { return cleanVersion((ENV_SOURCES[host] || (() => null))(env || {})); } catch { return null; }
}

function onPath(bin, env) {
  const exts = process.platform === "win32" ? ["", ".cmd", ".exe", ".ps1"] : [""];
  for (const dir of String(env.PATH || env.Path || "").split(delimiter)) {
    if (!dir) continue;
    for (const e of exts) {
      const p = join(dir, bin + e);
      try { if (statSync(p).isFile()) return p; } catch { /* next */ }
    }
  }
  return null;
}

// The version from where the binary really lives, without running it.
export function versionFromInstallPath(real, npmName) {
  const seg = /[\\/]versions[\\/]([^\\/]+)/.exec(real) || /[\\/](?:Caskroom|Cellar)[\\/][^\\/]+[\\/]([^\\/]+)/.exec(real);
  if (seg && cleanVersion(seg[1])) return seg[1];
  if (!npmName) return null;
  let dir = dirname(real);
  for (let i = 0; i < 6; i++) {
    const pj = join(dir, "package.json");
    if (existsSync(pj)) {
      try { const j = JSON.parse(readFileSync(pj, "utf8")); if (j && j.name === npmName) return cleanVersion(j.version); } catch { /* keep walking */ }
    }
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

// Full probe for one host: PATH resolve -> install path -> `--version` (optional). Returns
// { version, source } where source is "path" | "spawn" | null. A `--version` answer is cached by the
// binary's real path + mtime.
export function probeVersion(host, { env = process.env, manifest = loadManifest(), stateDir = null, spawn = true, timeoutMs = 3000 } = {}) {
  const m = manifest.hosts?.[host];
  if (!m || !m.bin) return { version: null, source: null };
  try {
    const bin = onPath(m.bin, env || {});
    if (!bin) return { version: null, source: null };
    let real = bin;
    try { real = realpathSync(bin); } catch { /* use as is */ }
    const mtime = (() => { try { return statSync(real).mtimeMs; } catch { return 0; } })();
    const cacheFile = stateDir ? join(stateDir, "host-version-cache.json") : null;
    let cache = {};
    if (cacheFile) { try { cache = JSON.parse(readFileSync(cacheFile, "utf8")) || {}; } catch { cache = {}; } }
    const hit = cache[host];
    if (hit && hit.real === real && hit.mtime === mtime && (hit.version === null || cleanVersion(hit.version))) return { version: hit.version, source: hit.source };
    let version = versionFromInstallPath(real, m.npm), source = version ? "path" : null;
    if (!version && spawn) {
      const r = spawnSync(bin, ["--version"], { env, encoding: "utf8", timeout: timeoutMs, input: "", shell: process.platform === "win32" && /\.(cmd|ps1)$/i.test(bin), windowsHide: true });
      version = r.status === 0 ? cleanVersion(parseVersion(r.stdout)) : null;
      source = version ? "spawn" : null;
    }
    // Only a spawned answer is worth caching (the path probe is a few stats); writing nothing in the
    // common case also keeps the detached beat worker from touching the state dir at all.
    if (cacheFile && spawn && source !== "path") {
      try { mkdirSync(stateDir, { recursive: true }); cache[host] = { real, mtime, version, source }; writeFileSync(cacheFile, JSON.stringify(cache), { mode: 0o600 }); } catch { /* cache is an optimisation */ }
    }
    return { version, source };
  } catch { return { version: null, source: null }; }
}

// The posture beat's answer for one host: env (caller only), then the probe.
export function hostVersion(host, { caller = "", env = process.env, manifest = loadManifest(), stateDir = null, spawn = true } = {}) {
  const fromEnv = host === caller ? versionFromEnv(host, env) : null;
  const version = fromEnv || probeVersion(host, { env, manifest, stateDir, spawn }).version;
  return { version: version || null, tested: isTested(host, version, manifest) };
}
