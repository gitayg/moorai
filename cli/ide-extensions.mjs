// Installed IDE-extension scanning: the extensions already on disk in VS Code, VS Code Insiders,
// VSCodium, Cursor, Windsurf, Kiro (and VS Code Server), plus JetBrains IDE plugins. Report-only.
//
// What is checked, per extension (VS Code family):
//   ide-ext-known-malicious          exact id + version in a public advisory (data/ide-extension-advisories.js)
//   ide-ext-invisible-code           a bundled script holds a run of >= 16 invisible Unicode selectors
//                                    (U+FE00-FE0F, U+E0000-E01EF): the GlassWorm loader technique;
//                                    a lone emoji selector never comes close
//   ide-ext-typosquat                near-miss of a widely installed id (data/popular-ide-extensions.js)
//   ide-ext-publisher-impersonation  a widely installed extension's name under another publisher
//   ide-ext-sideloaded               the editor's extensions.json records the install source as "vsix"
// JetBrains plugins are inventoried (id + version from META-INF/plugin.xml inside the plugin jar) and
// classified as AI or not; the checks above need a reference list that exists only for the VS Code family.
//
// Content-free: the result carries editor family, extension id, version, AI flag, install source, codes,
// risk and advisory ids. Never a path, a file name inside an extension, or file contents. Reads are
// bounded per file, per extension and per run, and a skipped file sets `truncated`.
import { readFileSync, readdirSync, lstatSync, statSync } from "node:fs";
import { join, dirname, extname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { knownBadExtension } from "../data/ide-extension-advisories.js";
import { POPULAR_IDE_EXTENSIONS } from "../data/popular-ide-extensions.js";
import { FileSource } from "./model-scan-bytes.mjs";
import { zipEntries, readEntry } from "./model-scan-zip.mjs";

const SELF = dirname(fileURLToPath(import.meta.url));
export const IDE_LIMITS = Object.freeze({
  maxExtensionsPerRoot: 2000, maxFilesPerExtension: 400, maxDepth: 10,
  maxFileBytes: 8 * 1024 * 1024, maxExtensionBytes: 48 * 1024 * 1024, maxTotalBytes: 512 * 1024 * 1024,
  maxJarsPerPlugin: 50, maxPluginXmlBytes: 512 * 1024
});
export const INVISIBLE_RUN_MIN = 16;
const SCRIPT_EXT = new Set([".js", ".cjs", ".mjs"]);
const CODE_ORDER = ["ide-ext-known-malicious", "ide-ext-invisible-code", "ide-ext-typosquat", "ide-ext-publisher-impersonation", "ide-ext-sideloaded"];
const CODE_RISK = { "ide-ext-known-malicious": "critical", "ide-ext-invisible-code": "high", "ide-ext-typosquat": "medium", "ide-ext-publisher-impersonation": "medium", "ide-ext-sideloaded": "low" };
const RISK_RANK = ["none", "low", "medium", "high", "critical"];

// ---- roots ----------------------------------------------------------------------------------------

const VSCODE_FAMILY = [
  ["vscode", ".vscode/extensions"], ["vscode-insiders", ".vscode-insiders/extensions"], ["vscode-server", ".vscode-server/extensions"],
  ["vscodium", ".vscode-oss/extensions"], ["vscodium", ".vscodium/extensions"], ["cursor", ".cursor/extensions"],
  ["windsurf", ".windsurf/extensions"], ["kiro", ".kiro/extensions"]
];

export function ideExtensionRoots({ home = homedir(), platform = process.platform, env = process.env } = {}) {
  const roots = VSCODE_FAMILY.map(([editor, rel]) => ({ editor, kind: "vscode", dir: join(home, ...rel.split("/")) }));
  if (platform === "darwin") roots.push({ editor: "jetbrains", kind: "jetbrains", dir: join(home, "Library", "Application Support", "JetBrains"), sub: "plugins" });
  else if (platform === "win32") roots.push({ editor: "jetbrains", kind: "jetbrains", dir: join((env && env.APPDATA) || join(home, "AppData", "Roaming"), "JetBrains"), sub: "plugins" });
  else roots.push({ editor: "jetbrains", kind: "jetbrains", dir: join(home, ".local", "share", "JetBrains"), sub: null });
  return roots;
}

// ---- classifiers ----------------------------------------------------------------------------------

function loadAiRegex() {
  const fallback = /copilot|continue|codeium|cody|tabnine|claude|cline|roo.?code|kilocode|supermaven|codegpt|amazon.*q|windsurf|augment|gemini|chatgpt|openai/i;
  try {
    const cat = JSON.parse(readFileSync(join(SELF, "..", "data", "ai-catalog.json"), "utf8"));
    const kws = (cat.extensions || []).flatMap((e) => (Array.isArray(e.keywords) ? e.keywords : [])).filter(Boolean);
    if (!kws.length) return fallback;
    return new RegExp(kws.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "i");
  } catch { return fallback; }
}
const AI_RE = loadAiRegex();

// Bounded Damerau-Levenshtein "distance <= max".
function withinEdit(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return false;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return false;
  }
  return d[a.length][b.length] <= max;
}

const POPULAR = new Set(POPULAR_IDE_EXTENSIONS);
const POPULAR_BY_NAME = new Map();
for (const id of POPULAR_IDE_EXTENSIONS) { const n = id.slice(id.indexOf(".") + 1); POPULAR_BY_NAME.set(n, [...(POPULAR_BY_NAME.get(n) || []), id]); }
const IMPERSONATION_MIN_NAME = 8;

// id (publisher.name) → [] | ["ide-ext-typosquat"] | ["ide-ext-publisher-impersonation"]
export function classifyExtensionId(id) {
  const k = String(id || "").toLowerCase();
  const dot = k.indexOf(".");
  if (dot < 1 || POPULAR.has(k)) return [];
  const name = k.slice(dot + 1);
  if (name.length >= IMPERSONATION_MIN_NAME && POPULAR_BY_NAME.has(name)) return ["ide-ext-publisher-impersonation"];
  const max = k.length >= 12 ? 2 : 1;
  for (const p of POPULAR) if (withinEdit(k, p, max)) return ["ide-ext-typosquat"];
  return [];
}

// Longest run of invisible selector code points (U+FE00-FE0F, U+E0000-E01EF) in a string.
const INVISIBLE = /(?:[\uFE00-\uFE0F]|\uDB40[\uDC00-\uDDEF])+/g;
export function invisibleRun(text) {
  let best = 0;
  for (const m of String(text).matchAll(INVISIBLE)) {
    const n = [...m[0]].length;
    if (n > best) best = n;
  }
  return best;
}

// ---- VS Code family -------------------------------------------------------------------------------

function readJson(p) { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } }
function listDir(p) { try { return readdirSync(p, { withFileTypes: true }); } catch { return []; } }

function scriptFiles(root, lim) {
  const out = [];
  const rec = (dir, depth) => {
    if (depth > lim.maxDepth || out.length >= lim.maxFilesPerExtension) return;
    for (const e of listDir(dir)) {
      if (out.length >= lim.maxFilesPerExtension) return;
      if (e.name === ".git") continue;
      const full = join(dir, e.name);
      let st;
      try { st = lstatSync(full); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) rec(full, depth + 1);
      else if (st.isFile() && SCRIPT_EXT.has(extname(e.name).toLowerCase())) out.push({ path: full, size: st.size });
    }
  };
  rec(root, 0);
  return out;
}

function invisibleScan(dir, lim, budget) {
  let used = 0;
  for (const f of scriptFiles(dir, lim)) {
    if (f.size > lim.maxFileBytes || used + f.size > lim.maxExtensionBytes || budget.left < f.size) { budget.truncated = true; continue; }
    let text;
    try { text = readFileSync(f.path, "utf8"); } catch { continue; }
    used += f.size; budget.left -= f.size;
    if (invisibleRun(text) >= INVISIBLE_RUN_MIN) return true;
  }
  return false;
}

function installSources(root) {
  const list = readJson(join(root, "extensions.json"));
  const out = new Map();
  if (!Array.isArray(list)) return out;
  for (const e of list) {
    const src = e && e.metadata && typeof e.metadata.source === "string" ? e.metadata.source : null;
    if (!src) continue;
    if (typeof e.relativeLocation === "string") out.set(`rel:${e.relativeLocation}`, src);
    if (e.identifier && typeof e.identifier.id === "string") out.set(`id:${e.identifier.id.toLowerCase()}@${e.version}`, src);
  }
  return out;
}

function riskOf(codes) {
  let r = 0;
  for (const c of codes) r = Math.max(r, RISK_RANK.indexOf(CODE_RISK[c] || "none"));
  return RISK_RANK[r];
}

function vscodeRoot(root, lim, budget, seen) {
  const out = [];
  const sources = installSources(root.dir);
  let n = 0;
  for (const e of listDir(root.dir)) {
    if (!e.isDirectory() || e.name.startsWith(".")) continue;
    if (++n > lim.maxExtensionsPerRoot) { budget.truncated = true; break; }
    const dir = join(root.dir, e.name);
    const pkg = readJson(join(dir, "package.json"));
    let id, version;
    if (pkg && typeof pkg.publisher === "string" && typeof pkg.name === "string") {
      id = `${pkg.publisher}.${pkg.name}`.toLowerCase();
      version = typeof pkg.version === "string" ? pkg.version : null;
    } else {
      const m = e.name.match(/^(.*?)-(\d+\.\d+\.\d+.*)$/);
      id = (m ? m[1] : e.name).toLowerCase();
      version = m ? m[2] : null;
    }
    const key = `${root.editor}:${id}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const source = sources.get(`rel:${e.name}`) || sources.get(`id:${id}@${version}`) || null;
    const bad = knownBadExtension(id, version);
    const codes = new Set();
    if (bad.length) codes.add("ide-ext-known-malicious");
    for (const c of classifyExtensionId(id)) codes.add(c);
    if (source === "vsix") codes.add("ide-ext-sideloaded");
    if (invisibleScan(dir, lim, budget)) codes.add("ide-ext-invisible-code");
    const ordered = CODE_ORDER.filter((c) => codes.has(c));
    out.push({
      editor: root.editor, id, version, ai: AI_RE.test(id),
      ...(source ? { source } : {}), codes: ordered, risk: riskOf(ordered),
      ...(bad.length ? { advisories: [...new Set(bad.map((b) => b.advisory))] } : {})
    });
  }
  return out;
}

// ---- JetBrains ------------------------------------------------------------------------------------

function tag(xml, name) {
  const m = new RegExp(`<${name}(?:\\s[^>]*)?>\\s*([^<]{1,200}?)\\s*</${name}>`).exec(xml);
  return m ? m[1].trim() : null;
}

function pluginXml(jarPath, lim) {
  let src;
  try {
    src = new FileSource(jarPath);
    const ent = zipEntries(src).find((x) => x.name === "META-INF/plugin.xml");
    if (!ent) return null;
    const buf = readEntry(src, ent, lim.maxPluginXmlBytes);
    return buf ? buf.toString("utf8") : null;
  } catch { return null; } finally { if (src) src.close(); }
}

function jetbrainsPlugin(dir, isJar, lim) {
  const jars = isJar ? [dir] : listDir(join(dir, "lib")).filter((e) => e.isFile() && e.name.toLowerCase().endsWith(".jar")).map((e) => join(dir, "lib", e.name)).sort().slice(0, lim.maxJarsPerPlugin);
  for (const j of jars) {
    const xml = pluginXml(j, lim);
    if (!xml) continue;
    const id = tag(xml, "id") || tag(xml, "name");
    if (id) return { id, version: tag(xml, "version"), name: tag(xml, "name") };
  }
  return null;
}

function jetbrainsRoot(root, lim, budget) {
  const out = [];
  for (const prod of listDir(root.dir)) {
    if (!prod.isDirectory() || prod.name.startsWith(".")) continue;
    const pdir = root.sub ? join(root.dir, prod.name, root.sub) : join(root.dir, prod.name);
    let n = 0;
    for (const p of listDir(pdir)) {
      const isJar = p.isFile() && p.name.toLowerCase().endsWith(".jar");
      if (!(p.isDirectory() || isJar) || p.name.startsWith(".")) continue;
      if (++n > lim.maxExtensionsPerRoot) { budget.truncated = true; break; }
      const info = jetbrainsPlugin(join(pdir, p.name), isJar, lim);
      const id = info ? info.id : p.name.replace(/\.jar$/i, "");
      out.push({ editor: `jetbrains:${prod.name}`, id, version: info ? info.version : null, ai: AI_RE.test(`${id} ${info && info.name ? info.name : ""} ${p.name}`), codes: [], risk: "none" });
    }
  }
  return out;
}

// ---- entry point ----------------------------------------------------------------------------------

export function scanIdeExtensions({ home = homedir(), platform = process.platform, env = process.env, limits = {} } = {}) {
  const lim = { ...IDE_LIMITS, ...limits };
  const budget = { left: lim.maxTotalBytes, truncated: false };
  const seen = new Set(), extensions = [];
  for (const root of ideExtensionRoots({ home, platform, env })) {
    try {
      if (!statSync(root.dir).isDirectory()) continue;
    } catch { continue; }
    extensions.push(...(root.kind === "vscode" ? vscodeRoot(root, lim, budget, seen) : jetbrainsRoot(root, lim, budget)));
  }
  return {
    scanned: extensions.length,
    ai: extensions.filter((x) => x.ai).length,
    flagged: extensions.filter((x) => x.codes.length).length,
    truncated: budget.truncated,
    extensions
  };
}
