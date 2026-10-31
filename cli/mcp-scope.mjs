// MCP path scope: a path argument judged against the directories the MCP server is declared to serve
// (SAF-T1105 path traversal via a file tool, SAF-T1606 directory listing via a file tool; threat #64).
//
// The declared scope, from the first source that gives one:
//   policy   policy.mcpScope.servers[<label>].roots (signed policy): absolute paths, ~ allowed. Any server.
//   roots    the client's MCP roots (the stdio guard only: it sees the client's roots/list answer), for a
//            filesystem server. The reference server (@modelcontextprotocol/server-filesystem) README: "Roots
//            notified by Client to Server, completely replace any server-side Allowed directories when
//            provided" (2025-era clients; Roots is deprecated in protocol 2026-07-28).
//   args     a filesystem server's launch arguments: the positional arguments after the package
//            (`npx -y @modelcontextprotocol/server-filesystem /a /b`, `mcp-server-filesystem /a`, or its
//            dist/index.js run by node), also when moorai-mcp-guard wraps the launch.
// Anything else (another server, a docker launch, no arguments) has no declared scope and is not judged.
//
// A path argument is a string under a path-named key (path, paths, source, destination, file, filePath, dir,
// directory, root, target, uri, ...), at any depth. It is resolved as the reference server resolves it: ~
// expanded, an absolute path as is, a relative one against the first root it stays inside (else the first
// root). Then:
//   traversal  it lands outside every root and holds a ".." segment
//   outside    it lands outside every root (an absolute path, ~, or a file:// URI elsewhere)
//   symlink    it lands inside a root, but the real path of it (or of its nearest existing parent) is outside
//   unjudged   the walk stopped with path arguments it could not read: more than 64 path-named strings, an object
//              or array nested deeper than 6 levels, or a path longer than 4096 characters. Padding a call past
//              a cap must not hide a path from the check, so these get the scope action too.
// A root counts in the form given and in its real path (macOS /tmp and /private/tmp), as the server does.
// A Windows drive path on a POSIX host is not judged (the server refuses it itself). Hard links are not seen:
// the check is path-based, like the server's.
//
// policy.mcpScope.mode (or servers[<label>].mode): "report" (default: alert, no decision change), "ask",
// "block", "off". Content-free: the alert names the server, the tool, the finding kinds, a count and the
// scope's source; never a path.
import { realpathSync } from "node:fs";
import { posix, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { isWithin, splitPath } from "./path-within.mjs";
import { bareToolName } from "./mcp-tool-class.mjs";

export const SCOPE_MODES = ["off", "report", "ask", "block"];
export const SCOPE_THREAT = 64;
export const FS_SERVER_PACKAGES = ["@modelcontextprotocol/server-filesystem", "mcp-server-filesystem"];
export const LISTING_TOOLS = new Set(["list_directory", "list_directory_with_sizes", "directory_tree", "search_files"]);
const PATH_KEYS = new Set(["path", "paths", "source", "sources", "destination", "file", "files", "filepath", "filepaths", "filename", "src", "dst", "dest", "dir", "directory", "root", "target", "uri"]);
const CAPS = { leaves: 64, depth: 6, roots: 32 };
const obj = (v) => v && typeof v === "object" && !Array.isArray(v);

export function mcpScopeConfig(policy, label) {
  const p = policy && obj(policy.mcpScope) ? policy.mcpScope : {};
  const per = obj(p.servers) && Object.prototype.hasOwnProperty.call(p.servers, label) && obj(p.servers[label]) ? p.servers[label] : {};
  const mode = SCOPE_MODES.includes(per.mode) ? per.mode : SCOPE_MODES.includes(p.mode) ? p.mode : "report";
  const roots = Array.isArray(per.roots) ? per.roots.filter((r) => typeof r === "string" && r && r.length <= 4096).slice(0, CAPS.roots) : null;
  return { mode, roots: roots && roots.length ? roots : null };
}

const baseName = (a) => String(a).replace(/\\/g, "/").split("/").pop();
const unversioned = (a) => String(a).replace(/(?<=.)@[^@/]*$/, "");
// The arguments after a filesystem server's package (or bin, or dist/index.js) in its launch, or null. A guarded
// launch (`moorai-mcp-guard.mjs ... -- npx ... <package> <dirs>`) is found the same way.
function fsArgv(decl) {
  if (!decl || typeof decl.command !== "string" || !decl.command) return null;
  const argv = [decl.command, ...(Array.isArray(decl.args) ? decl.args.map(String) : [])];
  const i = argv.findIndex((a) => FS_SERVER_PACKAGES.includes(unversioned(a)) || baseName(a).replace(/\.(cmd|exe|ps1)$/i, "") === "mcp-server-filesystem" || /[\\/]server-filesystem[\\/]dist[\\/]index\.js$/.test(a));
  return i < 0 ? null : argv.slice(i + 1);
}
export function isFilesystemServer(decl) { return fsArgv(decl) !== null; }
// The allowed directories in a filesystem server's launch arguments (options dropped), or null.
export function launchRoots(decl) {
  const rest = fsArgv(decl);
  if (!rest) return null;
  const dirs = rest.filter((a) => a && !a.startsWith("-")).slice(0, CAPS.roots);
  return dirs.length ? dirs : null;
}

// → null | { roots, source: "policy" | "roots" | "args" }
export function declaredScope({ policy, label, decl = null, clientRoots = [] } = {}) {
  const cfg = mcpScopeConfig(policy, label);
  if (cfg.roots) return { roots: cfg.roots, source: "policy" };
  if (!isFilesystemServer(decl)) return null;
  const cr = Array.isArray(clientRoots) ? clientRoots.filter((r) => typeof r === "string" && r).slice(0, CAPS.roots) : [];
  if (cr.length) return { roots: cr, source: "roots" };
  const lr = launchRoots(decl);
  return lr ? { roots: lr, source: "args" } : null;
}

const nonEmpty = (v) => !!v && typeof v === "object" && (Array.isArray(v) ? v.length > 0 : Object.keys(v).length > 0);
// The string leaves under path-named keys, bounded → { leaves, unvisited }. unvisited: the walk stopped at a
// cap with something left that could hold a path argument (a path-named string, or a non-empty object or array).
export function walkPathArgs(args) {
  const out = [];
  let unvisited = false;
  const stack = [[args, 0, false]];
  while (stack.length && out.length < CAPS.leaves) {
    const [v, d, keyed] = stack.pop();
    if (typeof v === "string") { if (keyed) out.push(v); continue; }
    if (!v || typeof v !== "object") continue;
    if (d >= CAPS.depth) { if (nonEmpty(v)) unvisited = true; continue; }
    if (Array.isArray(v)) { for (let i = v.length - 1; i >= 0; i--) stack.push([v[i], d + 1, keyed]); continue; }
    for (const [k, x] of Object.entries(v)) stack.push([x, d + 1, keyed || PATH_KEYS.has(k.toLowerCase().replace(/[_\-.]/g, ""))]);
  }
  if (stack.some(([v, , keyed]) => (typeof v === "string" ? keyed : nonEmpty(v)))) unvisited = true;
  return { leaves: out, unvisited };
}
export function pathArgs(args) { return walkPathArgs(args).leaves; }

function expand(s, home, platform) {
  if (s === "~" || s.startsWith("~/") || (platform === "win32" && s.startsWith("~\\"))) return home + s.slice(1);
  return s;
}
function samePath(a, b, platform) {
  const x = splitPath(a, platform), y = splitPath(b, platform);
  return !!x && !!y && x.head === y.head && x.keys.length === y.keys.length && x.keys.every((k, i) => k === y.keys[i]);
}
const insideAny = (p, roots, platform) => roots.some((r) => samePath(p, r, platform) || isWithin(p, r, platform));
// The real path of p, or of its nearest existing parent with the rest appended. null when nothing resolves.
function realNearest(p, P, realpath) {
  let cur = p, rest = [];
  for (let i = 0; i < 64; i++) {
    try { const r = realpath(cur); return rest.length ? P.join(r, ...rest.reverse()) : r; } catch { /* missing: try the parent */ }
    const up = P.dirname(cur);
    if (up === cur) return null;
    rest.push(P.basename(cur));
    cur = up;
  }
  return null;
}

// → { checked, kinds: [kind], findings: n, listing }
export function judgeScope(scope, tool, args, { home = os.homedir(), platform = process.platform, realpath = realpathSync, server = "" } = {}) {
  const res = { checked: 0, kinds: [], findings: 0, listing: LISTING_TOOLS.has(bareToolName(tool, server)) };
  if (!scope || !Array.isArray(scope.roots) || !scope.roots.length) return res;
  const P = platform === "win32" ? win32 : posix;
  const roots = [];
  for (const r of scope.roots) {
    const e = expand(r, home, platform);
    if (!P.isAbsolute(e)) continue;
    const abs = P.resolve(e);
    roots.push(abs);
    const real = realNearest(abs, P, realpath);
    if (real && real !== abs) roots.push(real);
  }
  if (!roots.length) return res;
  const kinds = new Set();
  const walk = walkPathArgs(args);
  let unjudged = walk.unvisited ? 1 : 0;
  for (const leaf of walk.leaves) {
    if (leaf.length > 4096) { unjudged++; continue; }
    if (!leaf || leaf.includes("\0")) continue;
    let s = leaf;
    if (/^file:/i.test(s)) { try { s = fileURLToPath(s, { windows: platform === "win32" }); } catch { continue; } }
    else if (/^[a-z][a-z0-9+.-]+:\/\//i.test(s)) continue;
    s = expand(s, home, platform);
    if (platform !== "win32" && /^[A-Za-z]:(?:[\\/]|$)/.test(s)) continue;
    let abs;
    if (P.isAbsolute(s)) abs = P.resolve(s);
    else abs = roots.map((r) => P.resolve(r, s)).find((c) => insideAny(c, roots, platform)) || P.resolve(roots[0], s);
    res.checked++;
    let kind = null;
    if (!insideAny(abs, roots, platform)) kind = /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(leaf) ? "traversal" : "outside";
    else {
      const real = realNearest(abs, P, realpath);
      if (real && !insideAny(real, roots, platform)) kind = "symlink";
    }
    if (kind) { kinds.add(kind); res.findings++; }
  }
  if (unjudged) { kinds.add("unjudged"); res.findings += unjudged; }
  res.kinds = [...kinds].sort();
  return res;
}

const VERDICT = { report: "allow", ask: "ask", block: "deny" };
// → null (nothing outside, or mode off) | { decision, mode, reason }
export function decideScope(policy, label, tool, judged) {
  if (!judged || !judged.findings) return null;
  const { mode } = mcpScopeConfig(policy, label);
  if (mode === "off") return null;
  if (judged.kinds.length === 1 && judged.kinds[0] === "unjudged") return { decision: VERDICT[mode], mode, reason: `${bareToolName(tool, label)} — path arguments past the limits of the MCP scope check (more than 64, nested deeper than 6, or over 4096 characters)` };
  const what = judged.listing ? "directory listing" : judged.kinds.includes("traversal") ? "path traversal" : "path";
  return { decision: VERDICT[mode], mode, reason: `${bareToolName(tool, label)} — ${what} outside the MCP server's declared scope (${judged.kinds.join(", ")})` };
}

export function scopeAlert({ tool, server, judged, source, decision }) {
  const onlyUnjudged = judged.kinds.length === 1 && judged.kinds[0] === "unjudged";
  const category = onlyUnjudged ? "MCP: path arguments the scope check could not read in full" : judged.listing ? "MCP: directory listing outside the server's scope" : judged.kinds.includes("traversal") ? "MCP: path traversal outside the server's scope" : "MCP: path outside the server's scope";
  return {
    threatId: SCOPE_THREAT, category, riskLevel: decision === "deny" ? "Blocked" : "High", stage: "mcp", tool, decision,
    reasonCode: "ENVELOPE", ...(server ? { mcpServer: server } : {}),
    contentHash: `mcp-scope:${judged.kinds.join(".")}${judged.listing ? ":listing" : ""}`,
    signature: { kinds: judged.kinds, paths: judged.findings, checked: judged.checked, scope: source, listing: judged.listing }
  };
}
