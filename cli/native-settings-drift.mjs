// Drift between the native settings MoorAI compiles (cli/native-settings.mjs) and what each host's file
// holds now. Reads files; never writes one.
//
//   nativeDrift(compiled, { root, home, read }) -> { host, state, files:[{ path, state, findings }] }
//   nativeSettingsPosture({ policy, platform, root, home, mcpIdentities, read })
//     -> { v:1, hosts: { <host>: { state, files, findings, weakening, unexpressed } } }   (heartbeat field)
//
// state: in-sync | drift | absent (no file where MoorAI's should be) | unreadable | not-applicable (the
// policy gives this host nothing to write).
// finding: { key, kind, count?, weakens }. key is a dotted key path inside the file ("*" for a whole-file
// TOML); kind: missing-entries | extra-entries | key-absent | value-changed | extra-key | content-changed.
// weakens: true when the file on disk lets through something MoorAI's compiled file refuses — an entry
// missing from a deny/ask list, an extra entry on an allow-list, a changed or deleted switch, an unknown key.
// Content-free: key paths and counts only, never a tool name, server, host or path value.
//
// root: a directory standing in for "/" (tests, offline images); home: where "~/" resolves.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { nativeSettings, renderFile, NATIVE_HOSTS } from "./native-settings.mjs";

// Lists where an extra entry on disk lets more through.
const ALLOW_LISTS = new Set(["allowedMcpServers", "sandbox.network.allowedDomains", "permissions.limitTo", "permissions.allow", "mcp.allowed"]);
const RANK = { "in-sync": 0, "not-applicable": 0, absent: 1, unreadable: 2, drift: 3 };

export function resolveNativePath(p, { root = "", home = homedir() } = {}) {
  if (p.startsWith("~/")) return join(home, ...p.slice(2).split("/"));
  if (/^[A-Za-z]:\\/.test(p)) return root ? join(root, p[0], ...p.slice(3).split("\\")) : p;
  return root ? join(root, ...p.slice(1).split("/")) : p;
}

function defaultRead(p) {
  try { return readFileSync(p, "utf8"); } catch (e) { if (e && e.code === "ENOENT") return null; throw e; }
}

// Leaves: dotted path -> value, descending into plain objects only (arrays and scalars are leaves).
function leaves(o, pre = "", out = new Map()) {
  for (const [k, v] of Object.entries(o)) {
    const key = pre ? `${pre}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length) leaves(v, key, out);
    else out.set(key, v);
  }
  return out;
}
const at = (o, key) => key.split(".").reduce((x, k) => (x && typeof x === "object" && !Array.isArray(x) ? x[k] : undefined), o);
const canon = (v) => JSON.stringify(v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort()) : v);

function jsonFindings(f, text) {
  let disk;
  try { disk = JSON.parse(text); } catch { return null; }
  if (!disk || typeof disk !== "object" || Array.isArray(disk)) return null;
  const want = leaves(f.content), findings = [];
  for (const [key, v] of want) {
    const got = at(disk, key);
    if (got === undefined) { findings.push({ key, kind: "key-absent", weakens: true }); continue; }
    if (Array.isArray(v)) {
      const w = new Set(v.map(canon)), g = new Set((Array.isArray(got) ? got : [got]).map(canon));
      const missing = [...w].filter((x) => !g.has(x)).length, extra = [...g].filter((x) => !w.has(x)).length;
      const allow = ALLOW_LISTS.has(key);
      if (missing) findings.push({ key, kind: "missing-entries", count: missing, weakens: !allow });
      if (extra) findings.push({ key, kind: "extra-entries", count: extra, weakens: allow });
      continue;
    }
    if (canon(got) !== canon(v)) findings.push({ key, kind: "value-changed", weakens: true });
  }
  if (f.merge === "whole") {
    for (const key of leaves(disk).keys()) if (!want.has(key) && ![...want.keys()].some((w) => key.startsWith(`${w}.`))) findings.push({ key, kind: "extra-key", weakens: true });
  }
  return findings.sort((a, b) => (a.key === b.key ? (a.kind < b.kind ? -1 : 1) : a.key < b.key ? -1 : 1));
}

export function nativeDrift(compiled, { root = "", home = homedir(), read = defaultRead } = {}) {
  const files = compiled.files.map((f) => {
    let text;
    try { text = read(resolveNativePath(f.path, { root, home })); } catch { return { path: f.path, state: "unreadable", findings: [] }; }
    if (text === null) return { path: f.path, state: "absent", findings: [] };
    let findings;
    if (f.format === "toml") findings = text === renderFile(f) ? [] : [{ key: "*", kind: "content-changed", weakens: true }];
    else findings = jsonFindings(f, text);
    if (findings === null) return { path: f.path, state: "unreadable", findings: [] };
    return { path: f.path, state: findings.length ? "drift" : "in-sync", findings };
  });
  const state = files.length ? files.reduce((s, x) => (RANK[x.state] > RANK[s] ? x.state : s), "in-sync") : "not-applicable";
  return { host: compiled.host, state, files };
}

export function nativeSettingsPosture({ policy, platform, root = "", home = homedir(), mcpIdentities = {}, read = defaultRead, hosts = NATIVE_HOSTS } = {}) {
  const out = {};
  for (const host of hosts) {
    const c = nativeSettings(policy, host, { platform, mcpIdentities });
    if (!c.ok) continue;
    const d = nativeDrift(c, { root, home, read });
    const all = d.files.flatMap((f) => f.findings);
    out[host] = { state: d.state, files: c.files.length, findings: all.length, weakening: all.filter((x) => x.weakens).length, unexpressed: c.unexpressed.length };
  }
  return { v: 1, hosts: out };
}
