// Doctor checks for the agent hosts MoorAI registers into. The EXPECTED registration is never written
// down here: it is produced by running MoorAI's own installers (`moorai-hook.mjs install`,
// `moorai-agent-hook.mjs <agent> install`) against a throwaway HOME and reading back what they wrote.
// So when REGISTERED_EVENTS or an adapter's matcher changes, the doctor's idea of "current" changes
// with it — it cannot drift from the installer.
import { readFileSync, existsSync, readdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { spawnSync, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import os from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = join(HERE, "moorai-hook.mjs");
const AGENT_HOOK = join(HERE, "moorai-agent-hook.mjs");

// Gemini reads settings.json through strip-json-comments (see cli/agent-hooks/gemini.mjs).
function stripComments(src) {
  let out = "", i = 0, q = false;
  while (i < src.length) {
    const c = src[i], n = src[i + 1];
    if (q) { out += c; if (c === "\\") { out += n ?? ""; i += 2; continue; } if (c === '"') q = false; i++; continue; }
    if (c === '"') { q = true; out += c; i++; continue; }
    if (c === "/" && n === "/") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++; i += 2; continue; }
    out += c; i++;
  }
  return out;
}
export function readJson(file, { comments = false } = {}) {
  let raw;
  try { raw = readFileSync(file, "utf8"); } catch { return { exists: false, data: null }; }
  if (!raw.trim()) return { exists: true, data: {} };
  try { return { exists: true, data: JSON.parse(raw) }; } catch { /* maybe comments */ }
  if (comments) { try { return { exists: true, data: JSON.parse(stripComments(raw)) }; } catch { /* fall through */ } }
  return { exists: true, data: null, error: "not valid JSON" };
}

// Host table. `ours` recognises a MoorAI entry the same way that host's installer does.
export function hostTable(home = os.homedir(), env = process.env) {
  const codexHome = env.CODEX_HOME || join(home, ".codex");
  const copilotHome = env.COPILOT_HOME || join(home, ".copilot");
  return [
    { id: "claude-code", label: "Claude Code", dir: join(home, ".claude"), file: join(home, ".claude", "settings.json"), rel: [".claude", "settings.json"], ours: (e) => JSON.stringify(e || {}).includes("moorai-hook"), install: [HOOK, "install"], fix: `node ${JSON.stringify(HOOK)} install` },
    { id: "codex", label: "OpenAI Codex CLI", dir: codexHome, file: join(codexHome, "hooks.json"), rel: [".codex", "hooks.json"], ours: agentOurs("codex"), install: [AGENT_HOOK, "codex", "install"], fix: `node ${JSON.stringify(AGENT_HOOK)} codex install` },
    { id: "cursor", label: "Cursor", dir: join(home, ".cursor"), file: join(home, ".cursor", "hooks.json"), rel: [".cursor", "hooks.json"], ours: agentOurs("cursor"), install: [AGENT_HOOK, "cursor", "install"], fix: `node ${JSON.stringify(AGENT_HOOK)} cursor install` },
    { id: "gemini", label: "Gemini CLI", dir: join(home, ".gemini"), file: join(home, ".gemini", "settings.json"), rel: [".gemini", "settings.json"], comments: true, ours: agentOurs("gemini"), install: [AGENT_HOOK, "gemini", "install"], fix: `node ${JSON.stringify(AGENT_HOOK)} gemini install` },
    { id: "copilot", label: "GitHub Copilot CLI", dir: copilotHome, file: join(copilotHome, "hooks", "moorai.json"), rel: [".copilot", "hooks", "moorai.json"], ours: agentOurs("copilot"), install: [AGENT_HOOK, "copilot", "install"], fix: `node ${JSON.stringify(AGENT_HOOK)} copilot install` }
  ];
}
function agentOurs(id) {
  const re = new RegExp(`moorai-agent-hook\\.mjs["']?\\s+${id}(\\s|$)`);
  return (e) => strings(e).some((s) => re.test(s)) || (id === "gemini" && e && Array.isArray(e.hooks) && e.hooks.some((h) => h && h.name === "moorai"));
}
function strings(v, out = []) {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => strings(x, out));
  else if (v && typeof v === "object") Object.values(v).forEach((x) => strings(x, out));
  return out;
}

// event -> sorted matcher list of MoorAI's entries.
export function ourSurface(cfg, ours) {
  const out = {};
  const hooks = cfg && typeof cfg.hooks === "object" && cfg.hooks ? cfg.hooks : {};
  for (const [ev, list] of Object.entries(hooks)) {
    if (!Array.isArray(list)) continue;
    const m = list.filter(ours).map((e) => (e && typeof e.matcher === "string" ? e.matcher : ""));
    if (m.length) out[ev] = m.sort();
  }
  return out;
}
export function diffSurface(want, have) {
  const missing = [], stale = [], extra = [];
  for (const [ev, ms] of Object.entries(want)) {
    const h = have[ev] || [];
    if (!h.length) missing.push(ev);
    else if (JSON.stringify(h) !== JSON.stringify(ms)) stale.push({ event: ev, want: ms, have: h });
  }
  for (const ev of Object.keys(have)) if (!want[ev]) extra.push(ev);
  return { missing, stale, extra, ok: !missing.length && !stale.length && !extra.length };
}
// Script paths MoorAI's entries point at, so a moved/deleted install is caught.
export function hookScripts(cfg, ours) {
  const hooks = cfg && typeof cfg.hooks === "object" && cfg.hooks ? cfg.hooks : {};
  const out = new Set();
  for (const list of Object.values(hooks)) {
    if (!Array.isArray(list)) continue;
    for (const e of list.filter(ours)) for (const s of strings(e)) {
      for (const m of s.matchAll(/"([^"]*moorai-(?:agent-)?hook\.mjs)"|(\S*moorai-(?:agent-)?hook\.mjs)/g)) out.add(m[1] || m[2]);
    }
  }
  return [...out];
}

// Run the real installer into a throwaway HOME and return what it wrote.
export function expectedSurface(host) {
  const home = mkdtempSync(join(os.tmpdir(), "moorai-doctor-expect-"));
  try {
    const env = { ...process.env, HOME: home, USERPROFILE: home };
    for (const k of ["CODEX_HOME", "COPILOT_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "APPDATA", "LOCALAPPDATA"]) delete env[k];
    const r = spawnSync(process.execPath, host.install, { env, encoding: "utf8", timeout: 15000, input: "" });
    if (r.status !== 0) return { error: `installer exited ${r.status}` };
    const { data } = readJson(join(home, ...host.rel), { comments: host.comments });
    if (!data) return { error: "installer wrote nothing readable" };
    return { surface: ourSurface(data, host.ours) };
  } finally { rmSync(home, { recursive: true, force: true }); }
}

const pathOf = (p) => p.replace(os.homedir(), "~");

// ---- Claude Code plugin install (hooks/hooks.json, `claude plugin install moorai@moorai`) ----
// code.claude.com/docs/en/plugins/loading: "`installed_plugins.json` records each install with its
// `scope`, `installPath`, and `version`"; the plugins root "is `~/.claude/plugins` unless you set
// `CLAUDE_CODE_PLUGIN_CACHE_DIR`"; `cache/<marketplace>/<plugin>/<version>/` — "`${CLAUDE_PLUGIN_ROOT}`
// points at this directory". Shape as Claude Code 2.1.284 writes it:
// { version: 2, plugins: { "moorai@moorai": [{ scope, installPath, version, installedAt, lastUpdated }] } }.
// Enabled means `enabledPlugins["moorai@…"] === true`, the same test the hook's pluginEnabled() makes.
export const PLUGIN_INSTALL = "claude plugin marketplace add gitayg/moorai && claude plugin install moorai@moorai";
const pluginIdOf = (enabled) => Object.entries(enabled || {}).filter(([id, on]) => on === true && id.startsWith("moorai@")).map(([id]) => id);
export function pluginsRoot(home = os.homedir(), env = process.env) { return env.CLAUDE_CODE_PLUGIN_CACHE_DIR || join(home, ".claude", "plugins"); }
export function pluginInstall(settings, { home = os.homedir(), env = process.env, managedPlugins = [] } = {}) {
  const ids = [...new Set([...pluginIdOf(settings && settings.enabledPlugins), ...managedPlugins])];
  if (!ids.length) return null;
  const file = join(pluginsRoot(home, env), "installed_plugins.json");
  const recs = (readJson(file).data || {}).plugins || {};
  for (const id of ids) {
    const list = Array.isArray(recs[id]) ? recs[id] : [];
    const rec = list.find((r) => r && r.scope === "user" && r.installPath) || list.find((r) => r && r.installPath);
    if (rec) return { id, installPath: rec.installPath, version: rec.version, scope: rec.scope };
  }
  return { id: ids[0], installPath: null, recordFile: file };
}
function checkPlugin(base, host, plug, exp) {
  const fix = `claude plugin update ${plug.id} (or reinstall: claude plugin uninstall ${plug.id} && claude plugin install ${plug.id})`;
  const hooksFile = join(plug.installPath, "hooks", "hooks.json");
  const where = `plugin ${plug.id}`;
  if (!existsSync(plug.installPath)) return { ...base, status: "fail", summary: `${where} is enabled but its copy ${pathOf(plug.installPath)} is gone`, fix, installed: true };
  const { data, error } = readJson(hooksFile);
  if (!data) return { ...base, status: "fail", summary: `${where}: ${pathOf(hooksFile)} is ${error || "missing"}`, fix, installed: true };
  const have = ourSurface(data, host.ours);
  const scripts = hookScripts(data, host.ours).map((s) => s.split("${CLAUDE_PLUGIN_ROOT}").join(plug.installPath));
  const details = { file: pathOf(hooksFile), plugin: plug.id, version: plug.version, events: have, expected: exp.surface, scripts: scripts.map(pathOf) };
  const d = diffSurface(exp.surface, have);
  const problems = [];
  if (d.missing.length) problems.push(`missing event(s) ${d.missing.join(", ")}`);
  for (const s of d.stale) problems.push(`${s.event} matchers are [${s.have.join(" ")}], current is [${s.want.join(" ")}]`);
  if (d.extra.length) problems.push(`unexpected event(s) ${d.extra.join(", ")}`);
  const missingScripts = scripts.filter((s) => !existsSync(s));
  if (missingScripts.length) problems.push(`hook file missing: ${missingScripts.map(pathOf).join(", ")}`);
  if (!scripts.length) problems.push("no hook script path found in the plugin's hooks.json");
  if (problems.length) return { ...base, status: "fail", summary: `${where}: ${problems.join("; ")}`, fix, details, installed: true };
  return { ...base, status: "ok", summary: `registered via plugin ${plug.id} (${plug.version || "unknown version"}, ${pathOf(plug.installPath)}): ${Object.entries(have).map(([e, m]) => `${e}(${m.length})`).join(" ")}`, details, installed: true };
}

export function checkHost(host, { managedHooks = null, managedPlugins = [], env = process.env, home = os.homedir() } = {}) {
  const base = { id: `host:${host.id}`, group: "hosts", title: host.label };
  const hostPresent = existsSync(host.dir);
  const { exists, data, error } = readJson(host.file, { comments: host.comments });
  if (exists && !data) return { ...base, status: "fail", summary: `${pathOf(host.file)} is ${error}; the host may ignore every hook in it`, fix: `repair the JSON in ${pathOf(host.file)}` };
  let have = data ? ourSurface(data, host.ours) : {};
  let where = pathOf(host.file);
  let scripts = data ? hookScripts(data, host.ours) : [];
  const inSettings = Object.keys(have).length > 0;
  const plug = host.id === "claude-code" ? pluginInstall(data, { home, env, managedPlugins }) : null;
  // Claude Code: MoorAI may be deployed in managed settings instead of the user file.
  if (host.id === "claude-code" && !Object.keys(have).length && managedHooks && Object.keys(ourSurface(managedHooks.data, host.ours)).length) {
    have = ourSurface(managedHooks.data, host.ours); where = `managed settings (${managedHooks.source})`; scripts = hookScripts(managedHooks.data, host.ours);
  }
  if (!Object.keys(have).length) {
    if (plug && plug.installPath) {
      const exp = expectedSurface(host);
      if (exp.error) return { ...base, status: "fail", summary: `could not compute the current MoorAI surface: ${exp.error}`, installed: true };
      return checkPlugin(base, host, plug, exp);
    }
    const why = plug ? `; ${plug.id} is enabled but ${pathOf(plug.recordFile)} has no install record for it` : "";
    if (!hostPresent) return { ...base, status: "skip", summary: `${host.label} not found (${pathOf(host.dir)} absent)`, installed: false };
    return { ...base, status: "warn", summary: `${host.label} is present but MoorAI is not registered in ${where}${host.id === "claude-code" ? " or as a plugin" : ""}${why}`, fix: host.id === "claude-code" ? `${host.fix} — or: ${PLUGIN_INSTALL}` : host.fix, installed: false };
  }
  const exp = expectedSurface(host);
  if (exp.error) return { ...base, status: "fail", summary: `could not compute the current MoorAI surface: ${exp.error}`, installed: true };
  const d = diffSurface(exp.surface, have);
  const missingScripts = scripts.filter((s) => !existsSync(s));
  const details = { file: where, events: have, expected: exp.surface, scripts: scripts.map(pathOf) };
  // Both: the hook's --plugin copy stands down for each event a live settings.json install covers
  // (settingsCovers in moorai-hook.mjs), so the settings copy is the one that runs where it covers.
  const both = inSettings && plug && plug.installPath ? `both installed; the plugin stands down where the settings copy covers an event — keep one (${plug.id} and ${where})` : "";
  const bothFix = both ? `claude plugin uninstall ${plug.id}, or: node ${JSON.stringify(HOOK)} uninstall` : "";
  if (both) details.plugin = plug.id;
  const problems = [];
  if (d.missing.length) problems.push(`missing event(s) ${d.missing.join(", ")}`);
  for (const s of d.stale) problems.push(`${s.event} matchers are [${s.have.join(" ")}], current is [${s.want.join(" ")}]`);
  if (d.extra.length) problems.push(`unexpected event(s) ${d.extra.join(", ")}`);
  if (missingScripts.length) problems.push(`hook file missing: ${missingScripts.map(pathOf).join(", ")}`);
  if (!scripts.length) problems.push("no hook script path found in MoorAI's entries");
  const other = scripts.filter((s) => existsSync(s) && s !== HOOK && s !== AGENT_HOOK);
  if (host.id === "claude-code" && data && data.disableAllHooks === true) problems.push(`disableAllHooks is true in ${pathOf(host.file)}`);
  if (host.id === "gemini" && data && data.hooksConfig && data.hooksConfig.enabled === false) problems.push("hooksConfig.enabled is false");
  if (problems.length) return { ...base, status: "fail", summary: `${problems.join("; ")}${both ? `; ${both}` : ""}`, fix: host.fix, details, installed: true };
  if (both) return { ...base, status: "warn", summary: both, fix: bothFix, details, installed: true };
  const notes = [];
  if (other.length) notes.push(`entries run ${other.map(pathOf).join(", ")} (compared against this package's surface)`);
  if (host.id === "codex") {
    const toml = (() => { try { return readFileSync(join(host.dir, "config.toml"), "utf8"); } catch { return ""; } })();
    if (!/hooks\.state/.test(toml)) return { ...base, status: "warn", summary: `registered, but ${pathOf(join(host.dir, "config.toml"))} has no [hooks.state] trust entry — Codex runs user hooks only after you trust them`, fix: "start codex and approve the MoorAI hook in the hook review (or /hooks)", details, installed: true };
  }
  return { ...base, status: "ok", summary: `registered in ${where}: ${Object.entries(have).map(([e, m]) => `${e}(${m.length})`).join(" ")}${notes.length ? ` — ${notes.join("; ")}` : ""}`, details, installed: true };
}

// Claude Code managed settings — code.claude.com/docs/en/managed-settings: file-based policy lives in
// `/Library/Application Support/ClaudeCode/` (macOS), `/etc/claude-code/` (Linux/WSL) and
// `C:\Program Files\ClaudeCode\` (Windows) as managed-settings.json plus an optional managed-settings.d/;
// the macOS MDM form is the `com.anthropic.claudecode` managed preferences domain.
// settings-reference: `allowManagedHooksOnly` (Managed scope) "Run only the hooks your organization
// deploys"; `disableAllHooks` (any file) turns hooks off. hooks reference: under allowManagedHooksOnly
// "Hooks from plugins force-enabled in managed settings `enabledPlugins` are exempt", and
// settings-reference: "Claude Code matches on the full `plugin@marketplace` ID".
export function managedDir() {
  if (process.platform === "darwin") return "/Library/Application Support/ClaudeCode";
  if (process.platform === "win32") return "C:\\Program Files\\ClaudeCode";
  return "/etc/claude-code";
}
export function readManagedSettings(dir = managedDir()) {
  const sources = [];
  const f = join(dir, "managed-settings.json");
  const main = readJson(f);
  if (main.exists) sources.push({ source: f, data: main.data, error: main.error });
  const dd = join(dir, "managed-settings.d");
  try { for (const n of readdirSync(dd).filter((n) => n.endsWith(".json")).sort()) { const r = readJson(join(dd, n)); sources.push({ source: join(dd, n), data: r.data, error: r.error }); } } catch { /* absent */ }
  if (process.platform === "darwin" && dir === managedDir()) {
    for (const p of ["/Library/Managed Preferences/com.anthropic.claudecode.plist", join("/Library/Managed Preferences", os.userInfo().username, "com.anthropic.claudecode.plist")]) {
      try { statSync(p); } catch { continue; }
      try { sources.push({ source: p, data: JSON.parse(execFileSync("plutil", ["-convert", "json", "-o", "-", p], { encoding: "utf8", timeout: 5000 })) }); }
      catch { sources.push({ source: p, data: null, error: "unreadable plist" }); }
    }
  }
  return sources;
}
export function checkManaged(sources = readManagedSettings(), ours = (e) => JSON.stringify(e || {}).includes("moorai-hook")) {
  const base = { id: "claude-code:managed", group: "hosts", title: "Claude Code managed settings" };
  if (!sources.length) return { ...base, status: "ok", summary: `no managed settings on disk under ${managedDir()} (server-managed settings from claude.ai are not visible locally)`, managedHooks: null };
  const bad = sources.filter((s) => !s.data);
  if (bad.length) return { ...base, status: "warn", summary: `unreadable managed source(s): ${bad.map((s) => s.source).join(", ")}`, managedHooks: null };
  const merged = { hooks: {} };
  for (const s of sources) for (const [ev, list] of Object.entries(s.data.hooks || {})) merged.hooks[ev] = [...(merged.hooks[ev] || []), ...(Array.isArray(list) ? list : [])];
  const withOurs = Object.keys(ourSurface(merged, ours)).length > 0;
  const managedHooks = withOurs ? { source: sources.map((s) => s.source).join(", "), data: merged } : null;
  const managedPlugins = [...new Set(sources.flatMap((s) => pluginIdOf(s.data.enabledPlugins)))];
  const disabled = sources.find((s) => s.data.disableAllHooks === true);
  if (disabled) return { ...base, status: "fail", summary: `disableAllHooks is true in ${disabled.source}: no hook runs, MoorAI included`, fix: "ask the Claude Code admin to remove disableAllHooks", managedHooks, managedPlugins };
  const only = sources.find((s) => s.data.allowManagedHooksOnly === true);
  if (only && !withOurs && !managedPlugins.length) return { ...base, status: "fail", summary: `allowManagedHooksOnly is true in ${only.source} and MoorAI is not among the managed hooks: Claude Code will not run MoorAI's user-level hooks`, fix: "deploy MoorAI's hook entries in managed settings (copy the hooks block `moorai-hook.mjs install` writes), or force-enable moorai@moorai in managed enabledPlugins (\"enabledPlugins\": {\"moorai@moorai\": true}) — hooks from force-enabled plugins are exempt", managedHooks, managedPlugins };
  const how = withOurs ? "MoorAI deployed as a managed hook" : `MoorAI plugin ${managedPlugins.join(", ")} force-enabled in managed enabledPlugins`;
  return { ...base, status: "ok", summary: `${sources.length} managed source(s); ${only ? `allowManagedHooksOnly on, ${how}` : "no hook restriction"}`, managedHooks, managedPlugins };
}
