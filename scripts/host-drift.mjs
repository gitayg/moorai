#!/usr/bin/env node
// Host drift check: is each agent host MoorAI hooks into still the version its adapter was tested
// against (data/host-versions.json), and do the adapter's conformance tests and no-model smoke checks
// still pass against it? Run nightly by .github/workflows/host-drift.yml after installing each host's
// LATEST release; runnable locally against whatever is installed.
//
//   node scripts/host-drift.mjs [--host <id>]... [--installed <id>=<version>]... [--latest]
//                               [--skip-tests] [--offline] [--out <report.json>] [--fail-on-drift]
//                               [--live] [--issue-body <file.md> --run-url <url>]
//
//   --host        limit to these hosts (default: every host in the manifest)
//   --installed   use this version instead of running `<bin> --version`
//   --latest      also ask npm for the latest published version (hosts with an `npm` package)
//   --offline     skip checks that fetch from GitHub (the Codex and Gemini published schemas)
//   --skip-tests  skip the conformance test run
//   --issue-body  with one --host: also write the GitHub issue body for that host (markdown)
//   --live        also run ONE real agent turn (makes a model call with the host's API key from the
//                 env; the workflow passes --live only when that key's secret exists)
//
// Report (stdout, and --out): { v, generatedAt, hosts: [{ host, label, tested, installed, latest,
// candidate, drift: same|newer|older|unknown, checks: [{ name, status: pass|fail|skip, detail }],
// attention, reasons }] }. Exit 1 when any check fails (or, with --fail-on-drift, when any host
// drifted); the report is written either way.
//
// No check here makes a model call unless --live is given. The Claude Code smoke runs one `claude -p` turn whose model
// endpoint is a dead local port (ANTHROPIC_BASE_URL=http://127.0.0.1:9), in a throwaway HOME, and
// only reads what the session-start / prompt hooks saw.
import { spawnSync, spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, delimiter } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest, parseVersion, cleanVersion, compareVersions, coreOf, versionFromEnv } from "../cli/agent-hooks/host-version.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const AGENT_HOOK = join(ROOT, "cli", "moorai-agent-hook.mjs");
const CLAUDE_HOOK = join(ROOT, "cli", "moorai-hook.mjs");

// ---- versions ----
export function driftOf(tested, candidate) {
  if (!cleanVersion(candidate) || !cleanVersion(tested)) return "unknown";
  const c = compareVersions(candidate, tested);
  return c === 0 ? "same" : c > 0 ? "newer" : "older";
}

function which(bin, env = process.env) {
  for (const dir of String(env.PATH || "").split(delimiter)) {
    if (dir && existsSync(join(dir, bin))) return join(dir, bin);
  }
  return null;
}

export function installedVersion(m, env = process.env) {
  const bin = m.bin && which(m.bin, env);
  if (!bin) return { bin: null, version: null };
  const r = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 30000, input: "", env });
  return { bin, version: r.status === 0 ? cleanVersion(parseVersion(r.stdout)) : null, raw: (r.stdout || r.stderr || "").trim().slice(0, 200) };
}

export function npmLatest(pkg) {
  const r = spawnSync("npm", ["view", pkg, "version"], { encoding: "utf8", timeout: 60000 });
  return r.status === 0 ? cleanVersion(parseVersion(r.stdout)) : null;
}

// ---- a small JSON-Schema subset (draft-07 / 2020-12 keywords these hosts use) ----
// type, properties, required, additionalProperties:false, items, enum, const, $ref (#/definitions,
// #/$defs), allOf / anyOf / oneOf. Returns a list of "path: problem" strings; empty = valid.
export function validate(schema, value, root = schema, path = "$") {
  const errs = [];
  if (!schema || schema === true) return errs;
  if (schema === false) return [`${path}: not allowed`];
  if (schema.$ref) {
    const ref = String(schema.$ref).replace(/^#\//, "").split("/").reduce((o, k) => (o ? o[k] : undefined), root);
    if (!ref) return [`${path}: unresolved $ref ${schema.$ref}`];
    errs.push(...validate(ref, value, root, path));
  }
  for (const s of schema.allOf || []) errs.push(...validate(s, value, root, path));
  for (const key of ["anyOf", "oneOf"]) {
    if (Array.isArray(schema[key]) && !schema[key].some((s) => !validate(s, value, root, path).length)) errs.push(`${path}: matches none of ${key}`);
  }
  if ("const" in schema && JSON.stringify(schema.const) !== JSON.stringify(value)) errs.push(`${path}: expected ${JSON.stringify(schema.const)}`);
  if (Array.isArray(schema.enum) && !schema.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) errs.push(`${path}: ${JSON.stringify(value)} not in enum`);
  if (schema.type) {
    const types = [].concat(schema.type);
    const t = value === null ? "null" : Array.isArray(value) ? "array" : Number.isInteger(value) ? "integer" : typeof value;
    if (!types.includes(t) && !(t === "integer" && types.includes("number"))) { errs.push(`${path}: type ${t}, want ${types.join("|")}`); return errs; }
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const r of schema.required || []) if (!(r in value)) errs.push(`${path}: missing required "${r}"`);
    const props = schema.properties || {};
    for (const [k, v] of Object.entries(value)) {
      if (props[k]) errs.push(...validate(props[k], v, root, `${path}.${k}`));
      else if (schema.additionalProperties === false) errs.push(`${path}: unknown property "${k}"`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === "object") errs.push(...validate(schema.additionalProperties, v, root, `${path}.${k}`));
    }
  }
  if (Array.isArray(value) && schema.items) value.forEach((v, i) => errs.push(...validate(schema.items, v, root, `${path}[${i}]`)));
  return errs;
}

// Follows $ref / allOf / anyOf / oneOf down to the object schema(s) and returns their property names.
function propsOf(node, root, seen = new Set()) {
  if (!node || typeof node !== "object" || seen.has(node)) return new Set();
  seen.add(node);
  const out = new Set(Object.keys(node.properties || {}));
  if (node.$ref) for (const p of propsOf(String(node.$ref).replace(/^#\//, "").split("/").reduce((o, k) => (o ? o[k] : undefined), root), root, seen)) out.add(p);
  for (const k of ["allOf", "anyOf", "oneOf"]) for (const s of node[k] || []) for (const p of propsOf(s, root, seen)) out.add(p);
  return out;
}
function enumOf(node, root, seen = new Set()) {
  if (!node || typeof node !== "object" || seen.has(node)) return [];
  seen.add(node);
  const out = [...(node.enum || []), ...("const" in node ? [node.const] : [])];
  if (node.$ref) out.push(...enumOf(String(node.$ref).replace(/^#\//, "").split("/").reduce((o, k) => (o ? o[k] : undefined), root), root, seen));
  for (const k of ["allOf", "anyOf", "oneOf"]) for (const s of node[k] || []) out.push(...enumOf(s, root, seen));
  return out;
}

// ---- Codex: the generated hook schemas (codex-rs/hooks/schema/generated/, one per event and
// direction) against the fields cli/agent-hooks/codex.mjs reads and writes, and the conformance
// fixture validated against the input schema. ----
export const CODEX_SCHEMA_URL = (tag, name) => `https://raw.githubusercontent.com/openai/codex/${tag}/codex-rs/hooks/schema/generated/${name}.schema.json`;
export function checkCodexSchemas({ preIn, preOut, upsIn }, fixture) {
  const problems = [];
  const need = (have, names, where) => { for (const n of names) if (!have.has(n)) problems.push(`${where}: no "${n}"`); };
  need(propsOf(preIn, preIn), ["hook_event_name", "tool_name", "tool_input", "session_id", "cwd"], "pre-tool-use input");
  if (!enumOf(preIn.properties?.hook_event_name, preIn).includes("PreToolUse")) problems.push("pre-tool-use input: hook_event_name is not PreToolUse");
  if (fixture) for (const e of validate(preIn, fixture)) problems.push(`fixture: ${e}`);
  need(propsOf(upsIn, upsIn), ["hook_event_name", "prompt", "session_id", "cwd"], "user-prompt-submit input");
  need(propsOf(preOut, preOut), ["hookSpecificOutput", "systemMessage"], "pre-tool-use output");
  const hso = preOut.properties?.hookSpecificOutput;
  need(propsOf(hso, preOut), ["hookEventName", "permissionDecision", "permissionDecisionReason", "additionalContext"], "pre-tool-use output.hookSpecificOutput");
  const dec = (() => { const root = preOut; const p = (function find(n, seen = new Set()) { if (!n || typeof n !== "object" || seen.has(n)) return null; seen.add(n); if (n.properties?.permissionDecision) return n.properties.permissionDecision; if (n.$ref) return find(String(n.$ref).replace(/^#\//, "").split("/").reduce((o, k) => (o ? o[k] : undefined), root), seen); for (const k of ["allOf", "anyOf", "oneOf"]) for (const s of n[k] || []) { const f = find(s, seen); if (f) return f; } return null; })(hso); return enumOf(p, root); })();
  if (!dec.includes("deny")) problems.push(`pre-tool-use output: permissionDecision enum ${JSON.stringify(dec)} lacks "deny"`);
  return problems;
}

// ---- Gemini: MoorAI's written settings.json hooks section against the published settings schema
// (schemas/settings.schema.json, `hooks` and `hooksConfig`). ----
export const GEMINI_SCHEMA_URL = (tag) => `https://raw.githubusercontent.com/google-gemini/gemini-cli/${tag}/schemas/settings.schema.json`;
export function checkGeminiSettings(schema, settings) {
  const problems = [];
  const hooksSchema = schema?.properties?.hooks;
  if (!hooksSchema) return ["settings schema has no `hooks` property"];
  if (!schema.properties.hooksConfig) problems.push("settings schema has no `hooksConfig` property");
  for (const ev of Object.keys(settings?.hooks || {})) if (!propsOf(hooksSchema, schema).has(ev)) problems.push(`hooks.${ev}: event not in the schema`);
  for (const e of validate(hooksSchema, settings?.hooks || {}, schema, "$.hooks")) problems.push(e);
  return problems;
}

// ---- Cursor: no published schema; the installed cursor-agent bundle still carries the hook events
// the adapter registers and the version fields cli/agent-hooks/host-version.mjs reads. ----
export const CURSOR_MARKERS = ["beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "preToolUse", "postToolUse", "subagentStart", "afterFileEdit", "beforeSubmitPrompt", "buildHookEnvironment", "CURSOR_VERSION", "cursor_version"];
export function checkCursorBundle(text) {
  return CURSOR_MARKERS.filter((m) => !text.includes(m)).map((m) => `bundle lacks "${m}"`);
}

async function fetchJson(url, fetchImpl) {
  const r = await fetchImpl(url, { signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
}

function tempHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-drift-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  return home;
}
function hermeticEnv(home, extra = {}) {
  return { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), ...extra };
}
function installInto(home, id, extra = {}) {
  const args = id === "claude-code" ? [CLAUDE_HOOK, "install"] : [AGENT_HOOK, id, "install"];
  return spawnSync(process.execPath, args, { env: hermeticEnv(home, extra), encoding: "utf8", timeout: 30000, input: "" });
}

// Claude Code: register MoorAI's hooks plus a recorder in a throwaway config, start one headless turn
// against a dead model endpoint, and read what the session-start and prompt hooks saw. Proves: the
// settings file holding MoorAI's registration still loads and runs command hooks, the hook stdin still
// has the fields the core hook reads, and AI_AGENT still encodes the version `claude --version` prints.
export async function claudeHookEnvSmoke(bin, version, { timeoutMs = 60000 } = {}) {
  const home = tempHome();
  try {
    const cfg = join(home, ".claude");
    const ins = installInto(home, "claude-code", { CLAUDE_CONFIG_DIR: cfg });
    if (ins.status !== 0) return { status: "fail", detail: `moorai install exited ${ins.status}: ${(ins.stderr || "").slice(0, 300)}` };
    const settingsFile = join(cfg, "settings.json");
    let settings = {};
    try { settings = JSON.parse(readFileSync(settingsFile, "utf8")); } catch { return { status: "fail", detail: "moorai install wrote no readable settings.json" }; }
    const rec = join(home, "rec");
    mkdirSync(rec, { recursive: true });
    const recorder = (name) => ({ hooks: [{ type: "command", command: `${JSON.stringify(process.execPath)} -e ${JSON.stringify(`const fs=require("fs");let b="";process.stdin.on("data",c=>b+=c).on("end",()=>{fs.writeFileSync(${JSON.stringify(join(rec, name + ".json"))},JSON.stringify({stdin:JSON.parse(b||"{}"),AI_AGENT:process.env.AI_AGENT||null}))})`)}` }] });
    settings.hooks = settings.hooks || {};
    (settings.hooks.SessionStart ||= []).push(recorder("session-start"));
    (settings.hooks.UserPromptSubmit ||= []).push(recorder("prompt"));
    writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
    const proj = join(home, "proj");
    mkdirSync(proj, { recursive: true });
    const child = spawn(bin, ["-p", "moorai drift smoke", "--max-turns", "1"], {
      cwd: proj, stdio: ["ignore", "ignore", "ignore"],
      env: hermeticEnv(home, { CLAUDE_CONFIG_DIR: cfg, ANTHROPIC_API_KEY: "sk-moorai-drift-not-a-key", ANTHROPIC_BASE_URL: "http://127.0.0.1:9", DISABLE_AUTOUPDATER: "1" })
    });
    const want = ["session-start", "prompt"].map((n) => join(rec, n + ".json"));
    const end = Date.now() + timeoutMs;
    while (Date.now() < end && !want.every(existsSync)) await new Promise((r) => setTimeout(r, 250));
    child.kill("SIGKILL");
    const seen = want.filter(existsSync).map((f) => JSON.parse(readFileSync(f, "utf8")));
    if (!seen.length) return { status: "fail", detail: "no command hook ran: the settings file with MoorAI's registration did not load, or hooks did not fire before the model call" };
    const problems = [];
    for (const s of seen) for (const k of ["session_id", "cwd", "hook_event_name", "transcript_path"]) if (!(k in s.stdin)) problems.push(`${s.stdin.hook_event_name || "?"} stdin lacks ${k}`);
    if (seen.length < want.length) problems.push("the UserPromptSubmit hook did not fire");
    const envVer = versionFromEnv("claude-code", { AI_AGENT: seen[0].AI_AGENT });
    if (!envVer) problems.push(`AI_AGENT ${JSON.stringify(seen[0].AI_AGENT)} no longer encodes a version (runtime detection falls back to the PATH probe)`);
    else if (version && coreOf(envVer) !== coreOf(version)) problems.push(`AI_AGENT says ${envVer}, --version says ${version}`);
    return problems.length ? { status: "fail", detail: problems.join("; ") } : { status: "pass", detail: `hooks fired; AI_AGENT -> ${envVer}` };
  } finally { rmSync(home, { recursive: true, force: true }); }
}

function readBundle(bin) {
  let dir;
  try { dir = dirname(realpathSync(bin)); } catch { return ""; }
  let text = "";
  for (const f of readdirSync(dir)) if (f.endsWith(".js")) { try { text += readFileSync(join(dir, f), "utf8"); } catch { /* skip */ } }
  return text;
}

// ---- optional live tier: ONE real agent turn per host, only when CI holds that host's API key ----
// Throwaway HOME with MoorAI enrolled against a local stand-in console, MoorAI's hook installed for the
// host, and one non-interactive turn asking the agent to run a harmless shell command. Pass = the
// host ran MoorAI's hook (prompt or tool event), proven by the hook's posture heartbeat reaching the
// stand-in, which also shows what version detection reported from inside the real host. It does not
// prove a tool call was intercepted: the conformance tests cover the verdict shapes. The command line and
// the auth env names come from the manifest's `live` entry; nothing else crosses into the sandbox.
export const LIVE_PROMPT = "Use your shell tool to run exactly this command and nothing else: echo moorai-live-probe";
export async function liveTurn(id, m, { bin, env = process.env, timeoutMs = 240000 } = {}) {
  if (!m.live || !Array.isArray(m.live.args)) return { status: "skip", detail: "no live command for this host in data/host-versions.json" };
  if (!bin) return { status: "skip", detail: `${m.bin} not installed` };
  const { createServer } = await import("node:http");
  const posts = [];
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/agent-posture") { try { posts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      res.writeHead(404); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const home = tempHome();
  let child;
  try {
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${srv.address().port}`, tenant: "host-drift-live", installToken: "host-drift-live" }), { mode: 0o600 });
    const ins = installInto(home, id);
    if (ins.status !== 0) return { status: "fail", detail: `moorai install exited ${ins.status}: ${(ins.stderr || "").slice(0, 300)}` };
    const proj = join(home, "proj");
    mkdirSync(proj, { recursive: true });
    const pass = Object.fromEntries((m.live.env || []).filter((k) => env[k]).map((k) => [k, env[k]]));
    const args = m.live.args.map((a) => (a === "{prompt}" ? LIVE_PROMPT : a));
    child = spawn(bin, args, { cwd: proj, stdio: ["ignore", "ignore", "pipe"], env: hermeticEnv(home, { PATH: env.PATH || process.env.PATH, ...pass }) });
    let stderr = "", exited = null;
    child.stderr.on("data", (d) => { if (stderr.length < 4000) stderr += d; });
    child.on("exit", (c) => { exited = c; });
    const seen = () => posts.find((p) => p && p.heartbeat && p.heartbeat.host === id);
    const end = Date.now() + timeoutMs;
    let grace = 0;
    while (Date.now() < end && !seen()) {
      if (exited !== null && !grace) grace = Date.now() + 10000; // the beat worker is detached: give it time to post
      if (grace && Date.now() > grace) break;
      await new Promise((r) => setTimeout(r, 250));
    }
    const hit = seen();
    if (!hit) return { status: "fail", detail: `no MoorAI heartbeat from ${id} (host exit ${exited}); stderr: ${stderr.replace(/\s+/g, " ").slice(0, 300)}` };
    const entry = (hit.posture && hit.posture.hosts || []).find((h) => h.host === id) || {};
    return { status: "pass", detail: `MoorAI's hook ran inside ${id}; posture reported version ${entry.version ?? "null"} tested ${entry.tested}` };
  } finally {
    if (child && child.exitCode === null) child.kill("SIGKILL");
    srv.close();
    rmSync(home, { recursive: true, force: true });
  }
}

export function runConformance(files) {
  const r = spawnSync(process.execPath, ["--test", "--import", "./test/hermetic-env.mjs", ...files], { cwd: ROOT, encoding: "utf8", timeout: 600000 });
  const out = (r.stdout || "") + (r.stderr || "");
  const n = (k) => Number((new RegExp(`^# ${k} (\\d+)`, "m").exec(out) || [])[1] || 0);
  const failed = out.split("\n").filter((l) => /^not ok /.test(l)).slice(0, 10);
  return { status: r.status === 0 ? "pass" : "fail", detail: `pass ${n("pass")} fail ${n("fail")}${failed.length ? ": " + failed.join(" | ") : ""}` };
}

// One host. `opts.exec` / `opts.fetch` exist so the tests can drive this without hosts or network.
export async function checkHost(id, m, opts = {}) {
  const { installed: forced, latest: wantLatest = false, offline = false, skipTests = false, fetch: fetchImpl = globalThis.fetch, conformance = runConformance, probe = installedVersion, latestOf = npmLatest, claudeSmoke = claudeHookEnvSmoke, live = false, liveImpl = liveTurn } = opts;
  const checks = [];
  const add = (name, r) => checks.push({ name, status: r.status, detail: r.detail || "" });
  const inst = forced ? { bin: null, version: cleanVersion(forced) } : probe(m);
  const latest = wantLatest && m.npm ? latestOf(m.npm) : null;
  const candidate = inst.version || latest;
  const drift = driftOf(m.tested, candidate);
  add("version", inst.version ? { status: "pass", detail: `installed ${inst.version}` } : { status: "skip", detail: inst.bin ? `\`${m.bin} --version\` printed no version: ${inst.raw || ""}` : `${m.bin || id} not installed` });

  if (skipTests) add("conformance", { status: "skip", detail: "--skip-tests" });
  else add("conformance", conformance(m.tests || []));

  const ver = candidate || m.tested; // the schemas of the version under test: installed, else npm latest
  try {
    if (id === "codex") {
      if (offline) add("hook-schema", { status: "skip", detail: "--offline" });
      else {
        const tag = `${m.tagPrefix || "rust-v"}${coreOf(ver)}`;
        const [preIn, preOut, upsIn] = await Promise.all(["pre-tool-use.command.input", "pre-tool-use.command.output", "user-prompt-submit.command.input"].map((n) => fetchJson(CODEX_SCHEMA_URL(tag, n), fetchImpl)));
        const fixture = JSON.parse(readFileSync(join(ROOT, "test", "fixtures", "agent-hooks", "codex", "pre-tool-use-bash.json"), "utf8"));
        const p = checkCodexSchemas({ preIn, preOut, upsIn }, fixture);
        add("hook-schema", p.length ? { status: "fail", detail: `${tag}: ${p.join("; ")}` } : { status: "pass", detail: `${tag}: input/output schemas carry every field the adapter uses; fixture validates` });
      }
    }
    if (id === "gemini") {
      if (offline) add("settings-schema", { status: "skip", detail: "--offline" });
      else {
        const tag = `v${coreOf(ver)}`;
        const schema = await fetchJson(GEMINI_SCHEMA_URL(tag), fetchImpl);
        const home = tempHome();
        try {
          const ins = installInto(home, "gemini");
          if (ins.status !== 0) add("settings-schema", { status: "fail", detail: `moorai install exited ${ins.status}` });
          else {
            const p = checkGeminiSettings(schema, JSON.parse(readFileSync(join(home, ".gemini", "settings.json"), "utf8")));
            add("settings-schema", p.length ? { status: "fail", detail: `${tag}: ${p.join("; ")}` } : { status: "pass", detail: `${tag}: MoorAI's hooks section validates against the published settings schema` });
          }
        } finally { rmSync(home, { recursive: true, force: true }); }
      }
    }
    if (id === "cursor") {
      if (!inst.bin) add("bundle-markers", { status: "skip", detail: "cursor-agent not installed" });
      else {
        const p = checkCursorBundle(readBundle(inst.bin));
        add("bundle-markers", p.length ? { status: "fail", detail: p.join("; ") } : { status: "pass", detail: "hook events and version fields present in the installed bundle" });
      }
    }
    if (id === "claude-code") {
      if (!inst.bin) add("hook-env", { status: "skip", detail: "claude not installed" });
      else add("hook-env", await claudeSmoke(inst.bin, inst.version));
    }
    if (live) add("live-turn", await liveImpl(id, m, { bin: inst.bin }));
    if (id === "copilot") add("no-model-smoke", { status: "skip", detail: "Copilot CLI publishes no hook schema and its bundle is no longer readable JS after 1.0.63; conformance tests only" });
  } catch (e) {
    add("smoke", { status: "fail", detail: String(e && e.message || e).slice(0, 300) });
  }

  const reasons = [];
  if (drift === "newer" || drift === "older") reasons.push(`${drift} than tested: ${candidate} vs ${m.tested}`);
  for (const c of checks) if (c.status === "fail") reasons.push(`${c.name} failed: ${c.detail}`);
  return { host: id, label: m.label || id, tested: m.tested, installed: inst.version || null, latest, candidate: candidate || null, drift, checks, attention: reasons.length > 0, reasons };
}

// The body of the per-host GitHub issue the workflow opens or updates (one issue per host).
export function renderIssue(r, runUrl = "") {
  const cell = (v) => String(v ?? "").replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");
  return [
    `Nightly host-drift check for **${r.label || r.host}**${runUrl ? ` (${runUrl})` : ""}.`, "",
    `- tested (data/host-versions.json): \`${r.tested ?? "none"}\``,
    `- installed latest: \`${r.installed ?? "unknown"}\``,
    `- npm latest: \`${r.latest ?? "n/a"}\``,
    `- drift: **${r.drift}**`, "",
    "| check | status | detail |", "|---|---|---|",
    ...(r.checks || []).map((c) => `| ${cell(c.name)} | ${cell(c.status)} | ${cell(c.detail)} |`), "",
    "Reasons:", ...(r.reasons || []).map((x) => `- ${x}`), "",
    "When every check passes on the new version, bump `tested` in `data/host-versions.json` and close this issue.",
    `_Updated ${new Date().toISOString()}_`, ""
  ].join("\n");
}

export async function run(argv, opts = {}) {
  const a = { hosts: [], installed: {}, latest: false, offline: false, skipTests: false, out: null, failOnDrift: false, live: false, issueBody: null, runUrl: "" };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--host") a.hosts.push(argv[++i]);
    else if (k === "--installed") { const [h, v] = String(argv[++i]).split("="); a.installed[h] = v; }
    else if (k === "--latest") a.latest = true;
    else if (k === "--offline") a.offline = true;
    else if (k === "--skip-tests") a.skipTests = true;
    else if (k === "--out") a.out = argv[++i];
    else if (k === "--fail-on-drift") a.failOnDrift = true;
    else if (k === "--live") a.live = true;
    else if (k === "--issue-body") a.issueBody = argv[++i];
    else if (k === "--run-url") a.runUrl = argv[++i];
    else throw new Error(`unknown argument ${k}`);
  }
  const manifest = opts.manifest || loadManifest();
  const ids = a.hosts.length ? a.hosts : Object.keys(manifest.hosts);
  const hosts = [];
  for (const id of ids) {
    const m = manifest.hosts[id];
    if (!m) { hosts.push({ host: id, drift: "unknown", checks: [{ name: "manifest", status: "fail", detail: "not in data/host-versions.json" }], attention: true, reasons: ["not in manifest"] }); continue; }
    hosts.push(await checkHost(id, m, { ...opts, installed: a.installed[id], latest: a.latest, offline: a.offline, skipTests: a.skipTests, live: a.live }));
  }
  const report = { v: 1, generatedAt: new Date().toISOString(), hosts };
  if (a.out) writeFileSync(a.out, JSON.stringify(report, null, 2) + "\n");
  if (a.issueBody && hosts.length === 1) writeFileSync(a.issueBody, renderIssue(hosts[0], a.runUrl));
  const failed = hosts.some((h) => h.checks.some((c) => c.status === "fail"));
  const drifted = hosts.some((h) => h.drift === "newer" || h.drift === "older");
  return { report, code: failed || (a.failOnDrift && drifted) ? 1 : 0 };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === realpathSync(process.argv[1])) {
  run(process.argv.slice(2)).then(({ report, code }) => {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    process.exit(code);
  }, (e) => { process.stderr.write(`host-drift: ${e && e.message || e}\n`); process.exit(2); });
}
