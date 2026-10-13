// Unknown processes calling an AI provider API (cli/ai-api-callers.mjs): address resolution with a TTL
// cache, shared-front-end ambiguity, the known-caller list, and the once-per-day alert. DNS and the TCP
// table are injected; the addresses below are the ones measured on 2026-10-13 (see the module header).
//
//   node --test test/ai-api-callers.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveAiHosts, aiApiCallers, callerAlerts, callerPosture, imageKey, mooraiPids, CALLER_REASON, CALLER_CATEGORY, CACHE_TTL_MS } from "../cli/ai-api-callers.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const GFE = ["172.217.118.4", "172.217.119.4"];
const DNS = {
  "api.openai.com": ["172.66.0.243", "2606:4700:7::f3"],
  "api.anthropic.com": ["160.79.104.10", "2607:6bc0::10"],
  "generativelanguage.googleapis.com": GFE,
  "www.googleapis.com": GFE,
  "api.mistral.ai": ["172.66.2.203"],
  "api.groq.com": ["104.18.38.236"],
  "api.x.ai": ["104.18.38.236"], // two "other" hosts on one address: still one provider, attributed
  "codestral.mistral.ai": ["104.18.3.115"],
  "openrouter.ai": ["104.18.3.115"] // two providers (mistral, other) on one address → ambiguous
};
const lookupOf = (table, calls = []) => async (h) => { calls.push(h); return (table[h] || []).map((address) => ({ address })); };
const est = (pid, proc, rhost) => ({ pid: String(pid), proc, state: "established", lhost: "10.0.0.5", lport: 50000 + pid, rhost, rport: 443 });

test("resolveAiHosts: provider per address; shared with a control host or a second provider → ambiguous", async () => {
  const r = await resolveAiHosts({ lookup: lookupOf(DNS) });
  assert.equal(r.byIp["160.79.104.10"], "anthropic");
  assert.equal(r.byIp["2607:6bc0::10"], "anthropic");
  assert.equal(r.byIp["172.66.0.243"], "openai");
  assert.equal(r.byIp["172.66.2.203"], "mistral");
  assert.equal(r.byIp["172.217.118.4"], undefined);
  assert.equal(r.byIp["104.18.38.236"], "other");
  assert.deepEqual(r.ambiguous, ["104.18.3.115", ...GFE].sort());
});

test("resolveAiHosts caches in the state dir for the TTL, then resolves again", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-aiapi-"));
  t.after(() => rmTree(dir));
  const calls = [];
  const now = 1_800_000_000_000;
  await resolveAiHosts({ lookup: lookupOf(DNS, calls), stateDir: dir, now });
  const n = calls.length;
  assert.ok(n > 0);
  const cached = await resolveAiHosts({ lookup: lookupOf(DNS, calls), stateDir: dir, now: now + CACHE_TTL_MS - 1 });
  assert.equal(calls.length, n, "within the TTL: no lookup");
  assert.equal(cached.byIp["160.79.104.10"], "anthropic");
  await resolveAiHosts({ lookup: lookupOf(DNS, calls), stateDir: dir, now: now + CACHE_TTL_MS });
  assert.equal(calls.length, 2 * n, "past the TTL: resolved again");
});

test("a lookup that hangs is cut off and the rest still resolve", async () => {
  const lookup = (h) => (h === "api.openai.com" ? new Promise(() => {}) : lookupOf(DNS)(h));
  const r = await resolveAiHosts({ lookup, timeoutMs: 50 });
  assert.equal(r.byIp["160.79.104.10"], "anthropic");
  assert.equal(r.byIp["172.66.0.243"], undefined);
});

test("imageKey folds Electron helpers and .exe; basenames only", () => {
  assert.equal(imageKey("Claude Helper"), "claude");
  assert.equal(imageKey("Google Chrome Helper (Renderer)"), "google chrome");
  assert.equal(imageKey("Codex (Service)"), "codex");
  assert.equal(imageKey("python.exe"), "python");
});

test("aiApiCallers: known apps, agents, browsers and MoorAI are known; a script host is not; ambiguous is counted, never attributed", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const sockets = [
    est(1, "claude", "160.79.104.10"), est(1, "claude", "160.79.104.10"),
    est(2, "Claude Helper", "2607:6bc0::10"),
    est(3, "Google Chrome Helper (Renderer)", "172.66.0.243"),
    est(4, "ChatGPT", "172.66.0.243"),
    est(5, "python.exe", "160.79.104.10"),
    est(6, "RuntimeBroker.exe", "[::ffff:172.66.2.203]"),
    est(7, "Google Drive", "172.217.118.4"),
    est(8, "curl", "104.18.3.115"),
    est(9, "node", "160.79.104.10"),
    est(10, "node", "160.79.104.10"),
    { pid: "10", proc: "node", state: "listen", lhost: "127.0.0.1", lport: 8791, rhost: null, rport: null },
    est(11, "sshd", "8.8.8.8")
  ];
  const r = aiApiCallers(sockets, resolved, { moorai: mooraiPids(sockets, { self: 999, parent: 998 }), argvOf: () => new Map() });
  assert.equal(r.ambiguous, 2);
  assert.deepEqual(r.callers, [
    { processImage: "ChatGPT", provider: "openai", known: true, connections: 1 },
    { processImage: "Claude Helper", provider: "anthropic", known: true, connections: 1 },
    { processImage: "Google Chrome Helper (Renderer)", provider: "openai", known: true, connections: 1 },
    { processImage: "RuntimeBroker.exe", provider: "mistral", known: false, connections: 1 },
    { processImage: "claude", provider: "anthropic", known: true, connections: 2 },
    { processImage: "node", provider: "anthropic", known: false, connections: 1 }, // pid 9: not MoorAI, never folded into it
    { processImage: "node", provider: "anthropic", known: true, connections: 1 },  // pid 10: the model proxy's node
    { processImage: "python.exe", provider: "anthropic", known: false, connections: 1 }
  ]);
  assert.deepEqual(callerPosture(r.callers)[0], { processImage: "ChatGPT", provider: "openai", known: true });
});

test("a node process that is not MoorAI is unknown", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(9, "node", "160.79.104.10")], resolved, { moorai: new Set(["1"]), argvOf: () => new Map() });
  assert.equal(r.callers[0].known, false);
});

test("AI_API_CALLER_UNKNOWN: contract fields, once per (image, provider) per UTC day, policy off silences", () => {
  const callers = [{ processImage: "python.exe", provider: "anthropic", known: false, connections: 3 }, { processImage: "claude", provider: "anthropic", known: true, connections: 9 }];
  const d1 = callerAlerts(callers, { ts: "2026-10-13T08:00:00.000Z" });
  assert.equal(d1.alerts.length, 1);
  const a = d1.alerts[0];
  assert.equal(a.reasonCode, CALLER_REASON);
  assert.equal(a.reasonCode, "AI_API_CALLER_UNKNOWN");
  assert.equal(a.category, CALLER_CATEGORY);
  assert.equal(a.category, "Unknown process calling an AI provider API");
  assert.equal(a.riskLevel, "High");
  assert.deepEqual([a.processImage, a.provider, a.connections], ["python.exe", "anthropic", 3]);
  assert.deepEqual(callerAlerts(callers, { prev: d1.next, ts: "2026-10-13T20:00:00.000Z" }).alerts, [], "same day: once");
  assert.equal(callerAlerts([{ ...callers[0], provider: "openai" }], { prev: d1.next, ts: "2026-10-13T20:00:00.000Z" }).alerts.length, 1, "another provider is another pair");
  assert.equal(callerAlerts(callers, { prev: d1.next, ts: "2026-10-14T00:00:01.000Z" }).alerts.length, 1, "next day: again");
  assert.deepEqual(callerAlerts(callers, { policy: { aiApiCallers: "off" } }).alerts, []);
});

// ---- script hosts (node / bun / deno / python) are known only by the package their main script is in ----
// The command line is injected (argvOf); production reads it locally per OS and never emits it.
const CLAUDE_JS = "/Users/u/.npm-global/lib/node_modules/@anthropic-ai/claude-code/cli.js";
const argvMap = (o) => () => new Map(Object.entries(o).map(([pid, v]) => [pid, Array.isArray(v) ? { argv: v, spaced: false } : v]));

test("node running @anthropic-ai/claude-code/cli.js calling api.anthropic.com is known, and raises no alert", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(41, "node", "160.79.104.10")], resolved, { moorai: new Set(), argvOf: argvMap({ 41: ["node", CLAUDE_JS, "-p", "hi"] }) });
  assert.deepEqual(r.callers, [{ processImage: "node", provider: "anthropic", known: true, connections: 1 }]);
  assert.deepEqual(callerAlerts(r.callers, { ts: "2026-10-13T08:00:00.000Z" }).alerts, []);
});

test("node running ~/tmp/x.js calling api.anthropic.com is unknown and alerts, image basename only", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(42, "node", "160.79.104.10")], resolved, { moorai: new Set(), argvOf: argvMap({ 42: ["node", "/Users/u/tmp/x.js"] }) });
  assert.deepEqual(r.callers, [{ processImage: "node", provider: "anthropic", known: false, connections: 1 }]);
  const a = callerAlerts(r.callers, { ts: "2026-10-13T08:00:00.000Z" }).alerts;
  assert.equal(a.length, 1);
  assert.equal(a[0].processImage, "node");
  assert.ok(!JSON.stringify(a).includes("x.js") && !JSON.stringify(callerPosture(r.callers)).includes("tmp"), "no path leaves the device");
});

test("an unknown node script is NOT hidden by a known node process on the same provider", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(41, "node", "160.79.104.10"), est(42, "node", "160.79.104.10")], resolved,
    { moorai: new Set(), argvOf: argvMap({ 41: ["node", CLAUDE_JS], 42: ["node", "/Users/u/tmp/x.js"] }) });
  assert.deepEqual(r.callers, [
    { processImage: "node", provider: "anthropic", known: false, connections: 1 },
    { processImage: "node", provider: "anthropic", known: true, connections: 1 }
  ]);
  assert.equal(callerAlerts(r.callers, { ts: "2026-10-13T08:00:00.000Z" }).alerts.length, 1);
});

test("Windows: canned Win32_Process CommandLine output → node.exe running the npm Gemini CLI is known, a script in Temp is not", async () => {
  const canned = [
    "5120|\"C:\\Program Files\\nodejs\\node.exe\" \"C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\@google\\gemini-cli\\bundle\\gemini.js\" -p \"summarise\"",
    "6144|\"C:\\Program Files\\nodejs\\node.exe\" C:\\Users\\u\\AppData\\Local\\Temp\\upd.js",
    ""
  ].join("\r\n");
  const { readArgv, winArgvScript } = await import("../cli/ai-api-callers.mjs");
  const scripts = [];
  const argvOf = (pids) => readArgv(pids, { platform: "win32", run: (s) => { scripts.push(s); return canned; } });
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(5120, "node.exe", "172.66.0.243"), est(6144, "node.exe", "172.66.0.243"), est(7, "ChatGPT", "172.66.0.243")], resolved, { moorai: new Set(), argvOf });
  assert.deepEqual(r.callers, [
    { processImage: "ChatGPT", provider: "openai", known: true, connections: 1 },
    { processImage: "node.exe", provider: "openai", known: false, connections: 1 },
    { processImage: "node.exe", provider: "openai", known: true, connections: 1 }
  ]);
  assert.equal(scripts.length, 1, "one PowerShell for every script-host pid");
  assert.equal(scripts[0], winArgvScript(["5120", "6144"]), "only the script-host pids are asked about");
});

test("bun, deno and python: package by script path, npm: spec or -m module; inline code is unknown", async () => {
  const { packageOf } = await import("../cli/ai-api-callers.mjs");
  const e = (argv) => ({ argv, spaced: false });
  assert.equal(packageOf(e(["bun", "/Users/u/.bun/install/global/node_modules/@openai/codex/bin/codex.js"]), "bun"), "@openai/codex");
  assert.equal(packageOf(e(["deno", "run", "-A", "npm:@google/gemini-cli@0.60.0"]), "deno"), "@google/gemini-cli");
  assert.equal(packageOf(e(["bun", "x", "@github/copilot"]), "bun"), "@github/copilot");
  assert.equal(packageOf(e(["python3", "-m", "aider", "--model", "x"]), "python"), "aider-chat");
  assert.equal(packageOf(e(["python3", "/Users/u/.local/pipx/venvs/aider-chat/bin/aider"]), "python"), "aider-chat");
  assert.equal(packageOf(e(["python3", "/Users/u/agent.py"]), "python"), null);
  assert.equal(packageOf(e(["node", "-e", `require(${JSON.stringify(CLAUDE_JS)})`]), "node"), null, "inline code names nothing");
  assert.equal(packageOf(e(["node", "--require", "/x/node_modules/@anthropic-ai/claude-code/hook.js", "/tmp/x.js"]), "node"), null, "the main script decides, not a preload");
  // macOS ps joins argv with spaces: a path with a space is rejoined only when it exists
  const real = (p) => { if (p === "/Users/u/My Tools/node_modules/@google/gemini-cli/bundle/gemini.js") return p; throw new Error("ENOENT"); };
  assert.equal(packageOf({ argv: ["node", "/Users/u/My", "Tools/node_modules/@google/gemini-cli/bundle/gemini.js", "-p"], spaced: true }, "node", { realpath: real }), "@google/gemini-cli");
});

test("python.exe running a script outside a known package stays unknown; python -m aider is known", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(51, "python3.12", "160.79.104.10"), est(52, "python3.12", "160.79.104.10")], resolved,
    { moorai: new Set(), argvOf: argvMap({ 51: ["python3.12", "-m", "aider"], 52: ["python3.12", "/Users/u/c2.py"] }) });
  assert.deepEqual(r.callers.map((c) => c.known), [false, true]);
});

test("Claude Code's native install (an image named like its version) is known only when argv[0] resolves into claude/versions", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const realpath = (p) => { if (p === "/Users/u/.local/bin/claude") return "/Users/u/.local/share/claude/versions/2.1.295"; if (p === "/tmp/2.1.295") return p; throw new Error("ENOENT"); };
  const { nativeClaude } = await import("../cli/ai-api-callers.mjs");
  assert.equal(nativeClaude({ argv: ["/Users/u/.local/bin/claude", "-p"], spaced: true }, "2.1.295", { realpath }), true);
  assert.equal(nativeClaude({ argv: ["/tmp/2.1.295"], spaced: true }, "2.1.295", { realpath }), false);
  const r = aiApiCallers([est(61, "2.1.295", "160.79.104.10"), est(62, "9.9.9", "160.79.104.10")], resolved,
    { moorai: new Set(), argvOf: argvMap({ 61: ["/Users/u/.local/share/claude/versions/2.1.295", "-p"], 62: ["/tmp/9.9.9"] }) });
  assert.deepEqual(r.callers.map((c) => [c.processImage, c.known]), [["2.1.295", true], ["9.9.9", false]]);
});

test("readArgv: Linux /proc cmdline, macOS ps (a vanished pid keeps the rest), no spawn without pids", async () => {
  const { readArgv } = await import("../cli/ai-api-callers.mjs");
  const files = { "/proc/41/cmdline": `node\0${CLAUDE_JS}\0-p\0` };
  const lin = readArgv(["41", "43"], { platform: "linux", readFile: (p) => { if (p in files) return files[p]; throw new Error("ENOENT"); } });
  assert.deepEqual([...lin.entries()], [["41", { argv: ["node", CLAUDE_JS, "-p"], spaced: false }]]);
  const calls = [];
  const mac = readArgv(["41", "x;rm"], { platform: "darwin", run: (args) => { calls.push(args); return `   41 node ${CLAUDE_JS} -p\n`; } });
  assert.deepEqual(calls, [["-ww", "-o", "pid=,args=", "-p", "41"]], "non-numeric pids are dropped");
  assert.deepEqual(mac.get("41"), { argv: ["node", CLAUDE_JS, "-p"], spaced: true });
  assert.equal(readArgv([], { platform: "darwin", run: () => { throw new Error("spawned"); } }).size, 0);
});
