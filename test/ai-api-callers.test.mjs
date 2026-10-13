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

// ---- script hosts (node / bun / deno / python) are known only by the package entry their main script is ----
// The command line, the file system and the executable are injected; production reads them locally per OS
// and never emits them. FX is a macOS home (/Users/u) with one install of each kind.
const CLAUDE_JS = "/Users/u/.npm-global/lib/node_modules/@anthropic-ai/claude-code/cli.js";
const GEMINI_BREW = "/opt/homebrew/lib/node_modules/@google/gemini-cli/bundle/gemini.js";
const CODEX_NVM = "/Users/u/.nvm/versions/node/v22.22.0/lib/node_modules/@openai/codex/bin/codex.js";
const COPILOT_PNPM = "/Users/u/Library/pnpm/global/5/.pnpm/@github+copilot@1.0.0/node_modules/@github/copilot/npm-loader.js";
const QWEN_VOLTA = "/Users/u/.volta/tools/image/packages/@qwen-code/qwen-code/lib/node_modules/@qwen-code/qwen-code/cli-entry.js";
const CRUSH_YARN = "/Users/u/.config/yarn/global/node_modules/@charmland/crush/run-crush.js";
const BUN_CODEX = "/Users/u/.bun/install/global/node_modules/@openai/codex/bin/codex.js";
const DENO_GEMINI = "/Users/u/Library/Caches/deno/npm/registry.npmjs.org/@google/gemini-cli/0.60.0/bundle/gemini.js";
const AIDER = "/Users/u/.local/share/uv/tools/aider-chat/bin/aider";
const AIDER_PY = "/Users/u/.local/share/uv/tools/aider-chat/bin/python3";
const W_GEMINI = String.raw`C:\Users\u\AppData\Roaming\npm\node_modules\@google\gemini-cli\bundle\gemini.js`;
const W_TEMP = String.raw`C:\Users\u\AppData\Local\Temp\upd.js`;
const pkgJson = (name, bin) => JSON.stringify({ name, version: "1.0.0", bin });
const FILES = {
  "/Users/u/.npm-global/lib/node_modules/@anthropic-ai/claude-code/package.json": pkgJson("@anthropic-ai/claude-code", { claude: "cli.js" }),
  "/opt/homebrew/lib/node_modules/@google/gemini-cli/package.json": pkgJson("@google/gemini-cli", { gemini: "bundle/gemini.js" }),
  "/Users/u/.nvm/versions/node/v22.22.0/lib/node_modules/@openai/codex/package.json": pkgJson("@openai/codex", { codex: "bin/codex.js" }),
  "/Users/u/Library/pnpm/global/5/.pnpm/@github+copilot@1.0.0/node_modules/@github/copilot/package.json": pkgJson("@github/copilot", { copilot: "npm-loader.js" }),
  "/Users/u/.volta/tools/image/packages/@qwen-code/qwen-code/lib/node_modules/@qwen-code/qwen-code/package.json": pkgJson("@qwen-code/qwen-code", { qwen: "cli-entry.js" }),
  "/Users/u/.config/yarn/global/node_modules/@charmland/crush/package.json": pkgJson("@charmland/crush", { crush: "./run-crush.js" }),
  "/Users/u/.bun/install/global/node_modules/@openai/codex/package.json": pkgJson("@openai/codex", { codex: "bin/codex.js" }),
  "/Users/u/Library/Caches/deno/npm/registry.npmjs.org/@google/gemini-cli/0.60.0/package.json": pkgJson("@google/gemini-cli", { gemini: "bundle/gemini.js" }),
  "C:/Users/u/AppData/Roaming/npm/node_modules/@google/gemini-cli/package.json": pkgJson("@google/gemini-cli", { gemini: "bundle/gemini.js" }),
  // decoys: the right package.json in the wrong place, or the wrong one in the right place
  "/tmp/node_modules/@anthropic-ai/claude-code/package.json": pkgJson("@anthropic-ai/claude-code", { claude: "cli.js" }),
  "/usr/local/lib/node_modules/evil/node_modules/@anthropic-ai/claude-code/package.json": pkgJson("@anthropic-ai/claude-code", { claude: "cli.js" }),
  "/usr/local/lib/node_modules/@openai/codex/package.json": pkgJson("@evil/codex", { codex: "bin/codex.js" })
};
const EXIST = new Set([CLAUDE_JS, GEMINI_BREW, CODEX_NVM, COPILOT_PNPM, QWEN_VOLTA, CRUSH_YARN, BUN_CODEX, DENO_GEMINI, AIDER, AIDER_PY, W_GEMINI, W_TEMP,
  "/tmp/evil.js", "/tmp/evil.py", "/tmp/a", "/tmp/node_modules/@anthropic-ai/claude-code/cli.js", "/usr/local/lib/node_modules/evil/node_modules/@anthropic-ai/claude-code/cli.js",
  "/Users/u/.npm-global/lib/node_modules/@anthropic-ai/claude-code/evil.js", "/usr/local/lib/node_modules/@openai/codex/bin/codex.js",
  "/tmp/x/venvs/aider-chat/bin/aider", "/tmp/site-packages/aider/main.py", "/Users/u/My Tools/node_modules/@google/gemini-cli/bundle/gemini.js"]);
const LINKS = {
  "/Users/u/.npm-global/bin/claude": CLAUDE_JS, "/opt/homebrew/bin/gemini": GEMINI_BREW, "/Users/u/.local/bin/aider": AIDER,
  "/Users/u/Library/pnpm/global/5/node_modules/@github/copilot/npm-loader.js": COPILOT_PNPM,
  "/tmp/a /Users/u/.npm-global/bin/claude": CLAUDE_JS // planted: a path that is also "/tmp/a" plus the shim
};
const realpath = (p) => { if (p in LINKS) return LINKS[p]; if (EXIST.has(p)) return p; throw Object.assign(new Error(`ENOENT ${p}`), { code: "ENOENT" }); };
const readFile = (p) => { const k = String(p).replace(/\\/g, "/"); if (k in FILES) return FILES[k]; throw Object.assign(new Error(`ENOENT ${p}`), { code: "ENOENT" }); };
const FX = { realpath, readFile, platform: "darwin", home: "/Users/u" };
const IMAGE = { node: "node", bun: "bun", deno: "deno", python: "python3.12" };
const argvMap = (o) => () => new Map(Object.entries(o).map(([pid, v]) => [pid, Array.isArray(v) ? { argv: v, spaced: false } : v]));
// One script-host connection to api.anthropic.com → is it known? (aiApiCallers, as production calls it)
async function knownOf(kind, entry, extra = {}) {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(70, extra.image || IMAGE[kind], "160.79.104.10")], resolved, { moorai: new Set(), argvOf: argvMap({ 70: entry }), ...FX, ...extra });
  return r.callers[0].known;
}

test("node running @anthropic-ai/claude-code/cli.js calling api.anthropic.com is known, and raises no alert", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(41, "node", "160.79.104.10")], resolved, { moorai: new Set(), argvOf: argvMap({ 41: ["node", CLAUDE_JS, "-p", "hi"] }), ...FX });
  assert.deepEqual(r.callers, [{ processImage: "node", provider: "anthropic", known: true, connections: 1 }]);
  assert.deepEqual(callerAlerts(r.callers, { ts: "2026-10-13T08:00:00.000Z" }).alerts, []);
});

test("node running ~/tmp/x.js calling api.anthropic.com is unknown and alerts, image basename only", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(42, "node", "160.79.104.10")], resolved, { moorai: new Set(), argvOf: argvMap({ 42: ["node", "/tmp/evil.js"] }), ...FX });
  assert.deepEqual(r.callers, [{ processImage: "node", provider: "anthropic", known: false, connections: 1 }]);
  const a = callerAlerts(r.callers, { ts: "2026-10-13T08:00:00.000Z" }).alerts;
  assert.equal(a.length, 1);
  assert.equal(a[0].processImage, "node");
  assert.ok(!JSON.stringify(a).includes("evil") && !JSON.stringify(callerPosture(r.callers)).includes("tmp"), "no path leaves the device");
});

test("an unknown node script is NOT hidden by a known node process on the same provider", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(41, "node", "160.79.104.10"), est(42, "node", "160.79.104.10")], resolved,
    { moorai: new Set(), argvOf: argvMap({ 41: ["node", CLAUDE_JS], 42: ["node", "/tmp/evil.js"] }), ...FX });
  assert.deepEqual(r.callers, [
    { processImage: "node", provider: "anthropic", known: false, connections: 1 },
    { processImage: "node", provider: "anthropic", known: true, connections: 1 }
  ]);
  assert.equal(callerAlerts(r.callers, { ts: "2026-10-13T08:00:00.000Z" }).alerts.length, 1);
});

// Rule 1: each runtime's own option grammar finds the main script; a value option consumes its value only in
// the form the runtime itself accepts.
test("rule 1, grammar: node --disable-warning <x> consumes <x> as node does, so the script after it decides", async () => {
  // node: `--disable-warning DEP0040 a.js` runs a.js (MEASURED, node 22): the spaced value is consumed.
  assert.equal(await knownOf("node", ["node", "--disable-warning", CLAUDE_JS, "/tmp/evil.js"]), false, "node runs /tmp/evil.js");
  assert.equal(await knownOf("node", ["node", "--no-warnings", "--max-old-space-size=8192", "--disable-warning=DEP0040", CLAUDE_JS, "-p", "--require", "x"]), true, "options after the script are its own");
  assert.equal(await knownOf("node", ["node", "--", CLAUDE_JS]), true);
  assert.equal(await knownOf("python", ["python3.12", "-Wd", "-X", "utf8", "-Bu", AIDER]), true, "python clusters short options");
  assert.equal(await knownOf("python", ["python3.12", "--check-hash-based-pycs", "never", AIDER]), true);
  assert.equal(await knownOf("bun", ["bun", "run", "--bun", BUN_CODEX]), true);
  assert.equal(await knownOf("deno", ["deno", "run", "-A", "--allow-net=api.anthropic.com", "--no-config", DENO_GEMINI]), true);
});

// Rule 2: anything on the command line that loads code other than the main script makes the process unknown.
test("rule 2, other code: preload, import, loader, inline, stdin, env file, inspector, symlinked deps, REPL", async () => {
  const node = [["--require", "/tmp/evil.js", CLAUDE_JS], ["-r", "/tmp/evil.js", CLAUDE_JS], ["--import=data:text/javascript,1", CLAUDE_JS],
    ["--experimental-loader=/tmp/l.mjs", CLAUDE_JS], ["-", CLAUDE_JS], ["--env-file=/tmp/.env", CLAUDE_JS], ["--inspect", CLAUDE_JS],
    ["--inspect-brk=0", CLAUDE_JS], ["--preserve-symlinks-main", CLAUDE_JS], ["--preserve_symlinks", CLAUDE_JS], ["-i", CLAUDE_JS], ["-e", "1", CLAUDE_JS], []];
  for (const opts of node) assert.equal(await knownOf("node", ["node", ...opts]), false, `node ${opts.join(" ")}`);
  for (const opts of [["--preload", "/tmp/evil.js", BUN_CODEX], ["-r", "/tmp/evil.js", BUN_CODEX], ["--config=/tmp/bunfig.toml", BUN_CODEX], ["--cwd", "/tmp", BUN_CODEX]])
    assert.equal(await knownOf("bun", ["bun", ...opts]), false, `bun ${opts.join(" ")}`);
  for (const opts of [["--preload", "/tmp/e.js", DENO_GEMINI], ["--import-map=/tmp/m.json", DENO_GEMINI], ["-c", "/tmp/deno.json", DENO_GEMINI]])
    assert.equal(await knownOf("deno", ["deno", "run", "--no-config", ...opts]), false, `deno ${opts.join(" ")}`);
  // python: -m from the working directory (MEASURED: a planted ./json_tool ran under -m json_tool), a dotted
  // -W category is imported (MEASURED), -X pycache_prefix reads bytecode from elsewhere, -i reads stdin after
  const py = [["-m", "aider"], ["-Bm", "aider"], ["-W", "ignore::evil.W", AIDER], ["-X", "pycache_prefix=/tmp/p", AIDER], ["-i", AIDER], ["-c", "1", AIDER], ["-uc", "1", AIDER], ["-m", "json.tool"]];
  for (const opts of py) assert.equal(await knownOf("python", ["python3.12", ...opts]), false, `python ${opts.join(" ")}`);
  assert.equal(await knownOf("python", [AIDER_PY, "-m", "aider"]), false, "-m aider without -P or -I: the working directory comes first, even in the venv");
  assert.equal(await knownOf("python", [AIDER_PY, "-P", "-m", "aider"]), true, "-P keeps the working directory off sys.path; the venv's own python");
  assert.equal(await knownOf("python", ["/usr/bin/python3", "-I", "-m", "aider"]), false, "-m aider needs the tool's venv interpreter");
  // The reason is named, not only refused by the option allowlist behind it.
  const { mainProgram } = await import("../cli/ai-api-callers.mjs");
  assert.deepEqual(["--require", "--import", "--loader", "-e", "-", "--env-file", "--inspect", "--preserve-symlinks-main"].map((o) => mainProgram(["node", o, CLAUDE_JS], "node")),
    ["preload", "import", "loader", "inline", "stdin", "env-file", "inspector", "symlinks"].map((loads) => ({ loads })));
  assert.deepEqual(mainProgram(["python3", "-uc", "1"], "python"), { loads: "inline" });
  assert.deepEqual(mainProgram(["bun", "--preload", "/tmp/e.js", BUN_CODEX], "bun"), { loads: "preload" });
});

// Rule 3: the main script must be a known package's own bin entry inside a package manager's install location.
test("rule 3, location and entry: a package name in a path is not enough", async () => {
  for (const [kind, argv] of [["node", ["node", "/opt/homebrew/bin/gemini"]], ["node", ["node", CODEX_NVM]], ["node", ["node", "/Users/u/Library/pnpm/global/5/node_modules/@github/copilot/npm-loader.js"]],
    ["node", ["node", QWEN_VOLTA]], ["node", ["node", CRUSH_YARN]], ["node", ["node", "/Users/u/.npm-global/bin/claude"]], ["python", ["python3.12", "/Users/u/.local/bin/aider", "--model", "x"]]])
    assert.equal(await knownOf(kind, argv), true, `${argv.join(" ")} is an installed entry`);
  const bad = [
    ["node", "/tmp/node_modules/@anthropic-ai/claude-code/cli.js", "not an install location"],
    ["node", "/usr/local/lib/node_modules/evil/node_modules/@anthropic-ai/claude-code/cli.js", "nested in another package"],
    ["node", "/Users/u/.npm-global/lib/node_modules/@anthropic-ai/claude-code/evil.js", "not the package's bin entry"],
    ["node", "/usr/local/lib/node_modules/@openai/codex/bin/codex.js", "package.json names another package"],
    ["python", "/tmp/x/venvs/aider-chat/bin/aider", "not a pipx or uv venv"],
    ["python", "/tmp/site-packages/aider/main.py", "not a console script"]
  ];
  for (const [kind, p, why] of bad) assert.equal(await knownOf(kind, [IMAGE[kind], p]), false, why);
  assert.equal(await knownOf("deno", ["deno", "run", "-A", "npm:@google/gemini-cli@0.60.0"]), false, "a package spec is resolved by the registry and the cwd's config");
  assert.equal(await knownOf("deno", ["deno", "run", "-A", DENO_GEMINI]), false, "deno without --no-config reads the cwd's deno.json");
  assert.equal(await knownOf("bun", ["bun", "x", "@github/copilot"]), false, "bun x resolves from the cwd's node_modules first");
});

// Rule 4: a Windows CommandLine is split by CommandLineToArgvW's rules; a line two splitters read differently,
// or one that holds a line break, never yields a known process.
test("rule 4, Windows: CommandLineToArgvW quoting and backslashes; argv[0] has no escapes", async () => {
  const { winArgv } = await import("../cli/ai-api-callers.mjs");
  assert.deepEqual(winArgv(String.raw`"C:\Program Files\nodejs\node.exe" "${W_GEMINI}" -p "say \"hi\"" a\\b`), [String.raw`C:\Program Files\nodejs\node.exe`, W_GEMINI, "-p", 'say "hi"', String.raw`a\\b`]);
  assert.deepEqual(winArgv(String.raw`node.exe "C:\tmp\dir\\" ${W_GEMINI}`), ["node.exe", String.raw`C:\tmp\dir\\`.slice(0, -1), W_GEMINI], "2n backslashes + quote: n backslashes, the quote closes");
  assert.equal(winArgv(String.raw`"C:\nodejs\node.exe\\" C:\tmp\evil.js " ${W_GEMINI}"`)[1], String.raw`C:\tmp\evil.js`, "argv[0] ends at the next quote, backslash or not");
  for (const bad of [String.raw`node.exe "a""b" x`, String.raw`C:\no"de.exe x`, String.raw`"C:\node.exe"x y`, String.raw`node.exe "unclosed`])
    assert.equal(winArgv(bad), null, `read one way or not at all: ${bad}`);
});

test("rule 4, Windows: PowerShell hands the CommandLine over base64, a forged line or a doubled pid is dropped", async () => {
  const { readArgv, winArgvScript, parseWinCommandLines } = await import("../cli/ai-api-callers.mjs");
  const b64 = (s) => Buffer.from(s, "utf16le").toString("base64");
  const forged = `"C:\\Program Files\\nodejs\\node.exe" ${W_TEMP}\r\n6144|"C:\\Program Files\\nodejs\\node.exe" "${W_GEMINI}"`;
  const m = parseWinCommandLines([`6144|${b64(forged)}`, `7000|${b64("node.exe a")}`, `7000|${b64(`node.exe "${W_GEMINI}"`)}`, `7100|${b64('node.exe "a""b"')}`, ""].join("\r\n"));
  assert.ok(m.get("6144").argv[1].startsWith(`${W_TEMP}\r\n6144|`), "a line break inside one command line stays inside its argument");
  assert.equal(m.size, 1, "and makes no second record");
  assert.equal(m.has("7000"), false, "a pid seen twice is dropped");
  assert.equal(m.has("7100"), false, "an unparseable command line is dropped");
  const canned = [`5120|${b64(`"C:\\Program Files\\nodejs\\node.exe" "${W_GEMINI}" -p "summarise"`)}`, `6144|${b64(`"C:\\Program Files\\nodejs\\node.exe" ${W_TEMP}`)}`,
    `6200|${b64(`"C:\\nodejs\\node.exe\\\\" ${W_TEMP} " ${W_GEMINI}"`)}`, ""].join("\r\n");
  const scripts = [];
  const argvOf = (pids) => readArgv(pids, { platform: "win32", run: (s) => { scripts.push(s); return canned; } });
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const r = aiApiCallers([est(5120, "node.exe", "172.66.0.243"), est(6144, "node.exe", "172.66.0.243"), est(6200, "node.exe", "172.66.0.243"), est(7, "ChatGPT", "172.66.0.243")], resolved,
    { moorai: new Set(), argvOf, ...FX, platform: "win32", home: String.raw`C:\Users\u` });
  assert.deepEqual(r.callers, [
    { processImage: "ChatGPT", provider: "openai", known: true, connections: 1 },
    { processImage: "node.exe", provider: "openai", known: false, connections: 2 },
    { processImage: "node.exe", provider: "openai", known: true, connections: 1 }
  ]);
  assert.equal(scripts.length, 1, "one PowerShell for every script-host pid");
  assert.equal(scripts[0], winArgvScript(["5120", "6144", "6200"]), "only the script-host pids are asked about");
  assert.match(scripts[0], /ToBase64String/);
});

// Rule 5: Claude Code's native install is known by the kernel's executable path, anchored to this home, and on
// macOS by Anthropic's code signature on the running process; argv[0] is never consulted.
test("rule 5, native Claude Code: executable in $HOME/.local/share/claude/versions, signed by Anthropic on macOS", async () => {
  const resolved = await resolveAiHosts({ lookup: lookupOf(DNS) });
  const V = "/Users/u/.local/share/claude/versions/2.1.295";
  const argv = argvMap({ 61: [V, "-p"], 62: [V], 63: ["/tmp/x/claude/versions/2.1.295"], 64: [V], 65: [V] });
  const exeOf = () => new Map([["61", { exe: V, signed: true }], ["62", { exe: "/tmp/2.1.295", signed: true }], ["63", { exe: "/tmp/x/claude/versions/2.1.295", signed: true }], ["64", { exe: V, signed: false }]]);
  const sockets = [61, 62, 63, 64, 65].map((p) => est(p, "2.1.295", "160.79.104.10"));
  const known = (opts) => Object.fromEntries(sockets.map((s) => [s.pid, aiApiCallers([s], resolved, { moorai: new Set(), argvOf: argv, exeOf, ...FX, ...opts }).callers[0].known]));
  assert.deepEqual(known({}), { 61: true, 62: false, 63: false, 64: false, 65: false }, "macOS: path AND signature; argv[0] claims nothing");
  assert.deepEqual(known({ platform: "linux", home: "/Users/u" }), { 61: true, 62: false, 63: false, 64: true, 65: false }, "Linux: the location alone");
  assert.deepEqual(known({ platform: "win32" }), { 61: false, 62: false, 63: false, 64: false, 65: false }, "Windows' native install runs as claude.exe");
});

test("rule 5, readExe: codesign's Executable= line and the requirement's exit code (macOS), /proc/<pid>/exe (Linux)", async () => {
  const { readExe, CLAUDE_CODE_REQUIREMENT } = await import("../cli/ai-api-callers.mjs");
  const calls = [];
  const run = (args) => { calls.push(args); return args[0] === "-d" ? { status: 0, stderr: `Executable=/Users/u/.local/share/claude/versions/2.1.295\n` } : { status: args[2] === "61" ? 0 : 3, stderr: "" }; };
  const m = readExe(["61", "62", "x;y"], { platform: "darwin", run });
  assert.deepEqual(m.get("61"), { exe: "/Users/u/.local/share/claude/versions/2.1.295", signed: true });
  assert.deepEqual(m.get("62"), { exe: "/Users/u/.local/share/claude/versions/2.1.295", signed: false });
  assert.ok(calls.some((a) => a[0] === "--verify" && a[1] === `-R=${CLAUDE_CODE_REQUIREMENT}`), "the running pid is checked against the requirement");
  assert.ok(!calls.flat().includes("x;y"), "non-numeric pids are dropped");
  const lin = readExe(["61"], { platform: "linux", readlink: (p) => (p === "/proc/61/exe" ? "/home/u/.local/share/claude/versions/2.1.295" : "") });
  assert.deepEqual(lin.get("61"), { exe: "/home/u/.local/share/claude/versions/2.1.295", signed: null });
  assert.equal(readExe(["61"], { platform: "win32" }).size, 0);
});

// Rule 6: whatever the grammar cannot place is unknown.
test("rule 6, unparseable: an unlisted option, an ambiguous macOS ps line, a relative script", async () => {
  assert.equal(await knownOf("node", ["node", "--frobnicate", CLAUDE_JS]), false, "an option node may give a value to");
  assert.equal(await knownOf("node", ["node", "--title", CLAUDE_JS]), false, "a value option in its spaced form");
  assert.equal(await knownOf("python", ["python3.12", "-J", AIDER]), false);
  assert.equal(await knownOf("bun", ["bun", "--frobnicate", BUN_CODEX]), false);
  assert.equal(await knownOf("deno", ["deno", "run", "--no-config", "--frobnicate", DENO_GEMINI]), false);
  assert.equal(await knownOf("node", ["node", "cli.js"]), false, "relative: the process's cwd is not read");
  // macOS ps joins argv with spaces: "/tmp/a" and "/tmp/a /Users/u/.npm-global/bin/claude" both exist → two readings
  assert.equal(await knownOf("node", { argv: ["node", "/tmp/a", "/Users/u/.npm-global/bin/claude"], spaced: true }), false, "two readings of one ps line");
  assert.equal(await knownOf("node", { argv: ["node", "/Users/u/My", "Tools/node_modules/@google/gemini-cli/bundle/gemini.js"], spaced: true }), false, "one reading, but not an install location");
  assert.equal(await knownOf("node", { argv: ["node", "--title=a\\012b", CLAUDE_JS], spaced: true }), false, "ps prints a newline as \\012 and a backslash as itself: undecodable");
  assert.equal(await knownOf("node", { argv: ["node", CLAUDE_JS, "-p"], spaced: true }), true, "a ps line with one reading");
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
