// The command hook is one process per tool call, so every module it loads is paid on every call. Modules only
// some paths need are loaded at their point of use (cli/moorai-hook.mjs); this pins that a typical call does not
// load them, through the real hook with a module-load trace (test/load-trace.mjs), and that the paths which do
// need them still load them. It also pins cli/hook-boot.mjs as the hook's first import.
//
//   node --test test/hook-lazy-load.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import module from "node:module";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TRACE = pathToFileURL(join(ROOT, "test", "load-trace.mjs")).href;
const WIN = process.platform === "win32";
const skip = typeof module.registerHooks !== "function" ? "module.registerHooks needs Node 22.15+" : false;

// Loaded only where a path needs them. MXC containment is Windows-only and still loads at startup there.
const DEFERRED = [
  "cli/mcp-reputation.mjs", "cli/mcp-package.mjs", "cli/quarantine-step.mjs", "cli/quarantine-reader.mjs", "cli/credential-exposure.mjs",
  "cli/mxc-detect.mjs", "cli/local-ai-inventory.mjs", "cli/oversight-disclosure.mjs", "cli/oversight-mcp.mjs", "cli/mcp-file-args.mjs",
  "data/agent-baseline.js", "cli/transcript-usage.mjs",
  ...(WIN ? [] : ["cli/containment-enforce.mjs", "cli/containment-guard.mjs"])
];

function sandbox(t) {
  const home = mkdtempSync(join(tmpdir(), "moorai-lazy-"));
  t.after(() => rmTree(home));
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, "notes.txt"), "plain text\n");
  const env = { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".xdg-config"), XDG_STATE_HOME: join(home, ".xdg-state"), APPDATA: join(home, "AppData", "Roaming"), LOCALAPPDATA: join(home, "AppData", "Local") };
  return { home, proj, env };
}
function loaded(sb, input, n) {
  const out = join(sb.home, `trace-${n}.json`);
  const r = spawnSync(process.execPath, ["--import", TRACE, HOOK], { input: JSON.stringify(input), env: { ...sb.env, MOORAI_LOAD_TRACE: out }, cwd: sb.proj, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const urls = JSON.parse(readFileSync(out, "utf8"));
  return { r, rel: new Set(urls.filter((u) => u.startsWith("file:")).map((u) => fileURLToPath(u).slice(ROOT.length + 1).replaceAll("\\", "/"))) };
}

test("a typical tool call and prompt do not load the modules only some paths need", { skip }, (t) => {
  const sb = sandbox(t);
  const calls = [
    { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls -la src" } },
    { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: join(sb.proj, "notes.txt") } },
    { hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: join(sb.proj, "out.txt"), content: "hello" } },
    { hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: { file_path: join(sb.proj, "notes.txt"), old_string: "plain", new_string: "flat" } },
    { hook_event_name: "UserPromptSubmit", prompt: "list the files in this folder" }
  ];
  calls.forEach((c, i) => {
    const { rel } = loaded(sb, { session_id: "s-lazy", cwd: sb.proj, ...c }, i);
    assert.ok(rel.has("cli/hook-core.mjs") && rel.has("src/engine.js"), `the trace saw the hook's own graph (${rel.size} modules)`);
    const hit = DEFERRED.filter((m) => rel.has(m));
    assert.deepEqual(hit, [], `${c.tool_name || c.hook_event_name} loaded ${hit.join(", ")}`);
    if (WIN) assert.ok(rel.has("cli/containment-enforce.mjs"), "Windows loads MXC containment at startup");
  });
});

test("an MCP call still loads the reputation, file-argument and MCP oversight modules", { skip }, (t) => {
  const sb = sandbox(t);
  const { rel } = loaded(sb, { hook_event_name: "PreToolUse", session_id: "s-lazy", cwd: sb.proj, tool_name: "mcp__filesystem__read_file", tool_input: { path: "notes.txt" } }, "mcp");
  for (const m of ["cli/mcp-reputation.mjs", "cli/mcp-file-args.mjs", "cli/oversight-mcp.mjs"]) assert.ok(rel.has(m), `${m} loaded for an MCP call`);
});

test("cli/hook-boot.mjs is the hook's first import, so its V8 setting precedes every other module", () => {
  const first = readFileSync(HOOK, "utf8").split("\n").find((l) => /^import\b/.test(l));
  assert.equal(first, 'import "./hook-boot.mjs";');
});
