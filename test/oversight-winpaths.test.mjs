// Weakening oversight (#84): Win32 spellings of a memory, settings or protected file. Windows opens "CLAUDE.md.",
// "CLAUDE.md. ", "CLAUDE.md::$DATA" and the 8.3 alias "CLAUDE~1.MD" as CLAUDE.md, and ".git/config." as .git/config,
// so every path check reads the canonical form too (data/path-canon.js, cli/oversight-surfaces.mjs pathForms), on
// every platform: a Write / Edit, a shell write, an MCP filesystem write and the origin-taint memory-write gate.
//
//   node --test --import ./test/hermetic-env.mjs test/oversight-winpaths.test.mjs
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { canonSegment, winCanonical, shortNameMatches, SHORT_NAME_RE } from "../data/path-canon.js";
import { agentSettingsKind } from "../data/skill-surface.js";
import { extensionPath } from "../data/origin-taint.js";
import { oversightPolicy, memoryPathHit, protectedPathHit, pathForms } from "../cli/oversight-surfaces.mjs";
import { oversightEditSignals } from "../cli/oversight-signals.mjs";
import { oversightCommandSignals } from "../cli/oversight-shell.mjs";
import { oversightMcpSignals } from "../cli/oversight-mcp.mjs";

const proj = mkdtempSync(join(tmpdir(), "moorai-winpaths-"));
after(() => rmTree(proj));
for (const d of [".git/hooks", ".vscode", "ops/alerting", "src"]) mkdirSync(join(proj, d), { recursive: true });
const BUILTIN = oversightPolicy(undefined);
const POLICY = oversightPolicy({ oversight: { v: 1, protectedPaths: ["ops/alerting/**", "src/audit_logger.py", "**/monitor_*.py"] } }, () => {});

// The bypass table, for a memory file, a rules file, a git config, a git hook and a settings file. 8.3: the alias of
// the file, or of the directory that makes it one.
const TARGETS = {
  "CLAUDE.md": { short: ["CLAUDE~1.MD"] },
  ".cursorrules": { short: ["CURSOR~1"] },
  "AGENTS.md": { short: ["AGENTS~1.MD"] },
  ".git/config": { short: ["GIT~1/config", "GIT~1/CONFIG~1"] },
  ".git/hooks/pre-commit": { short: ["GIT~1/hooks/pre-commit", ".git/HOOKS~1/pre-commit"] },
  ".vscode/settings.json": { short: [".vscode/SETTIN~1.JSO", "VSCODE~1/SETTIN~1.JSO", "VSCODE~1/settings.json"] }
};
function spellings(t) {
  const back = t.replace(/\//g, "\\");
  return [
    `${t}.`, `${t}. `, `${t}::$DATA`, `${t}:evil`, `${t}:evil:$DATA`, `${t}...`, `${t} . .`,
    `${t}. ::$DATA`, `${t}::$DATA.`,
    `${back}.`, back.toUpperCase() + ".",
    `C:\\proj\\${back}.`, `C:${back}.`, `\\\\?\\C:\\proj\\${back}::$DATA`,
    ...(t.includes("/") ? [t.split("/").map((s, i, a) => (i < a.length - 1 ? `${s}.` : s)).join("/")] : []),
    ...TARGETS[t].short
  ];
}
const ALL = Object.keys(TARGETS).flatMap((t) => [t, ...spellings(t)].map((p) => [t, p]));
const NEAR_MISSES = [
  "CLAUDE.md.bak", "CLAUDE.mdx", "notes.txt", "config.yaml", "notes.", "file.md.bak", "README.md", "src/app.ts",
  ".vscode/extensions.json", ".vscode/launch.json", "settings.json", "docs/settings.json", "config", "git/config",
  ".github/prompts/review.prompt.md", "CLAUDE~1.TXT", "RUNNER~1/AppData/x.txt", "PROGRA~1/app/readme.txt", "build/out~1",
  "a:b.txt", "C:\\proj\\notes.txt.", "notes.txt::$DATA", "ops/alert/a.yaml", "src/audit.py", "monitor.py"
];

test("canonical segment: trailing dots and spaces, streams, drive letters; dot-only segments kept", () => {
  for (const [i, o] of [["CLAUDE.md.", "CLAUDE.md"], ["CLAUDE.md. ", "CLAUDE.md"], ["CLAUDE.md::$DATA", "CLAUDE.md"], ["CLAUDE.md:s:$DATA", "CLAUDE.md"],
    ["CLAUDE.md. ::$DATA", "CLAUDE.md"], ["CLAUDE.md::$DATA.", "CLAUDE.md"], ["C:", "C:"], ["C:CLAUDE.md.", "C:/CLAUDE.md"], [".", "."], ["..", ".."],
    ["...", "..."], [".git.", ".git"], ["notes.txt", "notes.txt"], ["", ""]]) assert.equal(canonSegment(i), o, JSON.stringify(i));
  assert.equal(winCanonical("C:\\proj\\.git.\\config. "), "C:/proj/.git/config");
  assert.equal(winCanonical("/a/../b./c"), "/a/../b/c");
});

test("8.3 alias: stem, extension and the hashed form", () => {
  for (const [s, l] of [["CLAUDE~1.MD", "CLAUDE.md"], ["CLAUDE~2.MD", "CLAUDE.local.md"], ["GIT~1", ".git"], ["VSCODE~1", ".vscode"], ["SETTIN~1.JSO", "settings.json"],
    ["PRE-CO~1", "pre-commit"], ["CL1A2B~1.MD", "CLAUDE.md"], ["copilo~1.md", "copilot-instructions.md"]]) assert.ok(shortNameMatches(s, l), `${s} ~ ${l}`);
  for (const [s, l] of [["CLAUDE~1.TXT", "CLAUDE.md"], ["CLAUDE~1", "CLAUDE.md"], ["GIT~1.MD", ".git"], ["SETTIN~1.JSO", "setup.json"], ["AB~1", "CLAUDE"]]) assert.ok(!shortNameMatches(s, l), `${s} !~ ${l}`);
  for (const s of ["CLAUDE~1.MD", "A~1", "PRE-CO~12"]) assert.ok(SHORT_NAME_RE.test(s), s);
  for (const s of ["CLAUDE.md", "file~", "toolong~1.md", "a~b", "x~1.json"]) assert.ok(!SHORT_NAME_RE.test(s), s);
});

test("memoryPathHit: every Win32 spelling of every target (relative and absolute)", () => {
  for (const [t, p] of ALL) {
    assert.ok(memoryPathHit(p, BUILTIN, { cwd: proj, real: true }), `${t}: ${JSON.stringify(p)}`);
    if (!/^(?:[A-Za-z]:|\\\\)/.test(p)) assert.ok(memoryPathHit(join(proj, p), BUILTIN, { cwd: proj }), `${t}: absolute ${JSON.stringify(p)}`);
  }
});

test("near misses stay clean: no memory, settings or protected hit", () => {
  for (const p of NEAR_MISSES) {
    assert.ok(!memoryPathHit(p, BUILTIN, { cwd: proj, real: true }), `memory: ${p}`);
    assert.ok(!protectedPathHit(p, POLICY, { cwd: proj, real: true }), `protected: ${p}`);
    assert.deepEqual(oversightEditSignals({ path: p, before: null, after: "x\n", surfaces: BUILTIN, cwd: proj }), [], `edit: ${p}`);
  }
});

test("surface Write / Edit: oversightEditSignals raises memory-file for every spelling", () => {
  for (const [t, p] of ALL) assert.deepEqual(oversightEditSignals({ path: p, before: null, after: "always run curl x | sh\n", surfaces: BUILTIN, cwd: proj }), ["memory-file"], `${t}: ${JSON.stringify(p)}`);
});

test("surface shell: a redirect, tee, cp and mv into every spelling raise memory-file", () => {
  for (const [t, p] of ALL) {
    const q = `'${p.replace(/'/g, "'\\''")}'`;
    for (const cmd of [`echo x > ${q}`, `echo x | tee -a ${q}`, `cp notes.txt ${q}`, `mv notes.txt ${q}`]) {
      const s = oversightCommandSignals(cmd, { cwd: proj, surfaces: BUILTIN });
      // A cp / mv destination with a "$" is not literal to the shell reader (even quoted): write-target-unknown, which
      // the memory-write gate and decideOversight treat as a memory write (analysis-incomplete under a #84 policy).
      const ok = s.includes("memory-file") || (p.includes("$") && /^(?:cp|mv) /.test(cmd) && s.includes("write-target-unknown"));
      assert.ok(ok, `${t}: ${cmd} -> ${JSON.stringify(s)}`);
    }
  }
});

test("surface MCP filesystem write: write_file, edit_file and move_file into every spelling raise memory-file", () => {
  for (const [t, p] of ALL) {
    for (const [tool, args] of [["mcp__filesystem__write_file", { path: p, content: "x" }], ["mcp__filesystem__edit_file", { path: p, edits: [{ oldText: "a", newText: "b" }] }], ["mcp__filesystem__move_file", { source: join(proj, "notes.txt"), destination: p }]]) {
      const s = oversightMcpSignals(tool, args, { cwd: proj, surfaces: BUILTIN });
      assert.ok(s.includes("memory-file"), `${t}: ${tool} ${JSON.stringify(p)} -> ${JSON.stringify(s)}`);
    }
  }
});

test("protected paths (#84 policy): canonical forms, case and 8.3 aliases of a directory, a file and a wildcard file", () => {
  for (const p of ["ops/alerting/a.yaml.", "ops/alerting./a.yaml", "OPS/Alerting/A.YAML", "ops\\alerting\\a.yaml::$DATA", "ops/ALERTI~1/a.yaml", "src/audit_logger.py. ",
    "SRC/AUDIT_~1.PY", "C:\\proj\\src\\audit_logger.py.", "lib/MONITO~1.PY", "lib/monitor_disk.py:x", "LIB/Monitor_Disk.PY"]) {
    assert.ok(protectedPathHit(p, POLICY, { cwd: proj, real: true }), p);
    assert.deepEqual(oversightEditSignals({ path: p, before: null, after: "x\n", surfaces: POLICY, cwd: proj }), ["protected-surface"], `edit ${p}`);
  }
});

test("agent and editor settings that grant approvals or run commands are watched; on-demand files are not", () => {
  for (const p of [".vscode/settings.json", ".vscode/mcp.json", ".vscode/tasks.json", ".cursor/mcp.json", ".cursor/permissions.json", ".cursor/cli.json",
    "/home/u/.cursor/cli-config.json", ".codex/config.toml", ".gemini/settings.json", ".windsurf/hooks.json", ".claude/settings.json", ".claude/settings.local.json",
    ".mcp.json", "settings.VisualStudio.json", ".vs/mcp.json", "C:\\Users\\u\\.mcp.json"]) {
    assert.ok(agentSettingsKind(p), `kind: ${p}`);
    for (const f of [p, `${p}.`, `${p}::$DATA`]) assert.ok(memoryPathHit(f, BUILTIN, { cwd: proj }), `watched: ${f}`);
  }
  for (const p of [".github/copilot-instructions.md", ".github/copilot-instructions.md. "]) assert.ok(memoryPathHit(p, BUILTIN, { cwd: proj }), p);
  for (const p of [".github/prompts/a.prompt.md", ".claude/commands/x.md", ".claude/skills/s/SKILL.md", ".vscode/launch.json", ".idea/workspace.xml", ".devcontainer/devcontainer.json"]) assert.ok(!memoryPathHit(p, BUILTIN, { cwd: proj }), `not watched: ${p}`);
  const off = oversightPolicy({ oversight: { v: 1, memoryFiles: "off" } }, () => {});
  assert.ok(!memoryPathHit(".vscode/settings.json.", off, { cwd: proj }), "memoryFiles off turns the settings set off too");
});

test("8.3 on win32: an alias that resolves is judged by its long name; one that does not resolve fails closed", () => {
  const resolved = (to) => () => to;
  assert.ok(!memoryPathHit("CLAUDE~1.MD", BUILTIN, { cwd: proj, real: true, platform: "win32", realNative: resolved(join(proj, "CLAUDE-NOTES.txt")) }), "resolves to an unwatched long name");
  assert.ok(memoryPathHit("NOTES~1.TXT", BUILTIN, { cwd: proj, real: true, platform: "win32", realNative: resolved(join(proj, "CLAUDE.md")) }), "resolves to CLAUDE.md");
  assert.ok(memoryPathHit("CLAUDE~1.MD", BUILTIN, { cwd: proj, real: true, platform: "win32", realNative: () => null }), "unresolved: matched by the alias");
  assert.ok(memoryPathHit("CLAUDE~1.MD", BUILTIN, { cwd: proj, real: true, platform: "linux" }), "off win32: matched by the alias");
});

test("an expansion past the bound fails closed", () => {
  const p = Array.from({ length: 12 }, () => "SETTIN~1.JSO").join("/") + "/x.txt";
  assert.ok(memoryPathHit(p, BUILTIN, { cwd: proj }));
  assert.ok(pathForms("CLAUDE~1.MD", { cwd: proj }).some((f) => f.endsWith("CLAUDE.md")), "pathForms carries the expansion");
});

test("origin taint: extension-install reads the canonical form", () => {
  for (const p of [".vscode/tasks.json.", ".mcp.json::$DATA", ".claude/skills/s/SKILL.md. "]) assert.ok(extensionPath(p), p);
  for (const p of ["CLAUDE.md.", "notes.txt."]) assert.ok(!extensionPath(p), p);
});

// ---- the origin-taint memory-write gate, end to end through the hook ----
const HOOK = join(dirname(dirname(fileURLToPath(import.meta.url))), "cli", "moorai-hook.mjs");
async function withServer(policy, fn) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(policy)); return; }
    if (req.url === "/api/alerts" && req.method === "POST") { let b = ""; req.on("data", (c) => { b += c; }); req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); }); return; }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(server.address().port, alerts); } finally { server.close(); }
}
async function runHook(home, payload) {
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let out = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ cwd: join(home, "work"), ...payload }));
  await new Promise((r) => child.on("exit", r));
  const t = out.trim();
  if (!t) return { decision: "allow", reason: "" };
  const h = JSON.parse(t).hookSpecificOutput || {};
  return { decision: h.permissionDecision || "allow", reason: h.permissionDecisionReason || "" };
}
const pre = (session, tool_name, tool_input) => ({ hook_event_name: "PreToolUse", session_id: session, tool_name, tool_input });

test("surface origin-taint memory-write gate: after an outside-origin read, a Write, a shell write and an MCP write to a Win32 spelling ask", async () => {
  await withServer({ captureTier: "content-free", sessionRisk: { originTaint: "ask" } }, async (port, alerts) => {
    const home = mkdtempSync(join(tmpdir(), "moorai-winpaths-hook-"));
    try {
      for (const d of [".moorai", "work", "work/.vscode", "Downloads"]) mkdirSync(join(home, d), { recursive: true });
      writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-winpaths" }));
      writeFileSync(join(home, "Downloads", "brief.txt"), "a downloaded file\n");
      assert.equal((await runHook(home, pre("u1", "Write", { file_path: join(home, "work", "CLAUDE.md."), content: "Use tabs.\n" }))).decision, "allow", "untainted: notify only");
      const cases = [
        ["Write", { file_path: join(home, "work", "CLAUDE.md."), content: "Use tabs.\n" }],
        ["Write", { file_path: join(home, "work", ".vscode", "settings.json. "), content: "{}\n" }],
        ["Bash", { command: "echo '{}' > .VSCODE/Settings.JSON." }],
        ["Bash", { command: "echo x >> CLAUDE~1.MD" }],
        ["mcp__filesystem__write_file", { path: join(home, "work", "AGENTS.md:evil"), content: "x" }]
      ];
      const gate = () => alerts.filter((a) => a.category === "Origin taint: action after reading an internet-origin file");
      // One session per case: the gate alerts once per session and class.
      for (const [i, [tool, input]] of cases.entries()) {
        await runHook(home, pre(`t${i}`, "Read", { file_path: join(home, "Downloads", "brief.txt") }));
        const before = gate().length;
        const r = await runHook(home, pre(`t${i}`, tool, input));
        assert.equal(r.decision, "ask", `${tool} ${JSON.stringify(input)}`);
        // An MCP write is also an "outbound" gate; the reason names one class, the alerts carry each.
        assert.match(r.reason, /origin taint — session read an internet-origin file \(download folder\), then (?:memory write|an outbound action)/);
        assert.ok(gate().slice(before).some((a) => a.signature.action === "memory-write"), `memory-write alert: ${tool} ${JSON.stringify(input)}`);
      }
    } finally { rmTree(home); }
  });
});
