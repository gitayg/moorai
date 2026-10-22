// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/agent-hook-antigravity.test.mjs
//
// Drives the real entry point (cli/moorai-agent-hook.mjs antigravity) with stdin in the shape Google
// documents for Antigravity's PreToolUse hook (antigravity.google/docs/hooks: `toolCall` {name, args},
// `stepIdx`, `conversationId`, `workspacePaths`, `modelName`; the run_command example is the fixture) and
// asserts the stdout Antigravity documents: `decision` "allow" | "deny" | "force_ask" (+ `reason`).
// MoorAI never answers "auto_approve" and never sends `overwrite` or `permissionOverrides`. No agy binary
// is run: none is installed here, and the adapter has not been run against one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { toClaude, fromVerdict, PRE_MATCHER, hooksFile } from "../cli/agent-hooks/antigravity.mjs";
import { hostTable, checkHost } from "../cli/doctor-hosts.mjs";
import { ROOT, REVERSE_SHELL, UNTRUSTED_INSTALL, AWS_ENV, sandbox, runAgent, runAgentAsync, policyServer } from "./agent-hook-harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const FIXTURE = JSON.parse(readFileSync(join(ROOT, "test", "fixtures", "agent-hooks", "antigravity", "pre-tool-use-run-command.json"), "utf8"));
const box = () => sandbox("antigravity");
const payload = (home, name, args, extra = {}) => ({ ...FIXTURE, toolCall: { name, args }, workspacePaths: [join(home, "proj")], ...extra });
const run = (home, stdin, args) => runAgent("antigravity", home, stdin, args);

// Reads the answer the way Antigravity documents it.
function agVerdict(res) {
  assert.equal(res.status, 0, `exit ${res.status}: ${res.stderr}`);
  const out = res.stdout.trim();
  const j = out ? JSON.parse(out) : {};
  assert.ok(!("overwrite" in j) && !("permissionOverrides" in j), "MoorAI never rewrites the call or grants permissions");
  assert.notEqual(j.decision, "auto_approve", "MoorAI never auto-approves");
  assert.notEqual(j.decision, "ask", "ask respects Always Allow; MoorAI uses force_ask");
  if (j.decision === "deny" || j.decision === "force_ask") assert.match(j.reason, /^MoorAI: \S/);
  return { decision: j.decision || "none", reason: j.reason };
}
const pre = (home, name, args, extra) => agVerdict(run(home, payload(home, name, args, extra)));

test("the documented run_command payload is allowed with an explicit allow (delegates to Antigravity's policy)", () => {
  const home = box();
  try {
    const res = run(home, FIXTURE);
    assert.equal(res.status, 0, res.stderr);
    assert.deepEqual(JSON.parse(res.stdout), { decision: "allow" });
  } finally { rmTree(home); }
});

test("reverse shell in run_command is denied with decision deny and a MoorAI reason", () => {
  const home = box();
  try {
    assert.equal(pre(home, "run_command", { CommandLine: REVERSE_SHELL, Cwd: join(home, "proj") }).decision, "deny");
  } finally { rmTree(home); }
});

test("curl | bash (MoorAI ask) is force_ask, so an earlier Always Allow cannot skip the prompt", () => {
  const home = box();
  try {
    assert.equal(pre(home, "run_command", { CommandLine: UNTRUSTED_INSTALL }).decision, "force_ask");
  } finally { rmTree(home); }
});

test("write_to_file: benign content passes, a reverse-shell script is denied", () => {
  const home = box();
  try {
    assert.equal(pre(home, "write_to_file", { TargetFile: join(home, "proj", "a.txt"), CodeContent: "hello", Overwrite: false }).decision, "allow");
    assert.equal(pre(home, "write_to_file", { TargetFile: join(home, "proj", "run.sh"), CodeContent: `#!/bin/sh\n${REVERSE_SHELL}\n`, Overwrite: true }).decision, "deny");
  } finally { rmTree(home); }
});

test("replace_file_content and multi_replace_file_content are content-checked", () => {
  const home = box();
  try {
    const f = join(home, "proj", "run.sh");
    assert.equal(pre(home, "replace_file_content", { TargetFile: f, TargetContent: "echo hi", ReplacementContent: REVERSE_SHELL, AllowMultiple: false }).decision, "deny");
    // multi_replace_file_content's argument names are not documented: whatever shape it has, its strings are scanned.
    assert.equal(pre(home, "multi_replace_file_content", { TargetFile: f, ReplacementChunks: [{ TargetContent: "echo hi", ReplacementContent: REVERSE_SHELL }] }).decision, "deny");
    assert.equal(pre(home, "multi_replace_file_content", { TargetFile: f, Unknown: [{ Deep: { Text: REVERSE_SHELL } }] }).decision, "deny");
    assert.equal(pre(home, "multi_replace_file_content", { TargetFile: join(home, "proj", "a.txt"), ReplacementChunks: [{ TargetContent: "a", ReplacementContent: "b" }] }).decision, "allow");
  } finally { rmTree(home); }
});

test("view_file of a planted .env is denied under a #39 block policy; README stays allowed", async () => {
  const { srv, url } = await policyServer({ threatPolicy: { 39: "block" } });
  const home = sandbox("antigravity", url);
  try {
    writeFileSync(join(home, "proj", ".env"), AWS_ENV);
    writeFileSync(join(home, "proj", "README.md"), "hello\n");
    const bad = agVerdict(await runAgentAsync("antigravity", home, url, payload(home, "view_file", { AbsolutePath: join(home, "proj", ".env") })));
    assert.equal(bad.decision, "deny");
    const ok = agVerdict(await runAgentAsync("antigravity", home, url, payload(home, "view_file", { AbsolutePath: join(home, "proj", "README.md") })));
    assert.equal(ok.decision, "allow");
  } finally { srv.close(); rmTree(home); }
});

test("MCP tools named mcp_<server>_<tool> or mcp__<server>__<tool> are judged by the MCP checks", () => {
  const home = box();
  try {
    assert.equal(pre(home, "mcp_shellbox_exec", { cmd: REVERSE_SHELL }).decision, "deny");
    assert.equal(pre(home, "mcp__shellbox__exec", { cmd: REVERSE_SHELL }).decision, "deny");
    assert.equal(pre(home, "mcp_docs_search", { query: "array sort" }).decision, "allow");
  } finally { rmTree(home); }
});

test("unmapped tools, other events and malformed stdin never deny (fail open)", () => {
  const home = box();
  try {
    for (const [name, args] of [["list_dir", { DirectoryPath: "." }], ["grep_search", { Query: "x" }], ["search_web", { query: "x" }]]) {
      assert.equal(pre(home, name, args).decision, "allow", name);
    }
    // PostToolUse's documented input has the same toolCall fields; MoorAI registers only PreToolUse, and a
    // payload that names another event is never judged.
    assert.equal(pre(home, "run_command", { CommandLine: REVERSE_SHELL }, { hookEventName: "PostToolUse" }).decision, "allow");
    for (const input of ["{not json", "", "[]", "null", "42", JSON.stringify({ toolCall: "run_command" }), JSON.stringify({ toolCall: { name: "run_command", args: "ls" } })]) {
      const res = run(home, input);
      assert.equal(res.status, 0, `input ${JSON.stringify(input)}: ${res.stderr}`);
      assert.doesNotMatch(res.stdout, /deny|force_ask/, `input ${JSON.stringify(input)}`);
    }
  } finally { rmTree(home); }
});

test("toClaude: Antigravity tool names onto MoorAI's canonical tools", () => {
  const ws = "/w/p";
  const t = (name, args) => toClaude({ toolCall: { name, args }, conversationId: "c1", workspacePaths: [ws] });
  assert.deepEqual(t("run_command", { CommandLine: "ls", Cwd: "/w/p/sub" }), { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "c1", cwd: "/w/p/sub" });
  assert.deepEqual(t("view_file", { AbsolutePath: "/w/p/a.txt", StartLine: 1 }).tool_input, { file_path: "/w/p/a.txt" });
  assert.equal(t("view_file", { AbsolutePath: "/w/p/a.txt" }).tool_name, "Read");
  assert.deepEqual(t("write_to_file", { TargetFile: "rel/a.txt", CodeContent: "x" }).tool_input, { file_path: "/w/p/rel/a.txt", content: "x" });
  assert.deepEqual(t("replace_file_content", { TargetFile: "/w/p/a", TargetContent: "o", ReplacementContent: "n" }), { hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: { file_path: "/w/p/a", old_string: "o", new_string: "n" }, session_id: "c1", cwd: ws });
  assert.deepEqual(t("read_url_content", { Url: "https://example.com/x" }).tool_input, { url: "https://example.com/x", prompt: "" });
  assert.equal(t("read_url_content", { Url: "https://example.com/x" }).tool_name, "WebFetch");
  assert.equal(t("invoke_subagent", { Prompt: "do it" }).tool_name, "Task");
  assert.equal(t("mcp_github_create_issue", { title: "x" }).tool_name, "mcp__github__create_issue");
  assert.equal(t("list_dir", { DirectoryPath: "." }), null);
  assert.equal(toClaude({ hookEventName: "PostToolUse", toolCall: { name: "run_command", args: { CommandLine: "ls" } } }), null);
  assert.equal(toClaude(null), null);
});

test("fromVerdict: deny, force_ask, explicit allow; coach goes to stderr and still allows", () => {
  const p = FIXTURE;
  assert.deepEqual(JSON.parse(fromVerdict({ decision: "deny", reason: "reverse shell" }, p).stdout), { decision: "deny", reason: "MoorAI: reverse shell" });
  assert.deepEqual(JSON.parse(fromVerdict({ decision: "ask", reason: "needs sign-off" }, p).stdout), { decision: "force_ask", reason: "MoorAI: needs sign-off" });
  assert.deepEqual(JSON.parse(fromVerdict({ decision: "allow", reason: "" }, p).stdout), { decision: "allow" });
  const c = fromVerdict({ decision: "allow", reason: "", coach: "try the safer way" }, p);
  assert.deepEqual(JSON.parse(c.stdout), { decision: "allow" });
  assert.match(c.stderr, /try the safer way/);
  for (const v of [{ decision: "deny" }, { decision: "ask" }, { decision: "allow" }]) assert.equal(fromVerdict(v, p).exitCode, 0);
});

test("install writes the moorai hook into ~/.gemini/config/hooks.json, keeps the user's hooks, is idempotent; uninstall removes only ours", () => {
  const home = box();
  try {
    const file = hooksFile(home);
    mkdirSync(join(home, ".gemini", "config"), { recursive: true });
    const mine = { "my-linter-hook": { PostToolUse: [{ matcher: "run_command", hooks: [{ type: "command", command: "./lint.sh", timeout: 10 }] }] } };
    writeFileSync(file, JSON.stringify(mine, null, 2));
    assert.equal(run(home, "", ["install"]).status, 0);
    assert.equal(run(home, "", ["install"]).status, 0);
    const d = JSON.parse(readFileSync(file, "utf8"));
    assert.deepEqual(d["my-linter-hook"], mine["my-linter-hook"]);
    assert.equal(d.moorai.PreToolUse.length, 1);
    assert.equal(d.moorai.PreToolUse[0].matcher, PRE_MATCHER);
    assert.equal(d.moorai.PreToolUse[0].hooks.length, 1);
    assert.match(d.moorai.PreToolUse[0].hooks[0].command, /moorai-agent-hook\.mjs" antigravity$/);
    assert.equal(d.moorai.PreToolUse[0].hooks[0].type, "command");
    assert.ok(!("PostToolUse" in d.moorai), "no PostToolUse: its input carries no tool result to scan");
    assert.equal(run(home, "", ["uninstall"]).status, 0);
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), mine);
  } finally { rmTree(home); }
});

test("install into a fresh HOME creates the file; uninstall deletes the file it emptied; a malformed file is never overwritten", () => {
  const home = box();
  try {
    const file = hooksFile(home);
    assert.equal(run(home, "", ["install"]).status, 0);
    assert.ok(existsSync(file));
    assert.equal(run(home, "", ["uninstall"]).status, 0);
    assert.equal(existsSync(file), false);
    writeFileSync(file, "{ not json");
    run(home, "", ["install"]);
    assert.equal(readFileSync(file, "utf8"), "{ not json");
    run(home, "", ["uninstall"]);
    assert.equal(readFileSync(file, "utf8"), "{ not json");
  } finally { rmTree(home); }
});

test("doctor: antigravity is in the host table, reports a fresh install as current, and a disabled moorai hook as a failure", () => {
  const home = box();
  try {
    const host = () => hostTable(home, {}).find((h) => h.id === "antigravity");
    assert.ok(host(), "antigravity is in the doctor host table");
    assert.equal(checkHost(host(), { home, env: {} }).status, "skip");
    assert.equal(run(home, "", ["install"]).status, 0);
    const r = checkHost(host(), { home, env: {} });
    assert.equal(r.status, "ok", r.summary);
    assert.deepEqual(Object.keys(r.details.events), ["PreToolUse"]);
    const file = hooksFile(home);
    const d = JSON.parse(readFileSync(file, "utf8"));
    d.moorai.enabled = false;
    writeFileSync(file, JSON.stringify(d));
    const off = checkHost(host(), { home, env: {} });
    assert.equal(off.status, "fail");
    assert.match(off.summary, /enabled is false/);
  } finally { rmTree(home); }
});
