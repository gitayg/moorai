// scripts/host-drift.mjs — the nightly drift check's logic, driven without hosts or network: version
// drift against data/host-versions.json, the Codex hook-schema check, the Gemini settings-schema check
// against MoorAI's real installer output, the Cursor bundle markers, and the report / exit code.
// The schemas below mirror the published shapes (codex-rs/hooks/schema/generated/*.schema.json at
// rust-v0.154.0; gemini-cli schemas/settings.schema.json at v0.60.0), trimmed to what is checked.
//
//   node --test --import ./test/hermetic-env.mjs test/host-drift.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { driftOf, validate, checkCodexSchemas, checkGeminiSettings, checkCursorBundle, CURSOR_MARKERS, run } from "../scripts/host-drift.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = JSON.parse(readFileSync(join(ROOT, "test", "fixtures", "agent-hooks", "codex", "pre-tool-use-bash.json"), "utf8"));
const clone = (o) => JSON.parse(JSON.stringify(o));

const NS = { $ref: "#/definitions/NullableString" };
const PRE_IN = {
  type: "object", additionalProperties: false,
  required: ["cwd", "hook_event_name", "model", "permission_mode", "session_id", "tool_input", "tool_name", "tool_use_id", "transcript_path", "turn_id"],
  properties: { agent_id: { type: "string" }, agent_type: { type: "string" }, cwd: { type: "string" }, hook_event_name: { const: "PreToolUse", type: "string" }, model: { type: "string" }, permission_mode: { type: "string" }, session_id: { type: "string" }, tool_input: true, tool_name: { type: "string" }, tool_use_id: { type: "string" }, transcript_path: NS, turn_id: { type: "string" } },
  definitions: { NullableString: { type: ["string", "null"] } }
};
const PRE_OUT = {
  type: "object", additionalProperties: false,
  properties: { continue: { type: "boolean" }, decision: { $ref: "#/definitions/PreToolUseDecisionWire" }, hookSpecificOutput: { allOf: [{ $ref: "#/definitions/PreToolUseHookSpecificOutputWire" }], default: null }, reason: NS, stopReason: NS, suppressOutput: { type: "boolean" }, systemMessage: NS },
  definitions: {
    NullableString: { type: ["string", "null"] },
    PreToolUseDecisionWire: { enum: ["approve", "block"], type: "string" },
    PreToolUsePermissionDecisionWire: { enum: ["allow", "deny", "ask"], type: "string" },
    PreToolUseHookSpecificOutputWire: { type: "object", required: ["hookEventName"], properties: { additionalContext: NS, hookEventName: { type: "string" }, permissionDecision: { $ref: "#/definitions/PreToolUsePermissionDecisionWire" }, permissionDecisionReason: NS, updatedInput: true } }
  }
};
const UPS_IN = { type: "object", additionalProperties: false, required: ["cwd", "hook_event_name", "prompt", "session_id"], properties: { cwd: { type: "string" }, hook_event_name: { const: "UserPromptSubmit" }, model: { type: "string" }, permission_mode: { type: "string" }, prompt: { type: "string" }, session_id: { type: "string" }, transcript_path: NS, turn_id: { type: "string" } } };

const HOOK_ARRAY = { type: "array", items: { type: "object", properties: { matcher: { type: "string" }, sequential: { type: "boolean" }, hooks: { type: "array", items: { type: "object", properties: { name: { type: "string" }, type: { type: "string" }, command: { type: "string" }, description: { type: "string" }, timeout: { type: "number" } }, required: ["type", "command"] } } }, required: ["hooks"], additionalProperties: false } };
const GEMINI_SCHEMA = {
  type: "object",
  properties: {
    hooksConfig: { type: "object", properties: { enabled: { type: "boolean" }, disabled: { type: "array" } }, additionalProperties: false },
    hooks: { type: "object", properties: { BeforeTool: { $ref: "#/$defs/HookDefinitionArray" }, AfterTool: { $ref: "#/$defs/HookDefinitionArray" }, BeforeAgent: { $ref: "#/$defs/HookDefinitionArray" }, AfterAgent: { $ref: "#/$defs/HookDefinitionArray" } }, additionalProperties: false }
  },
  $defs: { HookDefinitionArray: HOOK_ARRAY }
};

function geminiSettings(t) {
  const home = mkdtempSync(join(tmpdir(), "moorai-drift-gem-"));
  t.after(() => rmTree(home));
  const r = spawnSync(process.execPath, [join(ROOT, "cli", "moorai-agent-hook.mjs"), "gemini", "install"], { env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: "utf8", input: "", timeout: 20000 });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(readFileSync(join(home, ".gemini", "settings.json"), "utf8"));
}

test("DRIFT: newer / older / same / unknown against the tested version", () => {
  assert.equal(driftOf("0.154.0", "0.155.0"), "newer");
  assert.equal(driftOf("0.154.0", "0.153.9"), "older");
  assert.equal(driftOf("2026.05.27-fe9a6e2", "2026.05.27-fe9a6e2"), "same");
  assert.equal(driftOf("0.154.0", null), "unknown");
});

test("VALIDATE: the schema subset catches missing, unknown, wrongly-typed and out-of-enum values", () => {
  assert.deepEqual(validate(PRE_IN, FIXTURE), []);
  assert.match(validate(PRE_IN, { ...FIXTURE, extra: 1 }).join(), /unknown property "extra"/);
  const { tool_name, ...noTool } = FIXTURE;
  assert.match(validate(PRE_IN, noTool).join(), /missing required "tool_name"/);
  assert.match(validate(PRE_IN, { ...FIXTURE, hook_event_name: "PostToolUse" }).join(), /expected "PreToolUse"/);
  assert.match(validate(PRE_IN, { ...FIXTURE, transcript_path: 3 }).join(), /type integer/);
});

test("CODEX: the published hook schemas carry every field the adapter reads and writes", () => {
  assert.deepEqual(checkCodexSchemas({ preIn: PRE_IN, preOut: PRE_OUT, upsIn: UPS_IN }, FIXTURE), []);
});

test("CODEX: a schema that drops a field the adapter depends on is reported", () => {
  const out = clone(PRE_OUT);
  delete out.definitions.PreToolUseHookSpecificOutputWire.properties.permissionDecisionReason;
  out.definitions.PreToolUsePermissionDecisionWire.enum = ["allow", "ask"];
  const inp = clone(PRE_IN);
  inp.properties.session = inp.properties.session_id; delete inp.properties.session_id; inp.required = inp.required.map((r) => (r === "session_id" ? "session" : r));
  const p = checkCodexSchemas({ preIn: inp, preOut: out, upsIn: UPS_IN }, FIXTURE).join("\n");
  assert.match(p, /permissionDecisionReason/);
  assert.match(p, /lacks "deny"/);
  assert.match(p, /pre-tool-use input: no "session_id"/);
  assert.match(p, /fixture: .*unknown property "session_id"/);
});

test("GEMINI: MoorAI's installed hooks section validates against the settings schema", (t) => {
  assert.deepEqual(checkGeminiSettings(GEMINI_SCHEMA, geminiSettings(t)), []);
});

test("GEMINI: an event or hook key the schema no longer knows is reported", (t) => {
  const s = geminiSettings(t);
  const schema = clone(GEMINI_SCHEMA);
  delete schema.properties.hooks.properties.BeforeAgent;
  schema.$defs.HookDefinitionArray.items.properties.hooks.items.additionalProperties = false;
  delete schema.$defs.HookDefinitionArray.items.properties.hooks.items.properties.timeout;
  const p = checkGeminiSettings(schema, s).join("\n");
  assert.match(p, /hooks\.BeforeAgent: event not in the schema/);
  assert.match(p, /unknown property "timeout"/);
});

test("CURSOR: every marker present passes; a missing one is named", () => {
  assert.deepEqual(checkCursorBundle(CURSOR_MARKERS.join(" ")), []);
  assert.deepEqual(checkCursorBundle(CURSOR_MARKERS.filter((m) => m !== "CURSOR_VERSION").join(" ")), ['bundle lacks "CURSOR_VERSION"']);
});

const fakes = (over = {}) => ({
  probe: () => ({ bin: null, version: null }),
  latestOf: () => null,
  conformance: () => ({ status: "pass", detail: "pass 3 fail 0" }),
  fetch: async (url) => ({ ok: true, json: async () => (/settings\.schema/.test(url) ? GEMINI_SCHEMA : /pre-tool-use\.command\.input/.test(url) ? PRE_IN : /pre-tool-use\.command\.output/.test(url) ? PRE_OUT : UPS_IN) }),
  ...over
});

test("REPORT: a newer host needs attention but exits 0; --fail-on-drift exits 1", async () => {
  const { report, code } = await run(["--host", "codex", "--installed", "codex=0.999.0"], fakes());
  const h = report.hosts[0];
  assert.equal(code, 0);
  assert.equal(h.drift, "newer");
  assert.equal(h.attention, true);
  assert.match(h.reasons[0], /newer than tested: 0\.999\.0 vs /);
  assert.equal(h.checks.find((c) => c.name === "hook-schema").status, "pass");
  assert.equal((await run(["--host", "codex", "--installed", "codex=0.999.0", "--fail-on-drift"], fakes())).code, 1);
});

test("REPORT: a failing conformance run fails the job and names the host", async () => {
  const { report, code } = await run(["--host", "gemini", "--offline"], fakes({ conformance: () => ({ status: "fail", detail: "pass 2 fail 1: not ok 3 - deny shape" }) }));
  assert.equal(code, 1);
  assert.equal(report.hosts[0].attention, true);
  assert.match(report.hosts[0].reasons.join(), /conformance failed: .*deny shape/);
});

test("REPORT: --latest uses npm's latest when the host is not installed; tested version is quiet", async () => {
  const m = JSON.parse(readFileSync(join(ROOT, "data", "host-versions.json"), "utf8"));
  const quiet = await run(["--host", "copilot", "--latest", "--skip-tests"], fakes({ latestOf: () => m.hosts.copilot.tested }));
  assert.equal(quiet.report.hosts[0].drift, "same");
  assert.equal(quiet.report.hosts[0].attention, false);
  const loud = await run(["--host", "copilot", "--latest", "--skip-tests"], fakes({ latestOf: () => "1.0.99" }));
  assert.equal(loud.report.hosts[0].latest, "1.0.99");
  assert.equal(loud.report.hosts[0].attention, true);
});

// The live tier's plumbing, with a stand-in host instead of a model: it reads the hook registration
// MoorAI's installer wrote into the throwaway HOME and runs it for one tool call, the way Claude Code
// does, with AI_AGENT set. It only does so when the auth env var the manifest names was passed through.
test("LIVE: a host that runs MoorAI's hook passes and reports the version detected inside it; no key, no turn", { skip: process.platform === "win32" }, async (t) => {
  const { writeFileSync: w, chmodSync, mkdtempSync: mk } = await import("node:fs");
  const { liveTurn } = await import("../scripts/host-drift.mjs");
  const dir = mk(join(tmpdir(), "moorai-live-fake-"));
  t.after(() => rmTree(dir));
  const fake = join(dir, "claude");
  w(fake, `#!${process.execPath}
const fs = require("fs"), path = require("path"), { spawnSync } = require("child_process");
if (!process.env.FAKE_HOST_KEY) { process.stderr.write("not logged in\\n"); process.exit(1); }
const s = JSON.parse(fs.readFileSync(path.join(process.env.HOME, ".claude", "settings.json"), "utf8"));
const cmd = s.hooks.PreToolUse.flatMap((g) => g.hooks).find((h) => /moorai-hook/.test(h.command)).command;
const payload = { session_id: "live-1", transcript_path: null, cwd: process.cwd(), hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "echo moorai-live-probe" }, tool_use_id: "t1" };
spawnSync("/bin/sh", ["-c", cmd], { input: JSON.stringify(payload), env: { ...process.env, AI_AGENT: "claude-code_7-7-7_harness" }, encoding: "utf8" });
`);
  chmodSync(fake, 0o755);
  const m = { ...JSON.parse(readFileSync(join(ROOT, "data", "host-versions.json"), "utf8")).hosts["claude-code"], live: { args: ["-p", "{prompt}"], env: ["FAKE_HOST_KEY"] } };
  const ok = await liveTurn("claude-code", m, { bin: fake, env: { PATH: process.env.PATH, FAKE_HOST_KEY: "k" }, timeoutMs: 30000 });
  assert.equal(ok.status, "pass", ok.detail);
  assert.match(ok.detail, /version 7\.7\.7 tested false/);
  const no = await liveTurn("claude-code", m, { bin: fake, env: { PATH: process.env.PATH }, timeoutMs: 30000 });
  assert.equal(no.status, "fail");
  assert.match(no.detail, /no MoorAI heartbeat .*not logged in/);
  assert.equal((await liveTurn("claude-code", { ...m, live: undefined }, { bin: fake })).status, "skip");
});

test("ISSUE: the per-host issue body names the versions, drift and every check, with table cells escaped", async () => {
  const { renderIssue } = await import("../scripts/host-drift.mjs");
  const body = renderIssue({ host: "codex", label: "OpenAI Codex CLI", tested: "0.154.0", installed: "0.160.1", latest: "0.160.1", drift: "newer", checks: [{ name: "hook-schema", status: "fail", detail: "a | b\nc" }], reasons: ["newer than tested: 0.160.1 vs 0.154.0"] }, "https://example/run/1");
  assert.match(body, /\*\*OpenAI Codex CLI\*\* \(https:\/\/example\/run\/1\)/);
  assert.match(body, /tested \(data\/host-versions\.json\): `0\.154\.0`/);
  assert.match(body, /drift: \*\*newer\*\*/);
  assert.match(body, /\| hook-schema \| fail \| a \\\| b c \|/);
  assert.match(body, /- newer than tested/);
});

test("REPORT: with the host not installed, the schema check reads the npm-latest release's schemas", async () => {
  const urls = [];
  const f = fakes();
  const { report } = await run(["--host", "codex", "--latest", "--skip-tests"], { ...f, latestOf: () => "0.160.1", fetch: async (u) => { urls.push(u); return f.fetch(u); } });
  assert.ok(urls.length && urls.every((u) => u.includes("/rust-v0.160.1/")), urls.join(" "));
  assert.match(report.hosts[0].checks.find((c) => c.name === "hook-schema").detail, /^rust-v0\.160\.1:/);
});
