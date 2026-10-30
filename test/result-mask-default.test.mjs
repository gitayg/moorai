// A credential (#39) in a tool RESULT is masked by default where the surface can rewrite the result, and the
// hook does the strongest documented thing where it cannot (cli/inbound.mjs CRED_RESULT_DECISION).
//
// Claude Code hooks reference (code.claude.com/docs/en/hooks, fetched 2026-10-30), PostToolUse decision control:
//   updatedToolOutput  "Replaces the tool's output with the provided value before it is sent to Claude. The value
//                       must match the tool's output shape"
//   decision "block"   "adds the `reason` next to the tool result. Claude still sees the original output"
//
//   node --test --import ./test/hermetic-env.mjs test/result-mask-default.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEngine } from "../cli/hook-core.mjs";
import { maskResult, maskedMcpResult } from "../cli/result-mask.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const AWS = "AKIAQ3EGUXWN5TLMRZ7P";                          // secret-aws-akia shape (#39), not a real key
const GH = "ghp_R4nd0mT0k3nV4lu3F0rT3st1ngOnlyAbCdEf12";   // secret-github shape (#39)
const TAG = /\[MOORAI:secret:[a-p]{8}\]/;
const DEFAULT = { captureTier: "content-free" };
const OPT_OUT = { captureTier: "content-free", threatPolicy: { 39: "notify" } };

function startServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}
async function hook(policy, payload, { enrolled = true, env = {} } = {}) {
  const { srv, port, alerts } = await startServer(policy);
  const home = mkdtempSync(join(tmpdir(), "moorai-rmask-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-rmask-proj-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", ...(enrolled ? { installToken: "tok-rmask-test" } : {}) }));
  try {
    const out = await new Promise((resolve) => {
      const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "", ...env }, stdio: ["pipe", "pipe", "pipe"] });
      let o = "";
      c.stdout.on("data", (d) => (o += d));
      c.on("close", (code) => resolve({ code, o }));
      c.stdin.end(JSON.stringify({ session_id: "s-rmask", transcript_path: "/tmp/t.jsonl", cwd: proj, tool_use_id: "toolu_R", ...payload }));
    });
    await new Promise((r) => setTimeout(r, 250));
    return { ...out, alerts, json: out.o.trim() ? JSON.parse(out.o) : null };
  } finally { srv.close(); rmTree(home); rmTree(proj); }
}
const postT = (tool_name, tool_input, tool_response) => ({ hook_event_name: "PostToolUse", tool_name, tool_input, tool_response });
const bashOut = (stdout) => ({ stdout, stderr: "", interrupted: false, isImage: false });
const noSecret = (r) => { const blob = r.o + JSON.stringify(r.alerts); assert.ok(!blob.includes(AWS) && !blob.includes(GH), "the secret must appear nowhere in the hook's output or its alerts"); };

// ---- the hook: Claude Code PostToolUse ----

test("hook DEFAULT: a key printed by Bash is masked through updatedToolOutput with no #39 policy at all", async () => {
  const r = await hook(DEFAULT, postT("Bash", { command: "cat ~/.aws/credentials" }, bashOut(`aws_access_key_id = ${AWS}\nregion = eu-west-1\n`)));
  const h = r.json?.hookSpecificOutput;
  assert.equal(h?.hookEventName, "PostToolUse");
  assert.deepEqual(Object.keys(h.updatedToolOutput).sort(), ["interrupted", "isImage", "stderr", "stdout"], "the Bash output shape is kept");
  assert.match(h.updatedToolOutput.stdout, TAG);
  assert.match(h.updatedToolOutput.stdout, /region = eu-west-1/, "the rest of the output is kept");
  assert.equal(r.json.decision, undefined, "a mask is not a block");
  assert.match(h.additionalContext, /masked 1 sensitive span \(#39\)/);
  assert.ok(r.alerts.some((a) => a.threatId === 39 && a.stage === "output"), "the finding is still reported");
  assert.ok(r.alerts.some((a) => a.category === "Sensitive span masked" && a.decision === "mask" && a.maskedIn === "result"));
  noSecret(r);
});

test("hook DEFAULT: an MCP result is masked, shape kept", async () => {
  const r = await hook(DEFAULT, postT("mcp__files__read", { path: "x" }, { content: [{ type: "text", text: `found config: ${GH}` }], isError: false }));
  const u = r.json?.hookSpecificOutput?.updatedToolOutput;
  assert.equal(u?.isError, false);
  assert.match(u.content[0].text, /^found config: \[MOORAI:secret:[a-p]{8}\]$/);
  noSecret(r);
});

test("hook OPT-OUT: an org action for #39 (notify) leaves the result as it was, and reports", async () => {
  const r = await hook(OPT_OUT, postT("Bash", { command: "cat ~/.aws/credentials" }, bashOut(`aws_access_key_id = ${AWS}\n`)));
  assert.equal(r.json, null, "nothing on stdout: the result is delivered untouched");
  assert.ok(r.alerts.some((a) => a.threatId === 39));
});

test("hook HOST-LIMITED (shim: no rewrite): decision block with a reason telling the model not to use or repeat the value", async () => {
  const r = await hook(DEFAULT, postT("Bash", { command: "cat ~/.aws/credentials" }, bashOut(`aws_access_key_id = ${AWS}\n`)), { env: { MOORAI_HOOK_HOST: "shim" } });
  assert.equal(r.json?.decision, "block");
  assert.match(r.json.reason, /could not mask here\. Do not use, repeat, store or send it/);
  assert.equal(r.json.hookSpecificOutput?.updatedToolOutput, undefined, "no rewrite where the host cannot apply one");
  assert.ok(r.alerts.some((a) => a.threatId === 39));
  noSecret(r);
});

test("hook FAILED MASK (result over the 256 KB rewrite budget): the same block reason, no partial rewrite", async () => {
  const r = await hook(DEFAULT, postT("Bash", { command: "cat big.log" }, bashOut(`aws_access_key_id = ${AWS}\n` + "x".repeat(300000))));
  assert.equal(r.json?.decision, "block");
  assert.match(r.json.reason, /#39/);
  assert.equal(r.json.hookSpecificOutput?.updatedToolOutput, undefined);
});

test("hook UNENROLLED: coaches with the same text, no rewrite and no post", async () => {
  const r = await hook(DEFAULT, postT("Bash", { command: "cat ~/.aws/credentials" }, bashOut(`aws_access_key_id = ${AWS}\n`)), { enrolled: false });
  assert.equal(r.json?.hookSpecificOutput?.updatedToolOutput, undefined);
  assert.equal(r.json?.decision, undefined);
  assert.match(r.json?.systemMessage || "", /Do not use, repeat, store or send it/);
});

test("hook: a result with no credential is not touched (no stdout)", async () => {
  const r = await hook(DEFAULT, postT("Bash", { command: "ls" }, bashOut("a.txt\nb.txt\n")));
  assert.equal(r.json, null);
});

// ---- the shared module (gateway, stdio guard, model proxy) ----

test("maskResult: masks #39 by default and verifies; an opt-out policy and an org block get nothing to mask", () => {
  const engine = buildEngine({});
  const hash = (s) => "h2:" + Buffer.from(s).toString("hex").slice(0, 16);
  const value = { content: [{ type: "text", text: `key ${AWS} ok` }], isError: false };
  const m = maskResult(engine, {}, value, { stage: "file", hash });
  assert.ok(m && !m.failed);
  assert.deepEqual(m.ids, [39]);
  assert.match(m.value.content[0].text, /^key \[MOORAI:secret:[a-p]{8}\] ok$/);
  assert.equal(value.content[0].text, `key ${AWS} ok`, "the input is not mutated");
  const out = maskedMcpResult({ jsonrpc: "2.0", id: 3, result: value }, m);
  assert.equal(out.id, 3);
  assert.equal(out.result.content.length, 2);
  assert.match(out.result.content[1].text, /masked 1 sensitive span/);
  assert.equal(maskResult(engine, { threatPolicy: { 39: "notify" } }, value, { stage: "file", hash }), null);
  assert.equal(maskResult(engine, { threatPolicy: { 39: "block" } }, value, { stage: "file", hash }), null, "a deny is the caller's to apply");
  const big = maskResult(engine, {}, { content: [{ type: "text", text: `key ${AWS}\n` + "y".repeat(300000) }] }, { stage: "file", hash });
  assert.equal(big?.failed, true, "over the rewrite budget the mask fails and the caller falls back");
  assert.equal(big.fallback.decision, "allow");
});
